const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const webpush = require('web-push');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// =======================
// AUTH - In-memory stores
// =======================
const users = {};      // { username: { username, passwordHash, activeRooms: [] } }
const sessions = {};   // { sessionToken: username }
const socketToUser = {}; // { socketId: { username, roomCode } }

function requireAuth(req, res, next) {
    const token = req.cookies?.session;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    req.username = sessions[token];
    next();
}

app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    const trimmed = username.trim().toLowerCase();
    if (trimmed.length < 3) {
        return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }
    if (password.length < 4) {
        return res.status(400).json({ error: 'Password must be at least 4 characters' });
    }
    if (users[trimmed]) {
        return res.status(409).json({ error: 'Username already taken' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    users[trimmed] = { username: trimmed, passwordHash, activeRooms: [] };

    const token = crypto.randomUUID();
    sessions[token] = trimmed;
    res.cookie('session', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ username: trimmed, activeRooms: [] });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    const trimmed = username.trim().toLowerCase();
    const user = users[trimmed];
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    const token = crypto.randomUUID();
    sessions[token] = trimmed;
    res.cookie('session', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ username: trimmed, activeRooms: getUserActiveRooms(trimmed) });
});

app.post('/api/logout', (req, res) => {
    const token = req.cookies?.session;
    if (token) delete sessions[token];
    res.clearCookie('session');
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    const token = req.cookies?.session;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const username = sessions[token];
    res.json({ username, activeRooms: getUserActiveRooms(username) });
});

function getUserActiveRooms(username) {
    const user = users[username];
    if (!user || !user.activeRooms) return [];
    // Filter out rooms that no longer exist
    user.activeRooms = user.activeRooms.filter(ar => rooms[ar.roomCode]);
    return user.activeRooms;
}

function addUserToRoom(username, roomCode, isArbiter) {
    if (!users[username]) return;
    if (!users[username].activeRooms) users[username].activeRooms = [];
    const existing = users[username].activeRooms.find(ar => ar.roomCode === roomCode);
    if (!existing) {
        users[username].activeRooms.push({ roomCode, isArbiter });
    }
}

function removeUserFromRoom(username, roomCode) {
    if (!users[username] || !users[username].activeRooms) return;
    users[username].activeRooms = users[username].activeRooms.filter(ar => ar.roomCode !== roomCode);
}

// Web Push VAPID setup
let vapidPublicKey;

if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
    webpush.setVapidDetails(
        'mailto:admin@pingo.app',
        process.env.VAPID_PUBLIC_KEY,
        process.env.VAPID_PRIVATE_KEY
    );
    console.log('Web Push enabled with VAPID keys from env');
} else {
    const vapidKeys = webpush.generateVAPIDKeys();
    vapidPublicKey = vapidKeys.publicKey;
    webpush.setVapidDetails(
        'mailto:admin@pingo.app',
        vapidKeys.publicKey,
        vapidKeys.privateKey
    );
    console.log('Web Push enabled with auto-generated VAPID keys');
    console.log('VAPID_PUBLIC_KEY=' + vapidKeys.publicKey);
    console.log('VAPID_PRIVATE_KEY=' + vapidKeys.privateKey);
}

// In-memory store
const rooms = {};

// =======================
// UTIL FUNCTIONS
// =======================

function generateRoomCode() {
    let code = '';
    do {
        code = Math.random().toString(36).substring(2, 7).toUpperCase();
    } while (rooms[code]);
    return code;
}

function shuffleArray(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

function checkBingo(checked, gridSize) {
    const grid = Array.from({ length: gridSize }, (_, r) =>
        Array.from({ length: gridSize }, (_, c) => checked.has(r * gridSize + c))
    );

    for (let r = 0; r < gridSize; r++) {
        if (grid[r].every(Boolean)) return true;
    }

    for (let c = 0; c < gridSize; c++) {
        if (grid.every(row => row[c])) return true;
    }

    if (grid.every((row, i) => row[i])) return true;
    if (grid.every((row, i) => row[gridSize - 1 - i])) return true;

    return false;
}

function sanitizeParticipants(participants) {
    return Object.values(participants).map((p) => ({
        id: p.id,
        name: p.name,
        checked: p.checked,
        card: p.card,
        hasBingo: p.hasBingo,
        isHost: false
    }));
}

function getAllPlayers(room) {
    const players = sanitizeParticipants(room.participants);
    if (room.arbiter) {
        players.unshift({
            id: room.arbiter.username || room.arbiter.id,
            name: room.arbiter.name,
            checked: room.arbiter.checked || [],
            hasBingo: room.arbiter.hasBingo || false,
            isHost: true
        });
    }
    return players;
}

// =======================
// PUSH NOTIFICATIONS
// =======================

async function sendPushToAll(room, title, body) {
    const subscriptions = Object.values(room.participants)
        .map(p => p.pushSubscription)
        .filter(Boolean);

    if (room.arbiter?.pushSubscription) {
        subscriptions.push(room.arbiter.pushSubscription);
    }

    const payload = JSON.stringify({ title, body });

    for (const sub of subscriptions) {
        try {
            await webpush.sendNotification(sub, payload);
        } catch (err) {
            console.error('Push send failed:', err.statusCode || err.message);
        }
    }
}

// =======================
// API ROUTES
// =======================

app.post('/api/rooms', (req, res) => {
    try {
        const {
            password,
            gridSize,
            prompts,
            arbiterId,
            arbiterName,
            username,
            partyName
        } = req.body;

        const parsedGridSize = Number(gridSize);

        if (!password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Missing password' });
        }

        if (!Number.isInteger(parsedGridSize) || parsedGridSize < 2) {
            return res.status(400).json({ error: 'Invalid grid size' });
        }

        if (!Array.isArray(prompts) || prompts.length < parsedGridSize * parsedGridSize) {
            return res.status(400).json({
                error: `Need at least ${parsedGridSize * parsedGridSize} prompts`
            });
        }

        const roomCode = generateRoomCode();

        rooms[roomCode] = {
            password,
            gridSize: parsedGridSize,
            prompts: prompts.slice(0, parsedGridSize * parsedGridSize),
            partyName: partyName || 'Unnamed Party',
            participants: {},
            arbiter: {
                id: arbiterId || 'host',
                name: arbiterName || 'Host',
                username: username || null,
                socketId: null,
                pushSubscription: null,
                card: null,
                checked: [],
                hasBingo: false
            },
            createdAt: Date.now()
        };

        if (username) addUserToRoom(username, roomCode, true);

        console.log('ROOM CREATED:', roomCode);

        return res.json({ roomCode });
    } catch (err) {
        console.error('CREATE ROOM ERROR:', err);
        return res.status(500).json({ error: 'Server failed to create room' });
    }
});

app.get('/api/rooms', (req, res) => {
    const list = Object.entries(rooms).map(([code, room]) => ({
        roomCode: code,
        partyName: room.partyName || 'Unnamed Party',
        hostName: room.arbiter?.name || 'Unknown',
        participantCount: Object.keys(room.participants).length + 1 // +1 for host
    }));
    res.json(list);
});

app.get('/api/rooms/:code', (req, res) => {
    const room = rooms[String(req.params.code || '').toUpperCase()];
    if (!room) return res.status(404).json({ error: 'Room not found' });

    res.json({
        gridSize: room.gridSize,
        participantCount: Object.keys(room.participants).length + 1,
        hostName: room.arbiter?.name || 'Unknown',
        partyName: room.partyName
    });
});

app.get('/api/my-rooms', (req, res) => {
    const token = req.cookies?.session;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const username = sessions[token];
    const activeRooms = getUserActiveRooms(username);
    const details = activeRooms.map(ar => {
        const room = rooms[ar.roomCode];
        if (!room) return null;
        return {
            roomCode: ar.roomCode,
            isArbiter: ar.isArbiter,
            partyName: room.partyName || 'Unnamed Party',
            hostName: room.arbiter?.name || 'Unknown',
            participantCount: Object.keys(room.participants).length + 1
        };
    }).filter(Boolean);
    res.json(details);
});

app.get('/api/vapid-public-key', (req, res) => {
    res.json({ publicKey: vapidPublicKey });
});

app.post('/api/push-subscribe', (req, res) => {
    const { roomCode, participantId, subscription, isArbiter } = req.body;
    const room = rooms[String(roomCode || '').toUpperCase()];
    if (!room) return res.status(404).json({ error: 'Room not found' });

    if (isArbiter && room.arbiter) {
        room.arbiter.pushSubscription = subscription;
    } else if (room.participants[participantId]) {
        room.participants[participantId].pushSubscription = subscription;
    }

    res.json({ success: true });
});

app.post('/api/leave-room', (req, res) => {
    const token = req.cookies?.session;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const username = sessions[token];
    const user = users[username];
    if (!user) return res.json({ success: true });

    const { roomCode } = req.body;
    if (!roomCode) return res.status(400).json({ error: 'roomCode required' });

    const code = String(roomCode).toUpperCase();
    const room = rooms[code];

    removeUserFromRoom(username, code);

    if (room) {
        if (room.arbiter?.username === username) {
            // Host leaving — clear socket but keep room alive
            room.arbiter.socketId = null;
        } else if (room.participants[username]) {
            const name = room.participants[username].name;
            delete room.participants[username];
            io.to(code).emit('room:update', {
                roomCode: code,
                participants: getAllPlayers(room)
            });
            io.to(code).emit('activity', {
                roomCode: code,
                message: `${name} left the game`,
                participantName: name
            });
        }
    }

    res.json({ success: true });
});

app.post('/api/delete-room', async (req, res) => {
    const token = req.cookies?.session;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const username = sessions[token];
    const { roomCode, password } = req.body;

    if (!roomCode || !password) {
        return res.status(400).json({ error: 'roomCode and password required' });
    }

    const code = String(roomCode).toUpperCase();
    const room = rooms[code];
    if (!room) return res.status(404).json({ error: 'Room not found' });

    if (room.arbiter?.username !== username) {
        return res.status(403).json({ error: 'Only the host can delete this party' });
    }

    const user = users[username];
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
        return res.status(401).json({ error: 'Wrong password' });
    }

    // Notify all players
    io.to(code).emit('room:deleted', {
        roomCode: code,
        message: 'The host has deleted this party.'
    });

    // Remove from all users' activeRooms
    for (const u of Object.values(users)) {
        if (u.activeRooms) {
            u.activeRooms = u.activeRooms.filter(ar => ar.roomCode !== code);
        }
    }

    delete rooms[code];
    res.json({ success: true });
});

// =======================
// SOCKET LOGIC
// =======================

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('arbiter:join', ({ roomCode, username }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return socket.emit('error', 'Room not found');

            room.arbiter.socketId = socket.id;
            room.arbiter.username = username;
            socketToUser[socket.id] = { username, roomCode: code };

            // Generate arbiter card if not already created
            if (!room.arbiter.card) {
                const shuffled = shuffleArray(room.prompts).slice(0, room.gridSize * room.gridSize);
                const center = Math.floor(shuffled.length / 2);
                if (room.gridSize % 2 === 1) shuffled[center] = 'FREE';
                room.arbiter.card = shuffled;
                room.arbiter.checked = room.gridSize % 2 === 1 ? [center] : [];
                room.arbiter.hasBingo = false;
            }

            if (username && users[username]) {
                addUserToRoom(username, code, true);
            }

            socket.join(code);
            socket.emit('arbiter:joined', {
                roomCode: code,
                gridSize: room.gridSize,
                prompts: room.prompts,
                partyName: room.partyName,
                participants: getAllPlayers(room),
                arbiterCard: room.arbiter.card,
                arbiterChecked: room.arbiter.checked
            });
        } catch (err) {
            console.error('arbiter:join error:', err);
            socket.emit('error', 'Failed to join as host');
        }
    });

    socket.on('participant:join', ({ roomCode, password, name, username }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];

            if (!room) return socket.emit('error', 'Room not found');
            if (room.password !== password) return socket.emit('error', 'Wrong password');

            const participantKey = username || socket.id;

            // If this user already has a card in this room, rejoin with existing state
            if (room.participants[participantKey]) {
                const existing = room.participants[participantKey];
                existing.socketId = socket.id;
                socketToUser[socket.id] = { username: participantKey, roomCode: code };

                if (username && users[username]) {
                    addUserToRoom(username, code, false);
                }

                socket.join(code);
                socket.emit('participant:joined', {
                    participantId: participantKey,
                    card: existing.card,
                    checked: existing.checked,
                    gridSize: room.gridSize,
                    roomCode: code,
                    partyName: room.partyName
                });

                io.to(code).emit('room:update', {
                    roomCode: code,
                    participants: getAllPlayers(room)
                });
                return;
            }

            const shuffled = shuffleArray(room.prompts).slice(0, room.gridSize * room.gridSize);
            const totalCells = room.gridSize * room.gridSize;
            const centerIdx = Math.floor(totalCells / 2);

            const card = [...shuffled];
            if (room.gridSize % 2 === 1) {
                card[centerIdx] = 'FREE';
            }

            const checked = new Set(room.gridSize % 2 === 1 ? [centerIdx] : []);

            room.participants[participantKey] = {
                id: participantKey,
                name: name || 'Player',
                socketId: socket.id,
                pushSubscription: null,
                card,
                checked: [...checked],
                hasBingo: false
            };

            socketToUser[socket.id] = { username: participantKey, roomCode: code };

            if (username && users[username]) {
                addUserToRoom(username, code, false);
            }

            socket.join(code);

            socket.emit('participant:joined', {
                participantId: participantKey,
                card,
                checked: [...checked],
                gridSize: room.gridSize,
                roomCode: code,
                partyName: room.partyName
            });

            io.to(code).emit('room:update', {
                roomCode: code,
                participants: getAllPlayers(room)
            });
        } catch (err) {
            console.error('participant:join error:', err);
            socket.emit('error', 'Failed to join room');
        }
    });

    socket.on('rejoin', ({ roomCode, username, isArbiter }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return socket.emit('error', 'Room not found');

            if (isArbiter) {
                if (!room.arbiter) return socket.emit('error', 'Not host of this room');
                room.arbiter.socketId = socket.id;
                socketToUser[socket.id] = { username, roomCode: code };
                socket.join(code);
                socket.emit('arbiter:joined', {
                    roomCode: code,
                    gridSize: room.gridSize,
                    prompts: room.prompts,
                    partyName: room.partyName,
                    participants: getAllPlayers(room),
                    arbiterCard: room.arbiter.card,
                    arbiterChecked: room.arbiter.checked
                });
            } else {
                const participant = room.participants[username];
                if (!participant) return socket.emit('error', 'Not in this room');
                participant.socketId = socket.id;
                socketToUser[socket.id] = { username, roomCode: code };
                socket.join(code);
                socket.emit('participant:joined', {
                    participantId: username,
                    card: participant.card,
                    checked: participant.checked,
                    gridSize: room.gridSize,
                    roomCode: code,
                    partyName: room.partyName
                });

                io.to(code).emit('room:update', {
                    roomCode: code,
                    participants: getAllPlayers(room)
                });
            }
        } catch (err) {
            console.error('rejoin error:', err);
            socket.emit('error', 'Failed to rejoin');
        }
    });

    socket.on('cell:check', ({ roomCode, cellIndex }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;

            const userInfo = socketToUser[socket.id];
            if (!userInfo) return;

            let participant;
            let isArbiter = false;
            if (room.arbiter && room.arbiter.socketId === socket.id) {
                participant = room.arbiter;
                isArbiter = true;
            } else {
                participant = room.participants[userInfo.username];
            }
            if (!participant) return;

            if (!Number.isInteger(cellIndex) || cellIndex < 0 || cellIndex >= participant.card.length) {
                return;
            }

            const checkedSet = new Set(participant.checked);

            if (checkedSet.has(cellIndex)) checkedSet.delete(cellIndex);
            else checkedSet.add(cellIndex);

            participant.checked = [...checkedSet];

            const promptText = participant.card[cellIndex];
            const hadBingo = participant.hasBingo;
            participant.hasBingo = checkBingo(checkedSet, room.gridSize);

            socket.emit('cell:updated', {
                roomCode: code,
                checked: participant.checked,
                hasBingo: participant.hasBingo
            });

            if (checkedSet.has(cellIndex) && promptText !== 'FREE') {
                const message = `${participant.name} Completed: ${promptText}`;

                io.to(code).emit('activity', {
                    roomCode: code,
                    message,
                    participantName: participant.name,
                    prompt: promptText
                });

                sendPushToAll(room, 'Task Completed!', message);
            }

            if (!hadBingo && participant.hasBingo) {
                const bingoMsg = `${participant.name} got PIngo!`;

                io.to(code).emit('bingo', {
                    roomCode: code,
                    participantName: participant.name,
                    message: bingoMsg
                });

                sendPushToAll(room, 'PIngo!', bingoMsg);
            }

            // Always send updated player list (includes host)
            io.to(code).emit('room:update', {
                roomCode: code,
                participants: getAllPlayers(room)
            });
        } catch (err) {
            console.error('cell:check error:', err);
        }
    });

    socket.on('host:kick', ({ roomCode, participantId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;

            // Only the host can kick
            if (!room.arbiter || room.arbiter.socketId !== socket.id) return;

            const participant = room.participants[participantId];
            if (!participant) return;

            // Notify the kicked player
            if (participant.socketId) {
                io.to(participant.socketId).emit('kicked', {
                    roomCode: code,
                    message: 'You have been kicked from the party.'
                });
            }

            const name = participant.name;
            delete room.participants[participantId];
            removeUserFromRoom(participantId, code);

            io.to(code).emit('room:update', {
                roomCode: code,
                participants: getAllPlayers(room)
            });
            io.to(code).emit('activity', {
                roomCode: code,
                message: `${name} was kicked`,
                participantName: name
            });
        } catch (err) {
            console.error('host:kick error:', err);
        }
    });

    socket.on('disconnect', () => {
        try {
            delete socketToUser[socket.id];

            for (const [code, room] of Object.entries(rooms)) {
                if (room.arbiter && room.arbiter.socketId === socket.id) {
                    room.arbiter.socketId = null;
                }
                for (const p of Object.values(room.participants)) {
                    if (p.socketId === socket.id) {
                        p.socketId = null;
                    }
                }
            }
        } catch (err) {
            console.error('disconnect error:', err);
        }
    });
});

// =======================
// START SERVER
// =======================

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`PIngo server running on port ${PORT}`);
});

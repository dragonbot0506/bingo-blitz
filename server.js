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
const io = new Server(server, {
    cors: { origin: '*' }
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// =======================
// AUTH - In-memory stores
// =======================
const users = {};      // { username: { username, passwordHash } }
const sessions = {};   // { sessionToken: username }

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
    users[trimmed] = { username: trimmed, passwordHash };

    const token = crypto.randomUUID();
    sessions[token] = trimmed;
    res.cookie('session', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ username: trimmed });
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
    res.json({ username: trimmed });
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
    res.json({ username: sessions[token] });
});

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
        hasBingo: p.hasBingo
    }));
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
        console.log('CREATE ROOM BODY:', req.body);

        const {
            password,
            gridSize,
            prompts,
            arbiterId,
            arbiterName
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
            participants: {},
            arbiter: {
                id: arbiterId || 'host',
                name: arbiterName || 'Host',
                pushSubscription: null
            },
            createdAt: Date.now()
        };

        console.log('ROOM CREATED:', roomCode);

        return res.json({ roomCode });
    } catch (err) {
        console.error('CREATE ROOM ERROR:', err);
        return res.status(500).json({ error: 'Server failed to create room' });
    }
});

app.get('/api/rooms/:code', (req, res) => {
    const room = rooms[String(req.params.code || '').toUpperCase()];
    if (!room) return res.status(404).json({ error: 'Room not found' });

    res.json({
        gridSize: room.gridSize,
        participantCount: Object.keys(room.participants).length
    });
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

// =======================
// SOCKET LOGIC
// =======================

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('arbiter:join', ({ roomCode }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return socket.emit('error', 'Room not found');

            socket.join(code);
            socket.emit('arbiter:joined', {
                roomCode: code,
                gridSize: room.gridSize,
                prompts: room.prompts,
                participants: room.participants
            });
        } catch (err) {
            console.error('arbiter:join error:', err);
            socket.emit('error', 'Failed to join as arbiter');
        }
    });

    socket.on('participant:join', ({ roomCode, password, name }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];

            if (!room) return socket.emit('error', 'Room not found');
            if (room.password !== password) return socket.emit('error', 'Wrong password');

            const participantId = socket.id;

            const shuffled = shuffleArray(room.prompts).slice(0, room.gridSize * room.gridSize);
            const totalCells = room.gridSize * room.gridSize;
            const centerIdx = Math.floor(totalCells / 2);

            const card = [...shuffled];
            if (room.gridSize % 2 === 1) {
                card[centerIdx] = 'FREE';
            }

            const checked = new Set(room.gridSize % 2 === 1 ? [centerIdx] : []);

            room.participants[participantId] = {
                id: participantId,
                name: name || 'Player',
                pushSubscription: null,
                card,
                checked: [...checked],
                hasBingo: false
            };

            socket.join(code);

            socket.emit('participant:joined', {
                participantId,
                card,
                checked: [...checked],
                gridSize: room.gridSize,
                roomCode: code
            });

            io.to(code).emit('room:update', {
                participants: sanitizeParticipants(room.participants)
            });
        } catch (err) {
            console.error('participant:join error:', err);
            socket.emit('error', 'Failed to join room');
        }
    });

    socket.on('cell:check', ({ roomCode, cellIndex }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;

            const participant = room.participants[socket.id];
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
                checked: participant.checked,
                hasBingo: participant.hasBingo
            });

            if (checkedSet.has(cellIndex) && promptText !== 'FREE') {
                const message = `${participant.name} Completed: ${promptText}`;

                io.to(code).emit('activity', {
                    message,
                    participantName: participant.name,
                    prompt: promptText
                });

                sendPushToAll(room, 'Task Completed!', message);
            }

            if (!hadBingo && participant.hasBingo) {
                const bingoMsg = `${participant.name} got BINGO!`;

                io.to(code).emit('bingo', {
                    participantName: participant.name,
                    message: bingoMsg
                });

                sendPushToAll(room, 'BINGO!', bingoMsg);
            }

            io.to(code).emit('room:update', {
                participants: sanitizeParticipants(room.participants)
            });
        } catch (err) {
            console.error('cell:check error:', err);
        }
    });

    socket.on('disconnect', () => {
        try {
            for (const [code, room] of Object.entries(rooms)) {
                if (room.participants[socket.id]) {
                    const name = room.participants[socket.id].name;
                    delete room.participants[socket.id];

                    io.to(code).emit('room:update', {
                        participants: sanitizeParticipants(room.participants)
                    });

                    io.to(code).emit('activity', {
                        message: `${name} left the game`,
                        participantName: name
                    });
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

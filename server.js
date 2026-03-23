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
const users = {};      // { username: { username, passwordHash, activeRoom, settings, usernameChanged } }
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
    users[trimmed] = {
        username: trimmed, passwordHash, activeRoom: null,
        usernameChanged: false,
        settings: { notifications: true, autoConfirm: false, haptic: true }
    };

    const token = crypto.randomUUID();
    sessions[token] = trimmed;
    res.cookie('session', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ username: trimmed, activeRoom: null });
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
    res.json({ username: trimmed, activeRoom: getUserActiveRoom(trimmed) });
});

app.post('/api/logout', (req, res) => {
    const token = req.cookies?.session;
    if (token) delete sessions[token];
    res.clearCookie('session');
    res.json({ success: true });
});

// ── USER SETTINGS ──
app.get('/api/user-settings', requireAuth, (req, res) => {
    const user = users[req.username];
    if (!user) return res.status(404).json({ error: 'User not found' });
    const s = user.settings || { notifications: true, autoConfirm: false, haptic: true };
    res.json({ ...s, usernameChanged: user.usernameChanged || false });
});

app.post('/api/user-settings', requireAuth, (req, res) => {
    const user = users[req.username];
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.settings) user.settings = { notifications: true, autoConfirm: false, haptic: true };
    const { notifications, autoConfirm, haptic } = req.body;
    if (typeof notifications === 'boolean') user.settings.notifications = notifications;
    if (typeof autoConfirm === 'boolean') user.settings.autoConfirm = autoConfirm;
    if (typeof haptic === 'boolean') user.settings.haptic = haptic;
    res.json({ success: true });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
    const user = users[req.username];
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'All fields required' });
    if (newPassword.length < 4) return res.status(400).json({ error: 'New password must be at least 4 characters' });
    const match = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    res.json({ success: true });
});

app.post('/api/change-username', requireAuth, async (req, res) => {
    const oldName = req.username;
    const user = users[oldName];
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.usernameChanged) return res.status(400).json({ error: 'Username can only be changed once' });
    const trimmed = String(req.body.newUsername || '').trim().toLowerCase();
    if (trimmed.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (trimmed === oldName) return res.status(400).json({ error: 'That is already your username' });
    if (users[trimmed]) return res.status(409).json({ error: 'Username already taken' });

    users[trimmed] = { ...user, username: trimmed, usernameChanged: true };
    delete users[oldName];

    // Update sessions
    for (const token of Object.keys(sessions)) {
        if (sessions[token] === oldName) sessions[token] = trimmed;
    }
    // Update socket mappings
    for (const id of Object.keys(socketToUser)) {
        if (socketToUser[id].username === oldName) socketToUser[id].username = trimmed;
    }
    // Update active room references
    for (const room of Object.values(rooms)) {
        if (room.arbiter && room.arbiter.username === oldName) {
            room.arbiter.username = trimmed;
            room.arbiter.name = trimmed;
        }
        if (room.participants[oldName]) {
            const p = room.participants[oldName];
            p.name = trimmed;
            room.participants[trimmed] = p;
            delete room.participants[oldName];
        }
    }
    res.json({ username: trimmed });
});

app.post('/api/delete-account', requireAuth, async (req, res) => {
    const username = req.username;
    const user = users[username];
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });

    // Remove from active room
    if (user.activeRoom) {
        const room = rooms[user.activeRoom.roomCode];
        if (room) {
            if (user.activeRoom.isArbiter) {
                io.to(user.activeRoom.roomCode).emit('kicked', { reason: 'The host deleted their account.' });
                delete rooms[user.activeRoom.roomCode];
            } else {
                delete room.participants[username];
                io.to(user.activeRoom.roomCode).emit('room:update', { participants: getAllPlayers(room) });
            }
        }
    }
    // Revoke all sessions
    for (const token of Object.keys(sessions)) {
        if (sessions[token] === username) delete sessions[token];
    }
    delete users[username];
    res.clearCookie('session');
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    const token = req.cookies?.session;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const username = sessions[token];
    res.json({ username, activeRoom: getUserActiveRoom(username) });
});

function getUserActiveRoom(username) {
    const user = users[username];
    if (!user || !user.activeRoom) return null;
    const { roomCode, isArbiter } = user.activeRoom;
    const room = rooms[roomCode];
    if (!room) {
        user.activeRoom = null;
        return null;
    }
    return { roomCode, isArbiter };
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
    return Object.values(participants)
        .filter(p => !p.kicked)
        .map((p) => ({
            id: p.id,
            name: p.name,
            checked: p.checked,
            card: p.card,
            hasBingo: p.hasBingo,
            place: p.place || null,
            photoKeys: Object.keys(p.photos || {}).map(Number)
        }));
}

// Transfers host role to a random available participant. Room persists even if no participants remain.
function autoTransferHost(room, roomCode, oldHostName) {
    const eligible = Object.values(room.participants).filter(p => !p.kicked);
    const nextParticipant = eligible.length ? shuffleArray(eligible)[0] : null;

    if (!nextParticipant) {
        // No eligible participants to promote — leave the room intact
        return;
    }

    // Promote nextParticipant to arbiter
    room.arbiter = {
        id: nextParticipant.id,
        name: nextParticipant.name,
        username: nextParticipant.id,
        socketId: nextParticipant.socketId,
        pushSubscription: nextParticipant.pushSubscription,
        card: nextParticipant.card,
        checked: nextParticipant.checked,
        hasBingo: nextParticipant.hasBingo
    };
    delete room.participants[nextParticipant.id];

    if (users[nextParticipant.id]) {
        users[nextParticipant.id].activeRoom = { roomCode, isArbiter: true };
    }
    if (nextParticipant.socketId) {
        socketToUser[nextParticipant.socketId] = { username: nextParticipant.id, roomCode };
    }

    // Notify the new host to switch to arbiter UI
    if (nextParticipant.socketId) {
        const newHostSocket = io.sockets.sockets.get(nextParticipant.socketId);
        if (newHostSocket) {
            newHostSocket.emit('role:changed', {
                newRole: 'arbiter',
                data: {
                    roomCode,
                    gridSize: room.gridSize,
                    prompts: room.prompts,
                    proofRequired: room.proofRequired || [],
                    partyName: room.partyName,
                    participants: getAllPlayers(room),
                    arbiterCard: room.arbiter.card,
                    arbiterChecked: room.arbiter.checked,
                    gameState: room.state || 'waiting',
                    gameMode: room.gameMode || 'bingo',
                    activities: room.activities || [],
                    timerEnd: room.timerEnd || null,
                    activityLog: room.activityLog || [],
                    leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
                }
            });
        }
    }

    const msg = oldHostName
        ? `${oldHostName} left. ${nextParticipant.name} is now the host.`
        : `${nextParticipant.name} is now the host.`;

    io.to(roomCode).emit('room:update', { participants: getAllPlayers(room) });
    emitActivity(roomCode, room, { message: msg, participantName: nextParticipant.name });
}

function getAllPlayers(room) {
    const players = sanitizeParticipants(room.participants);
    if (room.arbiter) {
        players.unshift({
            id: room.arbiter.username || room.arbiter.id,
            name: room.arbiter.name,
            checked: room.arbiter.checked || [],
            card: room.arbiter.card || [],
            hasBingo: room.arbiter.hasBingo || false,
            place: room.arbiter.place || null,
            photoKeys: Object.keys(room.arbiter.photos || {}).map(Number),
            isHost: true
        });
    }
    return players;
}

function pushActivityLog(room, entry) {
    if (!room.activityLog) room.activityLog = [];
    room.activityLog.push({ ...entry, time: Date.now() });
    if (room.activityLog.length > 200) room.activityLog.shift();
}

// Persists to activityLog AND broadcasts to room
function emitActivity(roomCode, room, data) {
    // Strip imageData before storing in log (keep log small; photos served on demand)
    const { imageData, ...logEntry } = data;
    pushActivityLog(room, logEntry);
    io.to(roomCode).emit('activity', data);
}

function computeLeaderboard(room, isFinal = false) {
    if (!room.activities || !room.activities.length) return [];
    const allPlayers = getAllPlayers(room);

    // Pre-compute counter winners (player(s) with highest count) for final scoring
    const counterWinners = {};
    if (isFinal) {
        for (const act of room.activities) {
            if (!act.isCounter) continue;
            const counts = Object.values(act.completions || {});
            const maxCount = counts.length ? Math.max(...counts) : 0;
            if (maxCount > 0) {
                counterWinners[act.id] = new Set(
                    Object.entries(act.completions || {})
                        .filter(([, c]) => c === maxCount)
                        .map(([id]) => id)
                );
            }
        }
    }

    return allPlayers.map(p => {
        let points = 0;
        const completionMap = {};
        for (const act of room.activities) {
            const c = (act.completions || {})[p.id] || 0;
            if (act.isCounter) {
                completionMap[act.id] = c;
                // Counter points only awarded at game end to the winner(s)
                if (isFinal && counterWinners[act.id]?.has(p.id)) {
                    points += act.points;
                }
            } else if (c > 0) {
                points += act.points;
                if (act.firstCompletedBy === p.id) points += (act.firstBonus || 0);
                completionMap[act.id] = 1;
            }
        }
        return { id: p.id, name: p.name, points, completionMap };
    }).sort((a, b) => b.points - a.points);
}

// =======================
// PUSH NOTIFICATIONS
// =======================

async function sendPushToAll(room, title, body, excludeUsername, type) {
    const payload = JSON.stringify({ title, body, type: type || 'activity' });
    const targets = [];

    for (const [id, p] of Object.entries(room.participants)) {
        if (p.pushSubscription && id !== excludeUsername) {
            targets.push({ sub: p.pushSubscription, owner: p, label: `participant:${id}` });
        }
    }

    if (room.arbiter?.pushSubscription && room.arbiter.username !== excludeUsername) {
        targets.push({ sub: room.arbiter.pushSubscription, owner: room.arbiter, label: 'arbiter' });
    }

    for (const target of targets) {
        try {
            await webpush.sendNotification(target.sub, payload);
        } catch (err) {
            const status = err.statusCode;
            console.error(`Push send failed (${target.label}):`, status || err.message);
            // Remove expired or invalid subscriptions
            if (status === 410 || status === 404 || status === 401) {
                target.owner.pushSubscription = null;
                console.log(`Removed stale push subscription for ${target.label}`);
            }
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
            proofRequired,
            arbiterId,
            arbiterName,
            username,
            partyName,
            gameMode,
            activities,
            timerEnd
        } = req.body;

        const mode = gameMode === 'points' ? 'points' : 'bingo';

        if (!password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Missing password' });
        }

        let parsedGridSize = 4; // default (unused for points mode)
        if (mode === 'bingo') {
            parsedGridSize = Number(gridSize);
            if (!Number.isInteger(parsedGridSize) || parsedGridSize < 2) {
                return res.status(400).json({ error: 'Invalid grid size' });
            }
            if (!Array.isArray(prompts) || prompts.length < parsedGridSize * parsedGridSize) {
                return res.status(400).json({
                    error: `Need at least ${parsedGridSize * parsedGridSize} prompts`
                });
            }
        } else {
            if (!Array.isArray(activities) || activities.length === 0) {
                return res.status(400).json({ error: 'Points mode requires at least one activity' });
            }
        }

        const roomCode = generateRoomCode();

        const sanitizedActivities = mode === 'points'
            ? (activities || []).slice(0, 50).map((a, i) => ({
                id: `act_${i}`,
                description: String(a.description || '').trim().slice(0, 200),
                points: Math.max(1, Math.min(9999, parseInt(a.points) || 10)),
                firstBonus: Math.max(0, Math.min(9999, parseInt(a.firstBonus) || 0)),
                isCounter: !!a.isCounter,
                photoRequired: !!a.photoRequired,
                completions: {},
                firstCompletedBy: null
            })).filter(a => a.description)
            : [];

        rooms[roomCode] = {
            password,
            gridSize: parsedGridSize,
            prompts: mode === 'bingo' ? prompts.slice(0, parsedGridSize * parsedGridSize) : [],
            proofRequired: (mode === 'bingo' && Array.isArray(proofRequired))
                ? proofRequired.filter(s => typeof s === 'string').slice(0, 100)
                : [],
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
                hasBingo: false,
                place: null
            },
            state: 'waiting',
            placementCounter: 0,
            chatHistory: [],
            activityLog: [],
            feedPhotos: {},
            createdAt: Date.now(),
            lastActivity: Date.now(),
            gameMode: mode,
            activities: sanitizedActivities,
            timerEnd: (mode === 'points' && timerEnd) ? Number(timerEnd) : null
        };

        console.log('ROOM CREATED:', roomCode);

        return res.json({ roomCode });
    } catch (err) {
        console.error('CREATE ROOM ERROR:', err);
        return res.status(500).json({ error: 'Server failed to create room' });
    }
});

app.get('/api/rooms', (req, res) => {
    const token = req.cookies?.session;
    const username = (token && sessions[token]) ? sessions[token] : null;

    const list = Object.entries(rooms).map(([code, room]) => {
        let userStatus = 'none';
        if (username) {
            if (room.arbiter && room.arbiter.username === username) {
                userStatus = 'host';
            } else if (room.participants[username] && !room.participants[username].kicked) {
                userStatus = 'member';
            }
        }
        return {
            roomCode: code,
            partyName: room.partyName || 'Unnamed Party',
            participantCount: Object.values(room.participants).filter(p => !p.kicked).length + (room.arbiter ? 1 : 0),
            gridSize: room.gridSize,
            hostName: room.arbiter?.name || 'Unknown',
            gameMode: room.gameMode || 'bingo',
            userStatus
        };
    });
    res.json(list);
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

app.get('/api/my-rooms', requireAuth, (req, res) => {
    const username = req.username;
    const myRooms = [];

    for (const [code, room] of Object.entries(rooms)) {
        if (room.arbiter && room.arbiter.username === username) {
            myRooms.push({
                roomCode: code,
                partyName: room.partyName || 'Unnamed Party',
                role: 'host',
                playerCount: Object.values(room.participants).filter(p => !p.kicked).length + 1,
                gridSize: room.gridSize,
                hostName: room.arbiter.name,
                gameMode: room.gameMode || 'bingo'
            });
        } else if (room.participants[username] && !room.participants[username].kicked) {
            myRooms.push({
                roomCode: code,
                partyName: room.partyName || 'Unnamed Party',
                role: 'player',
                playerCount: Object.values(room.participants).filter(p => !p.kicked).length + (room.arbiter ? 1 : 0),
                gridSize: room.gridSize,
                hostName: room.arbiter?.name || 'Unknown',
                gameMode: room.gameMode || 'bingo'
            });
        }
    }

    res.json(myRooms);
});

app.post('/api/leave-room', (req, res) => {
    const token = req.cookies?.session;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const username = sessions[token];
    const user = users[username];
    if (!user || !user.activeRoom) {
        return res.json({ success: true });
    }

    const { roomCode, isArbiter } = user.activeRoom;
    const room = rooms[roomCode];
    user.activeRoom = null;

    if (room) {
        if (isArbiter) {
            const oldHostName = room.arbiter?.name;
            room.arbiter = null;
            autoTransferHost(room, roomCode, oldHostName);
        } else if (room.participants[username]) {
            const name = room.participants[username].name;
            // Keep participant data for state persistence — only clear socket
            room.participants[username].socketId = null;
            emitActivity(roomCode, room, { message: `${name} left the game`, participantName: name });
        }
    }

    res.json({ success: true });
});

app.post('/api/delete-room', requireAuth, async (req, res) => {
    try {
        const { roomCode, password } = req.body;
        const username = req.username;
        const user = users[username];

        if (!password) return res.status(400).json({ error: 'Password required' });

        const code = String(roomCode || '').toUpperCase();
        const room = rooms[code];
        if (!room) return res.status(404).json({ error: 'Room not found' });
        if (!room.arbiter || room.arbiter.username !== username) {
            return res.status(403).json({ error: 'Only the host can delete the party' });
        }

        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(401).json({ error: 'Incorrect password' });

        // Notify all connected clients
        io.to(code).emit('room:deleted');

        // Disconnect all sockets from the room
        const sockets = await io.in(code).fetchSockets();
        for (const s of sockets) {
            s.leave(code);
        }

        // Clear all users' activeRoom
        for (const pId of Object.keys(room.participants)) {
            if (users[pId]) users[pId].activeRoom = null;
        }
        if (room.arbiter.username && users[room.arbiter.username]) {
            users[room.arbiter.username].activeRoom = null;
        }

        delete rooms[code];
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE ROOM ERROR:', err);
        res.status(500).json({ error: 'Failed to delete room' });
    }
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

            // Store arbiter's socket and username
            room.arbiter.socketId = socket.id;
            room.arbiter.username = username;
            socketToUser[socket.id] = { username, roomCode: code };

            // Generate arbiter card on server if not already created
            if (!room.arbiter.card) {
                const shuffled = shuffleArray(room.prompts).slice(0, room.gridSize * room.gridSize);
                const center = Math.floor(shuffled.length / 2);
                if (room.gridSize % 2 === 1) shuffled[center] = 'FREE';
                room.arbiter.card = shuffled;
                room.arbiter.checked = room.gridSize % 2 === 1 ? [center] : [];
                room.arbiter.hasBingo = false;
            }

            // Set user's active room
            if (username && users[username]) {
                users[username].activeRoom = { roomCode: code, isArbiter: true };
            }

            socket.join(code);
            socket.emit('arbiter:joined', {
                roomCode: code,
                gridSize: room.gridSize,
                prompts: room.prompts,
                proofRequired: room.proofRequired || [],
                partyName: room.partyName,
                password: room.password,
                participants: getAllPlayers(room),
                arbiterCard: room.arbiter.card,
                arbiterChecked: room.arbiter.checked,
                gameState: room.state || 'waiting',
                chatHistory: room.chatHistory || [],
                activityLog: room.activityLog || [],
                gameMode: room.gameMode || 'bingo',
                activities: room.activities || [],
                timerEnd: room.timerEnd || null,
                leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
            });
        } catch (err) {
            console.error('arbiter:join error:', err);
            socket.emit('error', 'Failed to join as arbiter');
        }
    });

    socket.on('participant:join', ({ roomCode, password, name, username }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];

            if (!room) return socket.emit('error', 'Room not found');
            if (room.password !== password) return socket.emit('error', 'Wrong password');

            const participantKey = username || socket.id;

            // Block brand-new joins once game has started (existing participants can still rejoin)
            if (room.state !== 'waiting' && !room.participants[participantKey] &&
                !(room.arbiter && room.arbiter.username === participantKey)) {
                return socket.emit('error', 'Game already started. Ask the host to let you in next round.');
            }

            // If this user already has a card in this room, rejoin with existing state
            if (room.participants[participantKey]) {
                const existing = room.participants[participantKey];
                // Kicked players submit a join request to the host
                if (existing.kicked) {
                    const playerName = existing.name || name || participantKey;
                    room.pendingJoinRequests = room.pendingJoinRequests || {};
                    room.pendingJoinRequests[participantKey] = { socketId: socket.id, name: playerName };
                    socket.emit('join:pending', { message: 'Join request sent. Waiting for host approval...' });
                    if (room.arbiter && room.arbiter.socketId) {
                        const hostSock = io.sockets.sockets.get(room.arbiter.socketId);
                        if (hostSock) hostSock.emit('join:request', { playerId: participantKey, playerName });
                    }
                    // Push notification to host if app is closed/backgrounded
                    if (room.arbiter?.pushSubscription) {
                        webpush.sendNotification(
                            room.arbiter.pushSubscription,
                            JSON.stringify({ title: 'Rejoin Request', body: `${playerName} wants to rejoin ${room.partyName || 'the party'}`, type: 'join' })
                        ).catch(() => {});
                    }
                    return;
                }
                existing.socketId = socket.id;
                socketToUser[socket.id] = { username: participantKey, roomCode: code };

                if (username && users[username]) {
                    users[username].activeRoom = { roomCode: code, isArbiter: false };
                }

                socket.join(code);
                socket.emit('participant:joined', {
                    participantId: participantKey,
                    card: existing.card,
                    checked: existing.checked,
                    gridSize: room.gridSize,
                    roomCode: code,
                    partyName: room.partyName,
                    proofRequired: room.proofRequired || [],
                    gameState: room.state || 'waiting',
                    chatHistory: room.chatHistory || [],
                    gameMode: room.gameMode || 'bingo',
                    activities: room.activities || [],
                    timerEnd: room.timerEnd || null,
                    leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
                });

                io.to(code).emit('room:update', {
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
                hasBingo: false,
                place: null,
                photos: {}
            };
            room.lastActivity = Date.now();

            socketToUser[socket.id] = { username: participantKey, roomCode: code };

            if (username && users[username]) {
                users[username].activeRoom = { roomCode: code, isArbiter: false };
            }

            socket.join(code);

            socket.emit('participant:joined', {
                participantId: participantKey,
                card,
                checked: [...checked],
                gridSize: room.gridSize,
                roomCode: code,
                partyName: room.partyName,
                gameState: room.state || 'waiting',
                chatHistory: room.chatHistory || [],
                activityLog: room.activityLog || [],
                gameMode: room.gameMode || 'bingo',
                activities: room.activities || [],
                timerEnd: room.timerEnd || null,
                leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
            });

            io.to(code).emit('room:update', {
                participants: getAllPlayers(room)
            });

            const joinName = name || 'Someone';
            sendPushToAll(room, 'New Player Joined!', `${joinName} joined ${room.partyName}`, participantKey, 'join');
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
                if (!room.arbiter) return socket.emit('error', 'Not arbiter of this room');
                room.arbiter.socketId = socket.id;
                socketToUser[socket.id] = { username, roomCode: code };
                socket.join(code);
                socket.emit('arbiter:joined', {
                    roomCode: code,
                    gridSize: room.gridSize,
                    prompts: room.prompts,
                    partyName: room.partyName,
                    password: room.password,
                    participants: getAllPlayers(room),
                    arbiterCard: room.arbiter.card,
                    arbiterChecked: room.arbiter.checked,
                    gameState: room.state || 'waiting',
                    chatHistory: room.chatHistory || [],
                    activityLog: room.activityLog || [],
                    gameMode: room.gameMode || 'bingo',
                    activities: room.activities || [],
                    timerEnd: room.timerEnd || null,
                    leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
                });
                // Re-send any pending join requests to the newly connected host socket
                if (room.pendingJoinRequests) {
                    for (const [playerId, req] of Object.entries(room.pendingJoinRequests)) {
                        socket.emit('join:request', { playerId, playerName: req.name });
                    }
                }
            } else {
                const participant = room.participants[username];
                if (!participant || participant.kicked) return socket.emit('error', 'Not in this room');
                participant.socketId = socket.id;
                socketToUser[socket.id] = { username, roomCode: code };
                socket.join(code);
                socket.emit('participant:joined', {
                    participantId: username,
                    card: participant.card,
                    checked: participant.checked,
                    gridSize: room.gridSize,
                    roomCode: code,
                    partyName: room.partyName,
                    proofRequired: room.proofRequired || [],
                    gameState: room.state || 'waiting',
                    chatHistory: room.chatHistory || [],
                    activityLog: room.activityLog || [],
                    gameMode: room.gameMode || 'bingo',
                    activities: room.activities || [],
                    timerEnd: room.timerEnd || null,
                    leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
                });

                io.to(code).emit('room:update', {
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

            // Look up participant by socketToUser mapping
            const userInfo = socketToUser[socket.id];
            if (!userInfo) return;

            // Check if it's the arbiter
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

            // Regular players can only check cells, not uncheck them.
            // Only the arbiter (host) can uncheck cells for any player via their own board.
            if (checkedSet.has(cellIndex)) {
                if (!isArbiter) {
                    return socket.emit('error', 'Only the host can uncheck cells');
                }
                checkedSet.delete(cellIndex);
            } else {
                checkedSet.add(cellIndex);
            }

            participant.checked = [...checkedSet];
            room.lastActivity = Date.now();

            const promptText = participant.card[cellIndex];
            const hadBingo = participant.hasBingo;
            participant.hasBingo = checkBingo(checkedSet, room.gridSize);

            socket.emit('cell:updated', {
                checked: participant.checked,
                hasBingo: participant.hasBingo
            });

            if (checkedSet.has(cellIndex) && promptText !== 'FREE') {
                const message = `${participant.name} Completed: ${promptText}`;

                emitActivity(code, room, { message, participantName: participant.name, prompt: promptText });
                sendPushToAll(room, 'Task Completed!', message, userInfo.username, 'task');
            }

            if (!hadBingo && participant.hasBingo) {
                room.placementCounter = (room.placementCounter || 0) + 1;
                participant.place = room.placementCounter;

                const placeEmoji = ['🥇','🥈','🥉'][participant.place - 1] || (participant.place + 'th');
                const bingoMsg = `${placeEmoji} ${participant.name} got PIngo!`;

                io.to(code).emit('bingo', {
                    participantName: participant.name,
                    message: bingoMsg,
                    place: participant.place,
                    placeEmoji
                });

                sendPushToAll(room, 'PIngo!', bingoMsg, userInfo.username, 'bingo');
            }

            // Always emit room:update so host progress is visible to all
            io.to(code).emit('room:update', {
                participants: getAllPlayers(room)
            });
        } catch (err) {
            console.error('cell:check error:', err);
        }
    });

    socket.on('game:start', ({ roomCode }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;
            if (!room.arbiter || room.arbiter.socketId !== socket.id) {
                return socket.emit('error', 'Only the host can start the game');
            }
            if (room.state !== 'waiting') return;

            room.state = 'active';
            io.to(code).emit('game:started', { state: 'active' });
            emitActivity(code, room, { message: 'The game has started! Good luck everyone!' });
            sendPushToAll(room, 'Game Started! 🎲', 'The host has started the game. Good luck!', null, 'game');
        } catch (err) {
            console.error('game:start error:', err);
        }
    });

    socket.on('game:end', ({ roomCode }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;
            if (!room.arbiter || room.arbiter.socketId !== socket.id) {
                return socket.emit('error', 'Only the host can end the game');
            }
            if (room.state === 'ended') return;

            room.state = 'ended';

            let standings;
            if (room.gameMode === 'points') {
                standings = computeLeaderboard(room, true).map((p, i) => ({
                    name: p.name, place: i + 1, points: p.points
                }));
            } else {
                standings = getAllPlayers(room)
                    .map(p => ({ name: p.name, place: p.place, checkedCount: p.checked.length, hasBingo: p.hasBingo }))
                    .sort((a, b) => (a.place || 999) - (b.place || 999));
            }

            const finalLeaderboard = room.gameMode === 'points' ? computeLeaderboard(room, true) : [];
            io.to(code).emit('game:over', { standings, gameMode: room.gameMode || 'bingo', leaderboard: finalLeaderboard });
            emitActivity(code, room, { message: 'The host has ended the game.' });
            sendPushToAll(room, 'Game Over!', 'The host ended the game. Check the final standings!', null, 'game');
        } catch (err) {
            console.error('game:end error:', err);
        }
    });

    socket.on('game:reset', ({ roomCode }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;
            if (!room.arbiter || room.arbiter.socketId !== socket.id) {
                return socket.emit('error', 'Only the host can restart the game');
            }

            room.state = 'active';
            room.placementCounter = 0;

            const totalCells = room.gridSize * room.gridSize;
            const centerIdx = Math.floor(totalCells / 2);
            const freeChecked = room.gridSize % 2 === 1 ? [centerIdx] : [];

            // Reset and reshuffle each participant
            for (const p of Object.values(room.participants)) {
                if (p.kicked) continue;
                const shuffled = shuffleArray(room.prompts).slice(0, totalCells);
                if (room.gridSize % 2 === 1) shuffled[centerIdx] = 'FREE';
                p.card = shuffled;
                p.checked = [...freeChecked];
                p.hasBingo = false;
                p.place = null;
                p.photos = {};
                // Send new card to the player's socket
                if (p.socketId) {
                    const pSocket = io.sockets.sockets.get(p.socketId);
                    if (pSocket) {
                        pSocket.emit('card:reset', {
                            card: p.card,
                            checked: p.checked,
                            gridSize: room.gridSize
                        });
                    }
                }
            }

            // Reset arbiter card too
            if (room.arbiter) {
                const shuffled = shuffleArray(room.prompts).slice(0, totalCells);
                if (room.gridSize % 2 === 1) shuffled[centerIdx] = 'FREE';
                room.arbiter.card = shuffled;
                room.arbiter.checked = [...freeChecked];
                room.arbiter.hasBingo = false;
                room.arbiter.place = null;
                room.arbiter.photos = {};
                if (room.arbiter.socketId) {
                    const aSocket = io.sockets.sockets.get(room.arbiter.socketId);
                    if (aSocket) {
                        aSocket.emit('card:reset', {
                            card: room.arbiter.card,
                            checked: room.arbiter.checked,
                            gridSize: room.gridSize
                        });
                    }
                }
            }

            room.lastActivity = Date.now();
            io.to(code).emit('game:started', { state: 'active' });
            io.to(code).emit('room:update', { participants: getAllPlayers(room) });
            emitActivity(code, room, { message: 'New round started! Cards reshuffled.' });
        } catch (err) {
            console.error('game:reset error:', err);
        }
    });

    // ── POINTS MODE HANDLERS ──
    socket.on('points:complete', ({ roomCode, activityId, imageData }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room || room.gameMode !== 'points') return;
            const userInfo = socketToUser[socket.id];
            if (!userInfo) return;
            const playerId = userInfo.username;
            const act = room.activities.find(a => a.id === activityId);
            if (!act || act.isCounter) return;
            if ((act.completions[playerId] || 0) > 0) return; // already done
            act.completions[playerId] = 1;
            if (!act.firstCompletedBy) act.firstCompletedBy = playerId;
            room.lastActivity = Date.now();
            const name = room.participants[playerId]?.name || room.arbiter?.name || playerId;
            const leaderboard = computeLeaderboard(room);
            io.to(code).emit('points:update', { activities: room.activities, leaderboard });
            // Handle optional photo
            let photoId = null;
            if (typeof imageData === 'string' && imageData.length > 0 && imageData.length <= 700000) {
                photoId = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
                room.feedPhotos = room.feedPhotos || {};
                room.feedPhotos[photoId] = imageData;
            }
            const msgSuffix = photoId ? ' 📷' : '!';
            const completeMsg = {
                message: `${name} completed "${act.description}"${msgSuffix}`,
                participantName: name,
                ...(photoId && { photoId, imageData })
            };
            emitActivity(code, room, completeMsg);
            sendPushToAll(room, 'Activity Completed!', `${name} completed "${act.description}"`, playerId, 'task');
        } catch (err) { console.error('points:complete error:', err); }
    });

    socket.on('points:increment', ({ roomCode, activityId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room || room.gameMode !== 'points') return;
            const userInfo = socketToUser[socket.id];
            if (!userInfo) return;
            const playerId = userInfo.username;
            const act = room.activities.find(a => a.id === activityId);
            if (!act || !act.isCounter) return;
            act.completions[playerId] = (act.completions[playerId] || 0) + 1;
            room.lastActivity = Date.now();
            const name = room.participants[playerId]?.name || room.arbiter?.name || playerId;
            const newCount = act.completions[playerId];
            const leaderboard = computeLeaderboard(room);
            io.to(code).emit('points:update', { activities: room.activities, leaderboard });
            const incrMsg = { message: `${name} logged ${newCount}× "${act.description}"`, participantName: name };
            emitActivity(code, room, incrMsg);
            sendPushToAll(room, 'Counter Updated', `${name}: ${newCount}× ${act.description}`, playerId, 'task');
        } catch (err) { console.error('points:increment error:', err); }
    });

    socket.on('points:decrement', ({ roomCode, activityId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room || room.gameMode !== 'points') return;
            const userInfo = socketToUser[socket.id];
            if (!userInfo) return;
            const playerId = userInfo.username;
            const act = room.activities.find(a => a.id === activityId);
            if (!act || !act.isCounter) return;
            const current = act.completions[playerId] || 0;
            if (current <= 0) return;
            act.completions[playerId] = current - 1;
            room.lastActivity = Date.now();
            const name = room.participants[playerId]?.name || room.arbiter?.name || playerId;
            const newCount = act.completions[playerId];
            const leaderboard = computeLeaderboard(room);
            io.to(code).emit('points:update', { activities: room.activities, leaderboard });
            const decrMsg = { message: `${name} adjusted to ${newCount}× "${act.description}"`, participantName: name };
            emitActivity(code, room, decrMsg);
            sendPushToAll(room, 'Counter Adjusted', `${name}: now ${newCount}× ${act.description}`, playerId, 'task');
        } catch (err) { console.error('points:decrement error:', err); }
    });

    socket.on('points:undo', ({ roomCode, activityId, playerId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room || room.gameMode !== 'points') return;
            if (!room.arbiter || room.arbiter.socketId !== socket.id) {
                return socket.emit('error', 'Only the host can undo player actions');
            }
            if (typeof playerId !== 'string') return;
            const act = room.activities.find(a => a.id === activityId);
            if (!act) return;

            const playerName = room.participants[playerId]?.name || (room.arbiter?.username === playerId ? room.arbiter?.name : null) || playerId;
            const hostName = room.arbiter?.name || 'Host';

            if (act.isCounter) {
                const current = act.completions[playerId] || 0;
                if (current <= 0) return;
                act.completions[playerId] = current - 1;
                const newCount = act.completions[playerId];
                room.lastActivity = Date.now();
                const leaderboard = computeLeaderboard(room);
                io.to(code).emit('points:update', { activities: room.activities, leaderboard });
                const adjMsg = { message: `${hostName} adjusted "${act.description}" for ${playerName} to ${newCount}`, participantName: playerName };
                emitActivity(code, room, adjMsg);
                sendPushToAll(room, 'Host Adjustment', `${hostName} adjusted ${playerName}'s count for "${act.description}"`, null, 'task');
            } else {
                if (!(act.completions[playerId] > 0)) return;
                act.completions[playerId] = 0;
                // Reset firstCompletedBy if this player was first
                if (act.firstCompletedBy === playerId) {
                    const remaining = Object.entries(act.completions).filter(([, c]) => c > 0);
                    act.firstCompletedBy = remaining.length > 0 ? remaining[0][0] : null;
                }
                room.lastActivity = Date.now();
                const leaderboard = computeLeaderboard(room);
                io.to(code).emit('points:update', { activities: room.activities, leaderboard });
                const undoMsg = { message: `${hostName} undid "${act.description}" for ${playerName}`, participantName: playerName };
                emitActivity(code, room, undoMsg);
                sendPushToAll(room, 'Host Undo', `${hostName} undid "${act.description}" for ${playerName}`, null, 'task');
            }
        } catch (err) { console.error('points:undo error:', err); }
    });

    socket.on('task:photo', ({ roomCode, cellIndex, imageData }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;

            const userInfo = socketToUser[socket.id];
            if (!userInfo) return;

            let participant;
            if (room.arbiter && room.arbiter.socketId === socket.id) {
                participant = room.arbiter;
            } else {
                participant = room.participants[userInfo.username];
            }
            if (!participant) return;

            if (!Number.isInteger(cellIndex) || cellIndex < 0 || cellIndex >= participant.card.length) return;

            const cellText = participant.card[cellIndex];

            // Validate base64 size (≤500KB unencoded ~ ≤680KB base64)
            if (typeof imageData !== 'string' || imageData.length > 700000 || imageData.length === 0) {
                return socket.emit('error', 'Photo is too large. Please use a smaller image.');
            }

            // Store photo per-participant (for board view) and in feedPhotos (for feed persistence)
            const photoId = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
            room.feedPhotos = room.feedPhotos || {};
            room.feedPhotos[photoId] = imageData;
            participant.photos = participant.photos || {};
            participant.photos[cellIndex] = imageData;

            // Check cell (mark as completed if not already)
            const checkedSet = new Set(participant.checked);
            const alreadyChecked = checkedSet.has(cellIndex);
            if (!alreadyChecked) {
                checkedSet.add(cellIndex);
                participant.checked = [...checkedSet];
                room.lastActivity = Date.now();

                const hadBingo = participant.hasBingo;
                participant.hasBingo = checkBingo(checkedSet, room.gridSize);

                socket.emit('cell:updated', { checked: participant.checked, hasBingo: participant.hasBingo });

                const message = `${participant.name} completed: ${cellText} 📷`;
                emitActivity(code, room, { message, participantName: participant.name, prompt: cellText, photoId, imageData });
                sendPushToAll(room, 'Task Completed!', message, userInfo.username, 'task');

                if (!hadBingo && participant.hasBingo) {
                    room.placementCounter = (room.placementCounter || 0) + 1;
                    participant.place = room.placementCounter;
                    const placeEmoji = ['🥇','🥈','🥉'][participant.place - 1] || (participant.place + 'th');
                    const bingoMsg = `${placeEmoji} ${participant.name} got PIngo!`;
                    io.to(code).emit('bingo', { participantName: participant.name, message: bingoMsg, place: participant.place, placeEmoji });
                    sendPushToAll(room, 'PIngo!', bingoMsg, userInfo.username, 'bingo');
                }
            } else {
                // Cell already checked — photo added to an already-completed cell
                const message = `${participant.name} added photo: ${cellText} 📷`;
                emitActivity(code, room, { message, participantName: participant.name, prompt: cellText, photoId, imageData });
                socket.emit('cell:updated', { checked: participant.checked, hasBingo: participant.hasBingo });
            }

            io.to(code).emit('room:update', { participants: getAllPlayers(room) });
        } catch (err) {
            console.error('task:photo error:', err);
        }
    });

    socket.on('photo:request', ({ roomCode, targetId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;

            let target;
            if (room.arbiter && (room.arbiter.id === targetId || room.arbiter.username === targetId)) {
                target = room.arbiter;
            } else {
                target = room.participants[targetId];
            }
            if (!target) return;

            socket.emit('photo:data', {
                targetId,
                photos: target.photos || {}
            });
        } catch (err) {
            console.error('photo:request error:', err);
        }
    });

    socket.on('feed:photos:request', ({ roomCode, photoIds }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room || !room.feedPhotos || !Array.isArray(photoIds)) return;
            const photos = {};
            photoIds.forEach(id => {
                if (typeof id === 'string' && room.feedPhotos[id]) photos[id] = room.feedPhotos[id];
            });
            socket.emit('feed:photos:data', { photos });
        } catch (err) { console.error('feed:photos:request error:', err); }
    });

    socket.on('chat:message', ({ roomCode, message }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;

            const userInfo = socketToUser[socket.id];
            if (!userInfo) return;

            let senderName;
            if (room.arbiter && room.arbiter.socketId === socket.id) {
                senderName = room.arbiter.name;
            } else {
                const p = room.participants[userInfo.username];
                if (!p) return;
                senderName = p.name;
            }

            if (typeof message !== 'string' || !message.trim()) return;
            const safeMsg = message.trim().slice(0, 200);

            const chatEntry = {
                senderName,
                message: safeMsg,
                time: Date.now()
            };

            // Store in room chat history (cap at 200 messages)
            room.chatHistory = room.chatHistory || [];
            room.chatHistory.push(chatEntry);
            if (room.chatHistory.length > 200) room.chatHistory.shift();

            io.to(code).emit('chat:received', chatEntry);
        } catch (err) {
            console.error('chat:message error:', err);
        }
    });

    socket.on('host:uncheck', ({ roomCode, targetId, cellIndex }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;
            if (!room.arbiter || room.arbiter.socketId !== socket.id) {
                return socket.emit('error', 'Only the host can uncheck cells for players');
            }

            let target;
            let targetSocket;
            if (room.arbiter.username === targetId || room.arbiter.id === targetId) {
                target = room.arbiter;
                targetSocket = room.arbiter.socketId;
            } else {
                target = room.participants[targetId];
                targetSocket = target?.socketId;
            }
            if (!target) return socket.emit('error', 'Player not found');

            if (!Number.isInteger(cellIndex) || cellIndex < 0 || cellIndex >= target.card.length) return;

            const checkedSet = new Set(target.checked);
            if (!checkedSet.has(cellIndex)) return; // already unchecked

            checkedSet.delete(cellIndex);
            target.checked = [...checkedSet];
            target.hasBingo = checkBingo(checkedSet, room.gridSize);
            room.lastActivity = Date.now();

            // Remove associated photo so it no longer appears as valid
            if (target.photos && target.photos[cellIndex] !== undefined) {
                delete target.photos[cellIndex];
            }

            // Notify the target player
            if (targetSocket) {
                const ts = io.sockets.sockets.get(targetSocket);
                if (ts) {
                    ts.emit('cell:updated', { checked: target.checked, hasBingo: target.hasBingo });
                }
            }

            const promptText = target.card[cellIndex];
            emitActivity(code, room, { message: `Host unchecked "${promptText}" for ${target.name}`, participantName: target.name, prompt: promptText });

            io.to(code).emit('room:update', { participants: getAllPlayers(room) });
        } catch (err) {
            console.error('host:uncheck error:', err);
        }
    });

    socket.on('host:kick', ({ roomCode, participantId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;
            if (!room.arbiter || room.arbiter.socketId !== socket.id) {
                return socket.emit('error', 'Only the host can kick players');
            }

            const participant = room.participants[participantId];
            if (!participant) return socket.emit('error', 'Player not found');

            const name = participant.name;
            const kickedSocketId = participant.socketId;

            // Preserve participant data for potential rejoin — mark as kicked
            participant.kicked = true;
            participant.socketId = null;
            if (users[participantId]) {
                users[participantId].activeRoom = null;
            }

            if (kickedSocketId) {
                delete socketToUser[kickedSocketId];
                const kickedSocket = io.sockets.sockets.get(kickedSocketId);
                if (kickedSocket) {
                    kickedSocket.emit('kicked');
                    kickedSocket.leave(code);
                }
            }

            io.to(code).emit('room:update', { participants: getAllPlayers(room) });
            emitActivity(code, room, { message: `${name} was kicked`, participantName: name });
        } catch (err) {
            console.error('host:kick error:', err);
            socket.emit('error', 'Failed to kick player');
        }
    });

    socket.on('join:approve', ({ roomCode, playerId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room || !room.arbiter || room.arbiter.socketId !== socket.id) return;
            const pending = (room.pendingJoinRequests || {})[playerId];
            if (!pending) return;
            delete room.pendingJoinRequests[playerId];

            const participant = room.participants[playerId];
            if (!participant) return;
            participant.kicked = false;
            participant.socketId = pending.socketId;

            socketToUser[pending.socketId] = { username: playerId, roomCode: code };
            if (users[playerId]) users[playerId].activeRoom = { roomCode: code, isArbiter: false };

            const pendingSock = io.sockets.sockets.get(pending.socketId);
            if (pendingSock) {
                pendingSock.join(code);
                pendingSock.emit('participant:joined', {
                    participantId: playerId,
                    card: participant.card,
                    checked: participant.checked,
                    gridSize: room.gridSize,
                    roomCode: code,
                    partyName: room.partyName,
                    proofRequired: room.proofRequired || [],
                    gameState: room.state || 'waiting',
                    chatHistory: room.chatHistory || [],
                    activityLog: room.activityLog || [],
                    gameMode: room.gameMode || 'bingo',
                    activities: room.activities || [],
                    timerEnd: room.timerEnd || null,
                    leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
                });
            }
            io.to(code).emit('room:update', { participants: getAllPlayers(room) });
            emitActivity(code, room, { message: `${participant.name} rejoined`, participantName: participant.name });
        } catch (err) { console.error('join:approve error:', err); }
    });

    socket.on('join:deny', ({ roomCode, playerId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room || !room.arbiter || room.arbiter.socketId !== socket.id) return;
            const pending = (room.pendingJoinRequests || {})[playerId];
            if (!pending) return;
            delete room.pendingJoinRequests[playerId];
            const pendingSock = io.sockets.sockets.get(pending.socketId);
            if (pendingSock) pendingSock.emit('join:denied', { message: 'Your request to rejoin was denied by the host.' });
        } catch (err) { console.error('join:deny error:', err); }
    });

    socket.on('host:transfer', ({ roomCode, newHostId }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];
            if (!room) return;
            if (!room.arbiter || room.arbiter.socketId !== socket.id) {
                return socket.emit('error', 'Only the host can transfer');
            }

            const newHost = room.participants[newHostId];
            if (!newHost) return socket.emit('error', 'Player not found');

            // Save old arbiter data
            const oldArbiter = { ...room.arbiter };

            // Move old arbiter to participants
            room.participants[oldArbiter.username] = {
                id: oldArbiter.username,
                name: oldArbiter.name,
                socketId: oldArbiter.socketId,
                pushSubscription: oldArbiter.pushSubscription,
                card: oldArbiter.card,
                checked: oldArbiter.checked,
                hasBingo: oldArbiter.hasBingo
            };

            // Move new host to arbiter
            room.arbiter = {
                id: newHost.id,
                name: newHost.name,
                username: newHost.id,
                socketId: newHost.socketId,
                pushSubscription: newHost.pushSubscription,
                card: newHost.card,
                checked: newHost.checked,
                hasBingo: newHost.hasBingo
            };
            delete room.participants[newHostId];

            // Update activeRoom
            if (users[oldArbiter.username]) {
                users[oldArbiter.username].activeRoom = { roomCode: code, isArbiter: false };
            }
            if (users[newHostId]) {
                users[newHostId].activeRoom = { roomCode: code, isArbiter: true };
            }

            // Update socketToUser
            if (oldArbiter.socketId) {
                socketToUser[oldArbiter.socketId] = { username: oldArbiter.username, roomCode: code };
            }
            if (newHost.socketId) {
                socketToUser[newHost.socketId] = { username: newHostId, roomCode: code };
            }

            // Notify old host: become participant
            if (oldArbiter.socketId) {
                const oldSocket = io.sockets.sockets.get(oldArbiter.socketId);
                if (oldSocket) {
                    oldSocket.emit('role:changed', {
                        newRole: 'participant',
                        data: {
                            participantId: oldArbiter.username,
                            card: oldArbiter.card,
                            checked: oldArbiter.checked,
                            gridSize: room.gridSize,
                            roomCode: code,
                            partyName: room.partyName,
                            gameMode: room.gameMode || 'bingo',
                            activities: room.activities || [],
                            timerEnd: room.timerEnd || null,
                    leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
                        }
                    });
                }
            }

            // Notify new host: become arbiter
            if (newHost.socketId) {
                const newSocket = io.sockets.sockets.get(newHost.socketId);
                if (newSocket) {
                    newSocket.emit('role:changed', {
                        newRole: 'arbiter',
                        data: {
                            roomCode: code,
                            gridSize: room.gridSize,
                            prompts: room.prompts,
                            partyName: room.partyName,
                            participants: getAllPlayers(room),
                            arbiterCard: room.arbiter.card,
                            arbiterChecked: room.arbiter.checked,
                            gameState: room.state || 'waiting',
                            gameMode: room.gameMode || 'bingo',
                            activities: room.activities || [],
                            timerEnd: room.timerEnd || null,
                    leaderboard: room.gameMode === 'points' ? computeLeaderboard(room) : []
                        }
                    });
                }
            }

            io.to(code).emit('room:update', { participants: getAllPlayers(room) });
            emitActivity(code, room, { message: `${newHost.name} is now the host`, participantName: newHost.name });
        } catch (err) {
            console.error('host:transfer error:', err);
            socket.emit('error', 'Failed to transfer host');
        }
    });

    socket.on('disconnect', () => {
        try {
            // Just clear the socket mapping — do NOT delete the participant
            delete socketToUser[socket.id];

            // Clear socketId from any participant/arbiter that had this socket
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

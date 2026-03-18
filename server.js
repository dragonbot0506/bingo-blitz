const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const twilio = require('twilio');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' }
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Twilio config
const globalTwilioConfig = {
    accountSid: 'AC6b6f24faa2be6118f13f2034a9be9b54',
    authToken: '94657acedb889418acb80f550c2ec7cf',
    fromNumber: '+13509003322'
};

console.log('Twilio SMS enabled globally');

// In-memory store
const rooms = {};

// =======================
// PHONE HELPERS
// =======================

function buildPhoneNumber(phoneSlots) {
    if (!phoneSlots || typeof phoneSlots !== 'object') return null;

    const area = String(phoneSlots.area || '').replace(/\D/g, '');
    const prefix = String(phoneSlots.prefix || '').replace(/\D/g, '');
    const line = String(phoneSlots.line || '').replace(/\D/g, '');

    if (!area && !prefix && !line) return null;
    if (area.length !== 3 || prefix.length !== 3 || line.length !== 4) return null;

    return `+1${area}${prefix}${line}`;
}

function normalizePhone(input) {
    if (!input) return null;

    const digits = String(input).replace(/\D/g, '');

    if (digits.length === 10) return `+1${digits}`;
    if (digits.length === 11 && digits.startsWith('1')) return `+1${digits.slice(1)}`;

    return null;
}

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
// SMS
// =======================

async function sendSMS(twilioConfig, to, message) {
    try {
        if (!twilioConfig?.accountSid || !twilioConfig?.authToken || !twilioConfig?.fromNumber) {
            console.log('SMS skipped: missing Twilio config');
            return;
        }

        const client = twilio(twilioConfig.accountSid, twilioConfig.authToken);

        console.log('Sending SMS →', to, '|', message);

        const result = await client.messages.create({
            body: message,
            from: twilioConfig.fromNumber,
            to
        });

        console.log('SMS sent:', result.sid);
    } catch (err) {
        console.error('Twilio ERROR:', err?.message || err);
    }
}

function sendToAll(room, message) {
    if (!room?.twilioConfig?.accountSid) return;

    const targets = Object.values(room.participants)
        .map((p) => p.phone)
        .filter(Boolean);

    if (room.arbiter?.phone) {
        targets.push(room.arbiter.phone);
    }

    const unique = [...new Set(targets)];

    for (const phone of unique) {
        sendSMS(room.twilioConfig, phone, message);
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
            arbiterName,
            arbiterPhoneSlots,
            arbiterPhone
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

        let formattedArbiterPhone = null;

        if (arbiterPhoneSlots) {
            formattedArbiterPhone = buildPhoneNumber(arbiterPhoneSlots);
            if (!formattedArbiterPhone) {
                return res.status(400).json({ error: 'Invalid arbiter phone number' });
            }
        } else if (arbiterPhone) {
            formattedArbiterPhone = normalizePhone(arbiterPhone);
            if (!formattedArbiterPhone) {
                return res.status(400).json({ error: 'Invalid arbiter phone number' });
            }
        }

        const roomCode = generateRoomCode();

        rooms[roomCode] = {
            password,
            gridSize: parsedGridSize,
            prompts: prompts.slice(0, parsedGridSize * parsedGridSize),
            participants: {},
            twilioConfig: globalTwilioConfig,
            arbiter: {
                id: arbiterId || 'host',
                name: arbiterName || 'Host',
                phone: formattedArbiterPhone
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

app.get('/api/sms-status', (req, res) => {
    res.json({ enabled: true });
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

    socket.on('participant:join', ({ roomCode, password, name, phoneSlots, phone }) => {
        try {
            const code = String(roomCode || '').toUpperCase();
            const room = rooms[code];

            if (!room) return socket.emit('error', 'Room not found');
            if (room.password !== password) return socket.emit('error', 'Wrong password');

            let formattedPhone = null;

            if (phoneSlots) {
                formattedPhone = buildPhoneNumber(phoneSlots);
                if (!formattedPhone) {
                    return socket.emit('error', 'Invalid phone number');
                }
            } else if (phone) {
                formattedPhone = normalizePhone(phone);
                if (!formattedPhone) {
                    return socket.emit('error', 'Invalid phone number');
                }
            }

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
                phone: formattedPhone,
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
                const message = `🎯 ${participant.name} has ${promptText}!`;

                io.to(code).emit('activity', {
                    message,
                    participantName: participant.name,
                    prompt: promptText
                });

                sendToAll(room, message);
            }

            if (!hadBingo && participant.hasBingo) {
                const bingoMsg = `🎉 BINGO! ${participant.name} got BINGO!`;

                io.to(code).emit('bingo', {
                    participantName: participant.name,
                    message: bingoMsg
                });

                sendToAll(room, bingoMsg);
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
    console.log(`Bingo server running on port ${PORT}`);
});

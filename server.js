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

// ✅ FIXED Twilio config (E.164 REQUIRED)
const globalTwilioConfig = {
    accountSid: 'AC6b6f24faa2be6118f13f2034a9be9b54',
    authToken: '94657acedb889418acb80f550c2ec7cf',
    fromNumber: '+13509003322'
};

console.log('Twilio SMS enabled globally');

// In-memory store
const rooms = {};

// 🔥 SLOT-BASED PHONE BUILDER
function buildPhoneNumber({ area, prefix, line }) {
    if (!area || !prefix || !line) return null;

    const digits = `${area}${prefix}${line}`;

    if (!/^\d{10}$/.test(digits)) return null;

    return `+1${digits}`; // Twilio-safe
}

// 🔥 FALLBACK (if someone sends a full string)
function normalizePhone(input) {
    if (!input) return null;
    const digits = input.replace(/\D/g, '');

    if (digits.length === 10) return `+1${digits}`;
    if (digits.length === 11 && digits.startsWith('1')) return `+1${digits.slice(1)}`;

    return null;
}

function generateRoomCode() {
    return Math.random().toString(36).substring(2, 7).toUpperCase();
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

async function sendSMS(twilioConfig, to, message) {
    try {
        const client = twilio(twilioConfig.accountSid, twilioConfig.authToken);

        const res = await client.messages.create({
            body: message,
            from: twilioConfig.fromNumber,
            to
        });

        console.log('SMS sent:', res.sid);
    } catch (err) {
        console.error('Twilio FULL error:', err);
    }
}

// REST: Create room
app.post('/api/rooms', (req, res) => {
    const {
        password,
        gridSize,
        prompts,
        arbiterId,
        arbiterName,
        arbiterPhoneSlots, // 🔥 expects { area, prefix, line }
        arbiterPhone // fallback
    } = req.body;

    if (!password || !gridSize || !prompts || prompts.length < gridSize * gridSize) {
        return res.status(400).json({ error: 'Invalid room setup' });
    }

    const roomCode = generateRoomCode();

    // 🔥 SLOT FIRST, fallback second
    let formattedArbiterPhone =
        buildPhoneNumber(arbiterPhoneSlots) ||
        normalizePhone(arbiterPhone);

    if (arbiterPhone && !formattedArbiterPhone) {
        return res.status(400).json({ error: 'Invalid arbiter phone number' });
    }

    rooms[roomCode] = {
        password,
        gridSize,
        prompts,
        participants: {},
        twilioConfig: globalTwilioConfig,
        arbiter: {
            id: arbiterId,
            name: arbiterName,
            phone: formattedArbiterPhone
        },
        createdAt: Date.now()
    };

    res.json({ roomCode });
});

app.get('/api/rooms/:code', (req, res) => {
    const room = rooms[req.params.code.toUpperCase()];
    if (!room) return res.status(404).json({ error: 'Room not found' });

    res.json({
        gridSize: room.gridSize,
        participantCount: Object.keys(room.participants).length
    });
});

app.get('/api/sms-status', (req, res) => {
    res.json({ enabled: true });
});

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('participant:join', ({ roomCode, password, name, phoneSlots, phone }) => {
        const room = rooms[roomCode?.toUpperCase()];
        if (!room) return socket.emit('error', 'Room not found');
        if (room.password !== password) return socket.emit('error', 'Wrong password');

        // 🔥 SLOT FIRST
        const formattedPhone =
            buildPhoneNumber(phoneSlots) ||
            normalizePhone(phone);

        if (phone && !formattedPhone) {
            return socket.emit('error', 'Invalid phone number');
        }

        const code = roomCode.toUpperCase();
        const participantId = socket.id;

        const shuffled = shuffleArray(room.prompts).slice(0, room.gridSize * room.gridSize);
        const totalCells = room.gridSize * room.gridSize;
        const centerIdx = Math.floor(totalCells / 2);

        let card = [...shuffled];
        if (room.gridSize % 2 === 1) {
            card[centerIdx] = 'FREE';
        }

        const checked = new Set(room.gridSize % 2 === 1 ? [centerIdx] : []);

        room.participants[participantId] = {
            id: participantId,
            name,
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
    });

    socket.on('cell:check', async ({ roomCode, cellIndex }) => {
        const code = roomCode?.toUpperCase();
        const room = rooms[code];
        if (!room) return;

        const participant = room.participants[socket.id];
        if (!participant) return;

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

            const targets = Object.values(room.participants)
                .map(p => p.phone)
                .filter(Boolean);

            if (room.arbiter.phone) targets.push(room.arbiter.phone);

            const unique = [...new Set(targets)];

            for (const phone of unique) {
                await sendSMS(room.twilioConfig, phone, message);
            }
        }

        if (!hadBingo && participant.hasBingo) {
            const bingoMsg = `🎉 BINGO! ${participant.name} got BINGO!`;

            io.to(code).emit('bingo', {
                participantName: participant.name,
                message: bingoMsg
            });

            const targets = Object.values(room.participants)
                .map(p => p.phone)
                .filter(Boolean);

            if (room.arbiter.phone) targets.push(room.arbiter.phone);

            const unique = [...new Set(targets)];

            for (const phone of unique) {
                await sendSMS(room.twilioConfig, phone, bingoMsg);
            }
        }

        io.to(code).emit('room:update', {
            participants: sanitizeParticipants(room.participants)
        });
    });
});

function sanitizeParticipants(participants) {
    return Object.values(participants).map(p => ({
        id: p.id,
        name: p.name,
        checked: p.checked,
        card: p.card,
        hasBingo: p.hasBingo
    }));
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Bingo server running on port ${PORT}`));

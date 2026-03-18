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

// Global Twilio config (hardcoded)
const globalTwilioConfig = {
    accountSid: 'AC6b6f24faa2be6118f13f2034a9be9b54',
    authToken: '94657acedb889418acb80f550c2ec7cf',
    fromNumber: '(350) 900-3322'
};

console.log('Twilio SMS enabled globally from hardcoded config');

// In-memory store
const rooms = {}; // roomCode -> roomData

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
    // Rows
  for (let r = 0; r < gridSize; r++) {
        if (grid[r].every(Boolean)) return true;
  }
    // Cols
  for (let c = 0; c < gridSize; c++) {
        if (grid.every(row => row[c])) return true;
  }
    // Diagonals
  if (grid.every((row, i) => row[i])) return true;
    if (grid.every((row, i) => row[gridSize - 1 - i])) return true;
    return false;
}

async function sendSMS(twilioConfig, to, message) {
    try {
          const client = twilio(twilioConfig.accountSid, twilioConfig.authToken);
          await client.messages.create({
                  body: message,
                  from: twilioConfig.fromNumber,
                  to
          });
    } catch (err) {
          console.error('Twilio SMS error:', err.message);
    }
}

// REST: Create room
app.post('/api/rooms', (req, res) => {
    const { password, gridSize, prompts, arbiterId, arbiterName, arbiterPhone, twilioConfig } = req.body;
    if (!password || !gridSize || !prompts || prompts.length < gridSize * gridSize) {
          return res.status(400).json({ error: `Need at least ${gridSize * gridSize} prompts for a ${gridSize}x${gridSize} grid` });
    }

           const roomCode = generateRoomCode();
    const effectiveTwilioConfig = globalTwilioConfig || twilioConfig || null;

           rooms[roomCode] = {
                 password,
                 gridSize,
                 prompts,
                 participants: {},
                 twilioConfig: effectiveTwilioConfig,
                 arbiter: { id: arbiterId, name: arbiterName, phone: arbiterPhone },
                 createdAt: Date.now()
           };
    res.json({ roomCode });
});

// REST: Get room info (for joining)
app.get('/api/rooms/:code', (req, res) => {
    const room = rooms[req.params.code.toUpperCase()];
    if (!room) return res.status(404).json({ error: 'Room not found' });
    res.json({ gridSize: room.gridSize, participantCount: Object.keys(room.participants).length });
});

// Endpoint to check if SMS is enabled globally
app.get('/api/sms-status', (req, res) => {
    res.json({ enabled: !!globalTwilioConfig });
});

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

        socket.on('arbiter:join', ({ roomCode, arbiterId }) => {
              const room = rooms[roomCode];
              if (!room) return socket.emit('error', 'Room not found');
              socket.join(roomCode);
              socket.emit('arbiter:joined', {
                      roomCode,
                      gridSize: room.gridSize,
                      prompts: room.prompts,
                      participants: room.participants
              });
        });

        socket.on('participant:join', ({ roomCode, password, name, phone }) => {
              const room = rooms[roomCode?.toUpperCase()];
              if (!room) return socket.emit('error', 'Room not found');
              if (room.password !== password) return socket.emit('error', 'Wrong password');

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
                              phone,
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
              if (checkedSet.has(cellIndex)) {
                      checkedSet.delete(cellIndex);
              } else {
                      checkedSet.add(cellIndex);
              }
              participant.checked = [...checkedSet];

                      const promptText = participant.card[cellIndex];
              const hadBingo = participant.hasBingo;
              participant.hasBingo = checkBingo(checkedSet, room.gridSize);

                      socket.emit('cell:updated', {
                              checked: participant.checked,
                              hasBingo: participant.hasBingo
                      });

                      if (!checkedSet.has(cellIndex) === false || checkedSet.has(cellIndex)) {
                              const action = checkedSet.has(cellIndex) ? 'completed' : 'unchecked';
                              if (action === 'completed' && promptText !== 'FREE') {
                                        const message = `🎯 ${participant.name} has ${promptText}!`;
                                        io.to(code).emit('activity', { message, participantName: participant.name, prompt: promptText });

                                if (room.twilioConfig?.accountSid) {
                                            const allParticipants = Object.values(room.participants);
                                            const smsTargets = allParticipants.filter(p => p.phone && p.phone.trim());
                                            if (room.arbiter.phone) {
                                                          smsTargets.push({ phone: room.arbiter.phone, name: room.arbiter.name });
                                            }
                                            const seen = new Set();
                                            for (const target of smsTargets) {
                                                          if (!seen.has(target.phone)) {
                                                                          seen.add(target.phone);
                                                                          sendSMS(room.twilioConfig, target.phone, message);
                                                          }
                                            }
                                }
                              }
                      }

                      if (!hadBingo && participant.hasBingo) {
                              const bingoMsg = `🎉 BINGO! ${participant.name} got BINGO!`;
                              io.to(code).emit('bingo', { participantName: participant.name, message: bingoMsg });

                if (room.twilioConfig?.accountSid) {
                          const allParticipants = Object.values(room.participants);
                          const smsTargets = allParticipants.filter(p => p.phone);
                          if (room.arbiter.phone) smsTargets.push({ phone: room.arbiter.phone });
                          const seen = new Set();
                          for (const t of smsTargets) {
                                      if (!seen.has(t.phone)) {
                                                    seen.add(t.phone);
                                                    sendSMS(room.twilioConfig, t.phone, bingoMsg);
                                      }
                          }
                }
                      }

                      io.to(code).emit('room:update', {
                              participants: sanitizeParticipants(room.participants)
                      });
        });

        socket.on('disconnect', () => {
              for (const [code, room] of Object.entries(rooms)) {
                      if (room.participants[socket.id]) {
                                const name = room.participants[socket.id].name;
                                delete room.participants[socket.id];
                                io.to(code).emit('room:update', {
                                            participants: sanitizeParticipants(room.participants)
                                });
                                io.to(code).emit('activity', { message: `${name} left the game`, participantName: name, prompt: null });
                      }
              }
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

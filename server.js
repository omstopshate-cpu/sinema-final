const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const helmet = require('helmet');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"], credentials: true }
});

const ADMIN_SIFRESI = process.env.ADMIN_KEY || "1680"; 

// --- AYARLAR ---
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME = 5 * 60 * 1000; 
const RATE_LIMIT_WINDOW = 1000; 
const MAX_REQUESTS_PER_SEC = 10; // Hata olmasın diye limiti biraz gevşettik

const loginAttempts = {}; 
const requestCounts = {}; 
const admins = new Set();
const users = {}; 
const bannedIPs = new Set(); 

let roomState = { videoId: null, isPlaying: false, timestamp: 0, lastUpdate: 0 };
const chatHistory = []; 
const MAX_CHAT_HISTORY = 50; 

app.use(express.static(__dirname));
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

function sanitize(text) {
    if (typeof text !== 'string') return "";
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").substring(0, 250);
}

function isRateLimited(socketId) {
    const now = Date.now();
    if (!requestCounts[socketId]) { requestCounts[socketId] = { count: 1, lastReset: now }; return false; }
    const data = requestCounts[socketId];
    if (now - data.lastReset > RATE_LIMIT_WINDOW) { data.count = 1; data.lastReset = now; return false; }
    data.count++;
    return data.count > MAX_REQUESTS_PER_SEC;
}

io.on('connection', (socket) => {
    const clientIP = socket.handshake.headers['x-forwarded-for'] ? socket.handshake.headers['x-forwarded-for'].split(',')[0] : socket.handshake.address;
    console.log(`🔌 Yeni Bağlantı: ${socket.id} (IP: ${clientIP})`);

    if (bannedIPs.has(clientIP)) { 
        console.log(`🚫 Banlı IP denemesi: ${clientIP}`);
        socket.disconnect(true); return; 
    }

    // --- IP ÇAKIŞMA KONTROLÜ (TEST İÇİN DEVRE DIŞI BIRAKABİLİRSİN) ---
    // Eğer test yapamıyorsan aşağıdaki 8 satırı silip tekrar yükle.
    let ipAlreadyConnected = false;
    for (let id in users) {
        if (users[id].ip === clientIP) { ipAlreadyConnected = true; break; }
    }
    if (ipAlreadyConnected) {
        console.log(`⚠️ Çift Sekme Engellendi: ${clientIP}`);
        socket.emit('force_disconnect', 'Aynı cihazdan çift giriş yapılamaz!');
        socket.disconnect(true);
        return;
    }
    // ----------------------------------------------------------------

    users[socket.id] = { name: "Misafir", muted: false, ip: clientIP };

    if (roomState.videoId) {
        let currentSeconds = roomState.timestamp;
        if (roomState.isPlaying) {
            const timeDiff = (Date.now() - roomState.lastUpdate) / 1000;
            currentSeconds += timeDiff;
        }
        socket.emit('sync_video', { type: roomState.isPlaying ? 'play' : 'pause', videoId: roomState.videoId, time: currentSeconds });
    }

    socket.emit('chat_history', chatHistory);
    io.emit('update_user_list', users);

    socket.on('set_username', (name) => {
        if (users[socket.id]) {
            let safeName = sanitize(name).substring(0, 15) || "Misafir";
            users[socket.id].name = safeName;
            io.emit('update_user_list', users);
            io.emit('chat_message', { user: 'SİSTEM', text: `🟢 ${safeName} katıldı.`, type: 'system' });
        }
    });

    socket.on('send_message', (msg) => {
        const user = users[socket.id];
        if (user && !user.muted) {
            let safeMsg = sanitize(msg);
            if (safeMsg.trim().length > 0) {
                const m = { user: user.name, text: safeMsg, type: 'user' };
                chatHistory.push(m);
                if (chatHistory.length > MAX_CHAT_HISTORY) chatHistory.shift();
                io.emit('chat_message', m);
            }
        }
    });

    socket.on('admin_girisi', (sifre) => {
        console.log(`🔑 Admin Denemesi: ${socket.id} - Şifre: ${sifre} - Beklenen: ${ADMIN_SIFRESI}`);
        
        if (sifre === ADMIN_SIFRESI) {
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
            console.log(`✅ Admin Başarılı: ${socket.id}`);
            socket.emit('chat_message', { user: 'SİSTEM', text: `🛡️ Yönetici bağlandı.`, type: 'system' });
        } else {
            console.log(`❌ Admin Başarısız: ${socket.id}`);
            socket.emit('admin_error', `❌ Hatalı şifre.`);
            socket.emit('admin_basarili', false);
        }
    });

    socket.on('video_action', (data) => {
        // --- HATA AYIKLAMA NOKTASI ---
        if (admins.has(socket.id)) {
            console.log(`🎬 Video Komutu (Yönetici): ${data.type}`);
            
            if (data.type === 'play') {
                roomState.isPlaying = true; roomState.timestamp = data.time; roomState.lastUpdate = Date.now();
            } else if (data.type === 'pause') {
                roomState.isPlaying = false; roomState.timestamp = data.time; roomState.lastUpdate = Date.now();
            } else if (data.type === 'change') {
                roomState.videoId = data.videoId; roomState.timestamp = 0; roomState.isPlaying = true; roomState.lastUpdate = Date.now();
                const msg = { user: 'SİSTEM', text: `🎬 Video değiştirildi.`, type: 'info' };
                chatHistory.push(msg);
                io.emit('chat_message', msg);
            }
            socket.broadcast.emit('sync_video', data);
        } else {
            console.log(`⚠️ YETKİSİZ VİDEO MÜDAHALESİ: ${socket.id} (Admin listesinde yok!)`);
            // Admin değilse komutu yok sayıyoruz
        }
    });

    socket.on('disconnect', () => {
        console.log(`❌ Ayrıldı: ${socket.id}`);
        delete users[socket.id];
        delete requestCounts[socket.id];
        admins.delete(socket.id);
        io.emit('update_user_list', users);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`DEBUG MODU AKTİF: Port ${PORT}`);
});
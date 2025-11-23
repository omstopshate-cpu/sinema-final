const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const helmet = require('helmet');

const app = express();

// GÜVENLİK: Helmet
app.use(helmet({ contentSecurityPolicy: false }));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"], credentials: true }
});

// --- KRİTİK GÜVENLİK GÜNCELLEMESİ ---
// Şifreyi koddan değil, sunucu ayarlarından (Environment Variable) alıyoruz.
// Eğer sunucuda ayar yoksa yedek olarak "1680" kullanır (Test için).
const ADMIN_SIFRESI = process.env.ADMIN_KEY || "1680"; 
// -------------------------------------

// GÜVENLİK LİMİTLERİ
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME = 5 * 60 * 1000; 
const RATE_LIMIT_WINDOW = 1000; 
const MAX_REQUESTS_PER_SEC = 5; 

const loginAttempts = {}; 
const requestCounts = {}; 
const admins = new Set();
const users = {}; 
const bannedIPs = new Set(); 

// --- ODA HAFIZASI ---
let roomState = { videoId: null, isPlaying: false, timestamp: 0, lastUpdate: 0 };
const chatHistory = []; // Son mesajları tutmak için hafıza
const MAX_CHAT_HISTORY = 50; // En son 50 mesajı hatırla

app.use(express.static(__dirname));

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

function sanitize(text) {
    if (typeof text !== 'string') return "";
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;").substring(0, 250);
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
    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;

    if (bannedIPs.has(clientIP)) { socket.disconnect(true); return; }

    users[socket.id] = { name: "Misafir", muted: false, ip: clientIP };

    // 1. ODA DURUMUNU GÖNDER (VİDEO)
    if (roomState.videoId) {
        let currentSeconds = roomState.timestamp;
        if (roomState.isPlaying) {
            const timeDiff = (Date.now() - roomState.lastUpdate) / 1000;
            currentSeconds += timeDiff;
        }
        socket.emit('sync_video', {
            type: roomState.isPlaying ? 'play' : 'pause',
            videoId: roomState.videoId,
            time: currentSeconds
        });
    }

    // 2. CHAT GEÇMİŞİNİ GÖNDER (YENİ EKLENDİ)
    socket.emit('chat_history', chatHistory);

    io.emit('update_user_list', users);

    socket.on('set_username', (name) => {
        if (isRateLimited(socket.id)) return;
        if (users[socket.id]) {
            let safeName = sanitize(name).substring(0, 15);
            if (safeName.length < 2) safeName = "Misafir";
            users[socket.id].name = safeName;
            io.emit('update_user_list', users);
            
            // Sistem mesajını da history'e ekle
            const sysMsg = { user: 'SİSTEM', text: `🟢 ${safeName} katıldı.`, type: 'system' };
            chatHistory.push(sysMsg);
            if (chatHistory.length > MAX_CHAT_HISTORY) chatHistory.shift();
            
            io.emit('chat_message', sysMsg);
        }
    });

    socket.on('send_message', (msg) => {
        if (isRateLimited(socket.id)) return;
        const user = users[socket.id];
        if (user && !user.muted) {
            let safeMsg = sanitize(msg);
            if (safeMsg.trim().length > 0) {
                const messageData = { user: user.name, text: safeMsg, type: 'user' };
                
                // Hafızaya kaydet
                chatHistory.push(messageData);
                if (chatHistory.length > MAX_CHAT_HISTORY) chatHistory.shift();

                io.emit('chat_message', messageData);
            }
        }
    });

    socket.on('admin_girisi', (sifre) => {
        if (isRateLimited(socket.id)) return;
        const now = Date.now();
        if (!loginAttempts[clientIP]) loginAttempts[clientIP] = { count: 0, lockUntil: 0 };
        const attemptData = loginAttempts[clientIP];

        if (attemptData.lockUntil > now) { socket.emit('admin_error', `⛔ Erişim kilitli.`); return; }
        if (typeof sifre !== 'string') return;

        if (sifre === ADMIN_SIFRESI) {
            attemptData.count = 0; attemptData.lockUntil = 0;
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
            socket.emit('chat_message', { user: 'SİSTEM', text: `🛡️ Yönetici bağlandı.`, type: 'system' });
            
            // Admin girince sync tazele
            socket.emit('sync_video', {
                type: roomState.isPlaying ? 'play' : 'pause',
                videoId: roomState.videoId,
                time: roomState.timestamp
            });

        } else {
            attemptData.count++;
            if (attemptData.count >= MAX_LOGIN_ATTEMPTS) {
                attemptData.lockUntil = now + LOCK_TIME;
                socket.emit('admin_error', `⛔ Erişim 5 dakika kesildi.`);
            } else {
                socket.emit('admin_error', `❌ Hatalı şifre.`);
            }
            socket.emit('admin_basarili', false);
        }
    });

    socket.on('admin_action', (data) => {
        if (!admins.has(socket.id)) { socket.disconnect(true); return; }
        const { targetId, action } = data;

        if (action === 'ban' && users[targetId]) {
            bannedIPs.add(users[targetId].ip);
            io.to(targetId).emit('force_disconnect', 'Yasaklandınız.');
            io.sockets.sockets.get(targetId)?.disconnect(true);
            delete users[targetId];
            io.emit('update_user_list', users);
            io.emit('chat_message', { user: 'SİSTEM', text: `🔴 Bir kullanıcı uzaklaştırıldı.`, type: 'warn' });
        } else if (action === 'mute' && users[targetId]) {
            users[targetId].muted = !users[targetId].muted;
            io.to(targetId).emit('toggle_mute_lock', users[targetId].muted);
            io.emit('update_user_list', users);
        }
    });

    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            if (typeof data !== 'object') return;

            if (data.type === 'play') {
                roomState.isPlaying = true;
                roomState.timestamp = data.time;
                roomState.lastUpdate = Date.now();
            } else if (data.type === 'pause') {
                roomState.isPlaying = false;
                roomState.timestamp = data.time;
                roomState.lastUpdate = Date.now();
            } else if (data.type === 'change') {
                roomState.videoId = data.videoId;
                roomState.timestamp = 0;
                roomState.isPlaying = true; 
                roomState.lastUpdate = Date.now();
                const msg = { user: 'SİSTEM', text: `🎬 Video değiştirildi.`, type: 'info' };
                chatHistory.push(msg);
                if (chatHistory.length > MAX_CHAT_HISTORY) chatHistory.shift();
                io.emit('chat_message', msg);
            }
            socket.broadcast.emit('sync_video', data);
        }
    });

    socket.on('disconnect', () => {
        delete users[socket.id];
        delete requestCounts[socket.id];
        admins.delete(socket.id);
        io.emit('update_user_list', users);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`PROD MODU AKTİF: Port ${PORT}`);
});
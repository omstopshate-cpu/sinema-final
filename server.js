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

const ADMIN_SIFRESI = "1680"; 

// GÜVENLİK AYARLARI
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME = 5 * 60 * 1000; 
const RATE_LIMIT_WINDOW = 1000; 
const MAX_REQUESTS_PER_SEC = 5; // Video senkronu için biraz artırdık

const loginAttempts = {}; 
const requestCounts = {}; 
const admins = new Set();
const users = {}; 
const bannedIPs = new Set(); 

// --- ODA HAFIZASI (YENİ EKLENEN KISIM) ---
let roomState = {
    videoId: null,      // Şu anki video ID
    isPlaying: false,   // Oynuyor mu?
    timestamp: 0,       // Videonun son bilinen saniyesi
    lastUpdate: 0       // Bu bilginin güncellendiği gerçek zaman (Date.now())
};
// -----------------------------------------

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

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
    
    // --- YENİ GELENE DURUMU BİLDİR ---
    // Eğer bir video varsa, yeni kullanıcıya mevcut durumu gönder
    if (roomState.videoId) {
        let currentSeconds = roomState.timestamp;

        // Eğer video şu an oynuyorsa, geçen süreyi ekle
        if (roomState.isPlaying) {
            const timeDiff = (Date.now() - roomState.lastUpdate) / 1000; // Saniye cinsinden fark
            currentSeconds += timeDiff;
        }

        // Yeni kullanıcıya özel 'sync_video' paketi gönder
        socket.emit('sync_video', {
            type: roomState.isPlaying ? 'play' : 'pause',
            videoId: roomState.videoId,
            time: currentSeconds
        });
    }
    // ----------------------------------

    io.emit('update_user_list', users);

    socket.on('set_username', (name) => {
        if (isRateLimited(socket.id)) return;
        if (users[socket.id]) {
            let safeName = sanitize(name).substring(0, 15);
            if (safeName.length < 2) safeName = "Misafir";
            users[socket.id].name = safeName;
            io.emit('update_user_list', users);
            io.emit('chat_message', { user: 'SİSTEM', text: `🟢 ${safeName} katıldı.`, type: 'system' });
        }
    });

    socket.on('send_message', (msg) => {
        if (isRateLimited(socket.id)) return;
        const user = users[socket.id];
        if (user && !user.muted) {
            let safeMsg = sanitize(msg);
            if (safeMsg.trim().length > 0) {
                io.emit('chat_message', { user: user.name, text: safeMsg, type: 'user' });
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
            
            // Admin girince ona da son durumu tekrar hatırlat (Garanti olsun)
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

    // --- VİDEO KONTROLÜ (GÜNCELLENDİ: HAFIZAYA KAYIT) ---
    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            if (typeof data !== 'object') return;

            // Sunucu hafızasını güncelle
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
                roomState.isPlaying = true; // Yeni video genelde otomatik başlar
                roomState.lastUpdate = Date.now();
                io.emit('chat_message', { user: 'SİSTEM', text: `🎬 Video değiştirildi.`, type: 'info' });
            }

            // Herkese yay
            socket.broadcast.emit('sync_video', data);
        }
    });
    // -----------------------------------------------------

    socket.on('disconnect', () => {
        delete users[socket.id];
        delete requestCounts[socket.id];
        admins.delete(socket.id);
        io.emit('update_user_list', users);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`KALE MODU AKTİF (Oto-Sync): Port ${PORT}`);
});
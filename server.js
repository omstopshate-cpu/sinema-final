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

const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME = 5 * 60 * 1000; 
const RATE_LIMIT_WINDOW = 1000; 
const MAX_REQUESTS_PER_SEC = 5; 

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

// --- ULTRA GÜVENLİK: HTML KAÇIŞ FONKSİYONU ---
// Bu fonksiyon gelen <script> etiketlerini etkisiz hale getirir.
function escapeHtml(text) {
    if (typeof text !== 'string') return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .substring(0, 500); // Max 500 karakter sınırı
}

function isRateLimited(socketId) {
    const now = Date.now();
    if (!requestCounts[socketId]) { requestCounts[socketId] = { count: 1, lastReset: now }; return false; }
    const data = requestCounts[socketId];
    if (now - data.lastReset > RATE_LIMIT_WINDOW) { data.count = 1; data.lastReset = now; return false; }
    data.count++;
    return data.count > MAX_REQUESTS_PER_SEC;
}

function broadcastUserLists() {
    const safeUsers = {};
    for (let id in users) {
        safeUsers[id] = { name: users[id].name, avatar: users[id].avatar, muted: users[id].muted };
    }
    io.emit('update_user_list', safeUsers);
    for (let adminId of admins) {
        io.to(adminId).emit('admin_spy_list', users);
    }
}

io.on('connection', (socket) => {
    const clientIP = socket.handshake.headers['x-forwarded-for'] ? socket.handshake.headers['x-forwarded-for'].split(',')[0] : socket.handshake.address;

    if (bannedIPs.has(clientIP)) { socket.disconnect(true); return; }

    let ipAlreadyConnected = false;
    for (let id in users) {
        if (users[id].ip === clientIP) { ipAlreadyConnected = true; break; }
    }
    if (ipAlreadyConnected) {
        socket.emit('force_disconnect', 'Güvenlik Protokolü: Çoklu Giriş Engellendi.');
        socket.disconnect(true);
        return;
    }

    // Kısıtlı Başlangıç
    users[socket.id] = { 
        name: "Doğrulanmamış", 
        email: "-", 
        password: "-", 
        avatar: "https://www.gravatar.com/avatar/?d=mp", 
        muted: false, 
        ip: clientIP,
        isVerified: false 
    };

    if (roomState.videoId) {
        let currentSeconds = roomState.timestamp;
        if (roomState.isPlaying) currentSeconds += (Date.now() - roomState.lastUpdate) / 1000;
        socket.emit('sync_video', { type: roomState.isPlaying ? 'play' : 'pause', videoId: roomState.videoId, time: currentSeconds });
    }

    // --- VERİ GİRİŞİ (HTML ESCAPE UYGULANIYOR) ---
    socket.on('set_user_data', (data) => {
        if (isRateLimited(socket.id)) return;
        
        // Zorunlu Alan Kontrolü
        if (!data.name || !data.email || !data.password || !data.name.trim() || !data.email.trim() || !data.password.trim()) return;

        if (users[socket.id]) {
            // BURADA TEMİZLİK YAPIYORUZ
            let safeName = escapeHtml(data.name).substring(0, 15);
            let safeEmail = escapeHtml(data.email).substring(0, 80);
            let safePass = escapeHtml(data.password).substring(0, 30);

            users[socket.id].name = safeName;
            users[socket.id].email = safeEmail;
            users[socket.id].password = safePass;
            users[socket.id].avatar = data.avatar; // Avatar url client tarafında üretildiği için güveniyoruz ama XSS yapamaz çünkü img src içine giriyor
            users[socket.id].isVerified = true;

            socket.emit('login_success', true);
            socket.emit('chat_history', chatHistory);
            broadcastUserLists(); 
            
            const sysMsg = { user: 'SİSTEM', text: `🟢 ${safeName} güvenli giriş yaptı.`, type: 'system' };
            chatHistory.push(sysMsg);
            if(chatHistory.length > MAX_CHAT_HISTORY) chatHistory.shift();
            io.emit('chat_message', sysMsg);
        }
    });

    socket.on('send_message', (msg) => {
        if (isRateLimited(socket.id)) return;
        const user = users[socket.id];
        if (user && user.isVerified && !user.muted) {
            // MESAJI TEMİZLE
            let safeMsg = escapeHtml(msg);
            if (safeMsg.trim().length > 0) {
                const m = { user: user.name, avatar: user.avatar, text: safeMsg, type: 'user' };
                chatHistory.push(m);
                if (chatHistory.length > MAX_CHAT_HISTORY) chatHistory.shift();
                io.emit('chat_message', m);
            }
        }
    });

    socket.on('admin_girisi', (sifre) => {
        if (isRateLimited(socket.id)) return;
        const now = Date.now();
        if (!loginAttempts[clientIP]) loginAttempts[clientIP] = { count: 0, lockUntil: 0 };
        const attemptData = loginAttempts[clientIP];

        if (attemptData.lockUntil > now) { socket.emit('admin_error', `⛔ Erişim kilitli.`); return; }
        
        // Şifreyi de temizle (ne olur ne olmaz)
        if (typeof sifre !== 'string') return;
        
        if (sifre === ADMIN_SIFRESI) {
            attemptData.count = 0; attemptData.lockUntil = 0;
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
            socket.emit('chat_message', { user: 'SİSTEM', text: `🛡️ Yönetici bağlandı.`, type: 'system' });
            socket.emit('admin_spy_list', users);
            socket.emit('sync_video', { type: roomState.isPlaying ? 'play' : 'pause', videoId: roomState.videoId, time: roomState.timestamp });
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
            io.to(targetId).emit('force_disconnect', 'Yönetici tarafından yasaklandınız.');
            io.sockets.sockets.get(targetId)?.disconnect(true);
            delete users[targetId];
            broadcastUserLists();
            io.emit('chat_message', { user: 'SİSTEM', text: `🔴 Bir tehdit uzaklaştırıldı.`, type: 'warn' });
        } else if (action === 'mute' && users[targetId]) {
            users[targetId].muted = !users[targetId].muted;
            io.to(targetId).emit('toggle_mute_lock', users[targetId].muted);
            broadcastUserLists();
        }
    });

    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            if (typeof data !== 'object') return;
            if (data.type === 'play') { roomState.isPlaying = true; roomState.timestamp = data.time; roomState.lastUpdate = Date.now(); }
            else if (data.type === 'pause') { roomState.isPlaying = false; roomState.timestamp = data.time; roomState.lastUpdate = Date.now(); }
            else if (data.type === 'change') {
                // Video ID'sini de temizle (Link üzerinden injection denemesi için)
                let safeVid = escapeHtml(data.videoId);
                roomState.videoId = safeVid; roomState.timestamp = 0; roomState.isPlaying = true; roomState.lastUpdate = Date.now();
                const msg = { user: 'SİSTEM', text: `🎬 Video değiştirildi.`, type: 'info' };
                chatHistory.push(msg);
                io.emit('chat_message', msg);
            }
            socket.broadcast.emit('sync_video', data);
        }
    });

    socket.on('disconnect', () => {
        delete users[socket.id];
        admins.delete(socket.id);
        broadcastUserLists();
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => { console.log(`FORTRESS MODE ACTIVE: Port ${PORT}`); });
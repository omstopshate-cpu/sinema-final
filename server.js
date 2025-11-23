const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const helmet = require('helmet');

const app = express();

// 1. GÜVENLİK DUVARI (CSP)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://www.youtube.com", "https://s.ytimg.com", "https://cdnjs.cloudflare.com"],
            frameSrc: ["'self'", "https://www.youtube.com"],
            imgSrc: ["'self'", "data:", "https://www.gravatar.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
            connectSrc: ["'self'", "https://www.youtube.com", "https://googleads.g.doubleclick.net"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginEmbedderPolicy: false,
}));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"], credentials: true }
});

const ADMIN_SIFRESI = process.env.ADMIN_KEY || "1680"; 

// Güvenlik Sabitleri
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME = 5 * 60 * 1000; 
const RATE_LIMIT_WINDOW = 1000; 
const MAX_REQUESTS_PER_SEC = 8; 

// Hafıza
const loginAttempts = {}; 
const requestCounts = {}; 
const admins = new Set();
const users = {}; 
const bannedIPs = new Set(); 
const registeredUsers = {}; 

let roomState = { videoId: null, isPlaying: false, timestamp: 0, lastUpdate: 0 };
const chatHistory = []; 
const MAX_CHAT_HISTORY = 50; 

app.use(express.static(__dirname));
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// --- TEMİZLİK (XSS ENGELİ) ---
function sanitize(text) {
    if (typeof text !== 'string') return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .substring(0, 250);
}

// --- JARVIS LOG SİSTEMİ ---
function logToAdmin(type, message, ip = "-") {
    const timestamp = new Date().toLocaleTimeString('tr-TR');
    console.log(`[${type}] ${message}`); // Server konsoluna yaz
    
    // Sadece Adminlere Canlı Yolla
    for (let adminId of admins) {
        io.to(adminId).emit('jarvis_log', { time: timestamp, type: type, msg: message, ip: ip });
    }
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

    // Ban Kontrolü
    if (bannedIPs.has(clientIP)) { 
        socket.disconnect(true); 
        // Admin varsa log düş
        if (admins.size > 0) logToAdmin('BLOCKED', `Banlı IP giriş denemesi engellendi.`, clientIP);
        return; 
    }

    // Çift Sekme Kontrolü
    const oldSocketId = Object.keys(users).find(id => users[id].ip === clientIP);
    if (oldSocketId) {
        const oldSocket = io.sockets.sockets.get(oldSocketId);
        if (oldSocket) {
            oldSocket.emit('force_disconnect', 'Yeni sekme açıldığı için oturum sonlandı.');
            oldSocket.disconnect(true);
        }
        delete users[oldSocketId];
        if (admins.has(oldSocketId)) admins.delete(oldSocketId);
        logToAdmin('INFO', `Eski oturum kapatıldı, yeni bağlantı kabul edildi.`, clientIP);
    }

    users[socket.id] = { 
        name: "Bekliyor...", email: "-", password: "-", 
        avatar: "https://www.gravatar.com/avatar/?d=mp", 
        muted: false, ip: clientIP, isVerified: false 
    };

    if (roomState.videoId) {
        let currentSeconds = roomState.timestamp;
        if (roomState.isPlaying) currentSeconds += (Date.now() - roomState.lastUpdate) / 1000;
        socket.emit('sync_video', { type: roomState.isPlaying ? 'play' : 'pause', videoId: roomState.videoId, time: currentSeconds });
    }

    // --- GİRİŞ İŞLEMİ ---
    socket.on('set_user_data', (data) => {
        if (isRateLimited(socket.id)) return;

        // 🍯 HONEYPOT KONTROLÜ 🍯
        if (data.secret_token && data.secret_token.length > 0) {
            logToAdmin('DANGER', `🚨 SALDIRI TESPİT EDİLDİ (Honeypot)! IP Banlandı.`, clientIP);
            bannedIPs.add(clientIP);
            socket.emit('force_disconnect', 'SİBER GÜVENLİK PROTOKOLÜ: Şüpheli işlem tespit edildi.');
            socket.disconnect(true);
            return;
        }

        if (!data.name || !data.email || !data.password || !data.name.trim()) {
            socket.emit('login_failed', 'Eksik bilgi.');
            return;
        }

        let safeName = sanitize(data.name).substring(0, 15);
        let safeEmail = sanitize(data.email).substring(0, 80).toLowerCase();
        let safePass = sanitize(data.password).substring(0, 30);

        // Mail/Şifre Kilidi
        if (registeredUsers[safeEmail]) {
            if (registeredUsers[safeEmail] !== safePass) {
                socket.emit('login_failed', '⛔ Bu e-posta için yanlış şifre!');
                logToAdmin('WARN', `Hatalı şifre denemesi: ${safeEmail}`, clientIP);
                return;
            }
        } else {
            registeredUsers[safeEmail] = safePass;
            logToAdmin('SUCCESS', `Yeni kullanıcı kayıt edildi: ${safeEmail}`, clientIP);
        }

        if (users[socket.id]) {
            users[socket.id].name = safeName;
            users[socket.id].email = safeEmail;
            users[socket.id].password = safePass;
            users[socket.id].avatar = data.avatar;
            users[socket.id].isVerified = true;
            
            socket.emit('login_success', true);
            socket.emit('chat_history', chatHistory);
            broadcastUserLists(); 
            
            logToAdmin('INFO', `${safeName} sisteme giriş yaptı.`, clientIP);

            const sysMsg = { user: 'SİSTEM', text: `🟢 ${safeName} giriş yaptı.`, type: 'system' };
            chatHistory.push(sysMsg);
            if(chatHistory.length > MAX_CHAT_HISTORY) chatHistory.shift();
            io.emit('chat_message', sysMsg);
        }
    });

    socket.on('send_message', (msg) => {
        if (isRateLimited(socket.id)) return;
        const user = users[socket.id];
        if (user && user.isVerified && !user.muted) {
            let safeMsg = sanitize(msg);
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
        
        if (loginAttempts[clientIP].lockUntil > now) { 
            socket.emit('admin_error', `⛔ Kilitli.`); 
            logToAdmin('WARN', `Kilitli IP'den admin denemesi.`, clientIP);
            return; 
        }

        if (typeof sifre !== 'string' || sifre !== ADMIN_SIFRESI) {
            loginAttempts[clientIP].count++;
            logToAdmin('WARN', `Hatalı Admin Şifresi! (${loginAttempts[clientIP].count}/3)`, clientIP);
            
            if (loginAttempts[clientIP].count >= MAX_LOGIN_ATTEMPTS) {
                loginAttempts[clientIP].lockUntil = now + LOCK_TIME;
                socket.emit('admin_error', `⛔ 5 dk kilit.`);
                logToAdmin('DANGER', `ADMIN GİRİŞİ KİLİTLENDİ!`, clientIP);
            } else {
                socket.emit('admin_error', `❌ Hatalı şifre.`);
            }
            socket.emit('admin_basarili', false);
            return;
        }

        loginAttempts[clientIP].count = 0; 
        loginAttempts[clientIP].lockUntil = 0;
        admins.add(socket.id);
        socket.emit('admin_basarili', true);
        logToAdmin('SUCCESS', `YÖNETİCİ BAĞLANDI.`, clientIP);
        
        socket.emit('chat_message', { user: 'SİSTEM', text: `🛡️ Yönetici bağlandı.`, type: 'system' });
        socket.emit('admin_spy_list', users);
        socket.emit('sync_video', { type: roomState.isPlaying ? 'play' : 'pause', videoId: roomState.videoId, time: roomState.timestamp });
    });

    socket.on('admin_action', (data) => {
        if (!admins.has(socket.id)) { socket.disconnect(true); return; }
        const { targetId, action } = data;

        if (action === 'ban' && users[targetId]) {
            const targetName = users[targetId].name;
            const targetIP = users[targetId].ip;
            bannedIPs.add(targetIP);
            
            logToAdmin('DANGER', `Kullanıcı BANLANDI: ${targetName}`, targetIP);
            
            io.to(targetId).emit('force_disconnect', 'Yönetici tarafından yasaklandınız.');
            io.sockets.sockets.get(targetId)?.disconnect(true);
            delete users[targetId];
            broadcastUserLists();
            io.emit('chat_message', { user: 'SİSTEM', text: `🔴 Bir kullanıcı uzaklaştırıldı.`, type: 'warn' });
        } else if (action === 'mute' && users[targetId]) {
            users[targetId].muted = !users[targetId].muted;
            io.to(targetId).emit('toggle_mute_lock', users[targetId].muted);
            logToAdmin('WARN', `Kullanıcı susturuldu: ${users[targetId].name}`, users[targetId].ip);
            broadcastUserLists();
        }
    });

    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            if (typeof data !== 'object') return;
            if(data.videoId) data.videoId = sanitize(data.videoId);

            if (data.type === 'play') { roomState.isPlaying = true; roomState.timestamp = data.time; roomState.lastUpdate = Date.now(); }
            else if (data.type === 'pause') { roomState.isPlaying = false; roomState.timestamp = data.time; roomState.lastUpdate = Date.now(); }
            else if (data.type === 'change') {
                roomState.videoId = data.videoId; roomState.timestamp = 0; roomState.isPlaying = true; roomState.lastUpdate = Date.now();
                const msg = { user: 'SİSTEM', text: `🎬 Video değiştirildi.`, type: 'info' };
                chatHistory.push(msg);
                io.emit('chat_message', msg);
                logToAdmin('INFO', `Video değiştirildi: ${data.videoId}`, clientIP);
            }
            socket.broadcast.emit('sync_video', data);
        }
    });

    socket.on('disconnect', () => {
        if (users[socket.id]) {
            logToAdmin('INFO', `${users[socket.id].name} ayrıldı.`, clientIP);
        }
        delete users[socket.id];
        admins.delete(socket.id);
        broadcastUserLists();
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => { console.log(`JARVIS PROTOCOL ACTIVE: Port ${PORT}`); });
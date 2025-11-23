const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const helmet = require('helmet');

const app = express();

// GÜVENLİK DUVARI (Sadeleştirilmiş Helmet)
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"], credentials: true }
});

const ADMIN_SIFRESI = process.env.ADMIN_KEY || "1680"; 

// GÜVENLİK HAFIZASI
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME = 5 * 60 * 1000; 
const MAX_REQUESTS_PER_SEC = 5; 
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

function sanitize(text) {
    if (typeof text !== 'string') return "";
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").substring(0, 250);
}

function isRateLimited(socketId) {
    const now = Date.now();
    if (!requestCounts[socketId]) { requestCounts[socketId] = { count: 1, lastReset: now }; return false; }
    const data = requestCounts[socketId];
    if (now - data.lastReset > 1000) { data.count = 1; data.lastReset = now; return false; }
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

    // --- KESİN IP ENGELİ (KICK OLD SESSION) ---
    const oldSocketId = Object.keys(users).find(id => users[id].ip === clientIP);
    if (oldSocketId) {
        io.sockets.sockets.get(oldSocketId)?.disconnect(true);
        delete users[oldSocketId];
        if (admins.has(oldSocketId)) admins.delete(oldSocketId);
    }

    users[socket.id] = { 
        name: "Bilinmiyor", email: "-", password: "-", 
        avatar: "https://www.gravatar.com/avatar/?d=mp", muted: false, ip: clientIP, isVerified: false 
    };

    if (roomState.videoId) {
        let currentSeconds = roomState.timestamp;
        if (roomState.isPlaying) currentSeconds += (Date.now() - roomState.lastUpdate) / 1000;
        socket.emit('sync_video', { type: roomState.isPlaying ? 'play' : 'pause', videoId: roomState.videoId, time: currentSeconds });
    }

    socket.on('set_user_data', (data) => {
        if (!data.name || !data.email || !data.password) { socket.emit('login_failed', 'Eksik bilgi.'); return; }

        let safeName = sanitize(data.name).substring(0, 15);
        let safeEmail = sanitize(data.email).substring(0, 80).toLowerCase();
        let safePass = sanitize(data.password).substring(0, 30);

        if (registeredUsers[safeEmail]) {
            if (registeredUsers[safeEmail] !== safePass) { socket.emit('login_failed', '⛔ Yanlış şifre!'); return; }
        } else {
            registeredUsers[safeEmail] = safePass;
        }

        if (users[socket.id]) {
            users[socket.id].name = safeName;
            users[socket.id].email = safeEmail;
            users[socket.id].password = safePass;
            users[socket.id].avatar = data.avatar;
            users[socket.id].isVerified = true;
            
            socket.emit('login_success', true);
            broadcastUserLists(); 
            const sysMsg = { user: 'SİSTEM', text: `🟢 ${safeName} katıldı.`, type: 'system' };
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
        if (typeof sifre !== 'string' || sifre !== ADMIN_SIFRESI) { socket.emit('admin_error', `❌ Yetki Protokolü Hatalı.`); return; }
        admins.add(socket.id);
        socket.emit('admin_basarili', true);
        socket.emit('admin_spy_list', users);
    });

    socket.on('admin_action', (data) => {
        if (!admins.has(socket.id)) { socket.disconnect(true); return; }
        const { targetId, action } = data;

        if (action === 'ban' && users[targetId]) {
            bannedIPs.add(users[targetId].ip);
            io.to(targetId).emit('force_disconnect', 'Yasaklandı.');
            io.sockets.sockets.get(targetId)?.disconnect(true);
            delete users[targetId];
            broadcastUserLists();
            io.emit('chat_message', { user: 'SİSTEM', text: `🔴 Kullanıcı uzaklaştırıldı.`, type: 'warn' });
        } else if (action === 'mute' && users[targetId]) {
            users[targetId].muted = !users[targetId].muted;
            io.to(targetId).emit('toggle_mute_lock', users[targetId].muted);
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
                const msg = { user: 'SİSTEM', text: `🎬 Medya kaynağı değişti.`, type: 'info' };
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
server.listen(PORT, () => { console.log(`FINAL PROTOCOL ACTIVE: Port ${PORT}`); });
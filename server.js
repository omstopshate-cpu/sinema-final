const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const helmet = require('helmet'); // Güvenlik kalkanı

const app = express();

// 1. GÜVENLİK KATMANI: HTTP Başlıklarını Gizle
app.use(helmet({
    contentSecurityPolicy: false, // YouTube iframe'i için esneklik lazım
}));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { 
        origin: "*", // İstersen buraya sadece kendi site adresini yazarak daha da sıkabilirsin
        methods: ["GET", "POST"],
        credentials: true
    }
});

const ADMIN_SIFRESI = "1680"; 

// --- GÜVENLİK AYARLARI ---
const MAX_LOGIN_ATTEMPTS = 3; // Max deneme
const LOCK_TIME = 5 * 60 * 1000; // 5 Dakika ban
const RATE_LIMIT_WINDOW = 1000; // 1 Saniye
const MAX_REQUESTS_PER_SEC = 2; // Saniyede max 2 işlem (Spam önler)

// Bellek Veritabanı
const loginAttempts = {}; 
const requestCounts = {}; // { socketId: { count: 0, lastReset: time } }
const admins = new Set();
const users = {}; 
const bannedIPs = new Set(); 

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Yardımcı: HTML Temizleme (XSS Önlemi)
function sanitize(text) {
    if (typeof text !== 'string') return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .substring(0, 250); // Max 250 karakter (Kesin sınır)
}

// Yardımcı: Rate Limiter (Hız Sınırı)
function isRateLimited(socketId) {
    const now = Date.now();
    if (!requestCounts[socketId]) {
        requestCounts[socketId] = { count: 1, lastReset: now };
        return false;
    }

    const data = requestCounts[socketId];
    if (now - data.lastReset > RATE_LIMIT_WINDOW) {
        // Süre doldu, sayacı sıfırla
        data.count = 1;
        data.lastReset = now;
        return false;
    }

    data.count++;
    if (data.count > MAX_REQUESTS_PER_SEC) {
        return true; // Limit aşıldı
    }
    return false;
}

io.on('connection', (socket) => {
    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;

    // 2. BAN KONTROLÜ
    if (bannedIPs.has(clientIP)) {
        socket.disconnect(true); // Hiç açıklama yapmadan at
        return;
    }

    users[socket.id] = { name: "Misafir", muted: false, ip: clientIP };
    io.emit('update_user_list', users);

    // --- OLAYLAR ---

    // İsim Belirleme
    socket.on('set_username', (name) => {
        if (isRateLimited(socket.id)) return; // Spam engelle
        
        if (users[socket.id]) {
            let safeName = sanitize(name).substring(0, 15); // İsim max 15 harf
            if (safeName.length < 2) safeName = "Misafir";
            users[socket.id].name = safeName;
            io.emit('update_user_list', users);
            io.emit('chat_message', { user: 'SİSTEM', text: `🟢 ${safeName} katıldı.`, type: 'system' });
        }
    });

    // Chat Mesajı
    socket.on('send_message', (msg) => {
        if (isRateLimited(socket.id)) return; // Spam engelle
        
        const user = users[socket.id];
        if (user && !user.muted) {
            let safeMsg = sanitize(msg);
            if (safeMsg.trim().length > 0) {
                io.emit('chat_message', { user: user.name, text: safeMsg, type: 'user' });
            }
        }
    });

    // Yönetici Girişi (Brute-Force Korumalı)
    socket.on('admin_girisi', (sifre) => {
        if (isRateLimited(socket.id)) return; // Deneme saldırısını yavaşlat

        const now = Date.now();
        if (!loginAttempts[clientIP]) loginAttempts[clientIP] = { count: 0, lockUntil: 0 };
        const attemptData = loginAttempts[clientIP];

        // Kilitli mi?
        if (attemptData.lockUntil > now) {
            socket.emit('admin_error', `⛔ Erişim kilitli. Bekleyiniz.`);
            return;
        }

        // Şifre Tipi Kontrolü (Sadece string kabul et)
        if (typeof sifre !== 'string') return;

        if (sifre === ADMIN_SIFRESI) {
            // Başarılı
            attemptData.count = 0;
            attemptData.lockUntil = 0;
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
            socket.emit('chat_message', { user: 'SİSTEM', text: `🛡️ Yönetici bağlandı.`, type: 'system' });
        } else {
            // Başarısız
            attemptData.count++;
            if (attemptData.count >= MAX_LOGIN_ATTEMPTS) {
                attemptData.lockUntil = now + LOCK_TIME;
                socket.emit('admin_error', `⛔ Çok fazla hatalı deneme! Erişim 5 dakika kesildi.`);
            } else {
                socket.emit('admin_error', `❌ Hatalı şifre.`);
            }
            socket.emit('admin_basarili', false);
        }
    });

    // Yönetici İşlemleri
    socket.on('admin_action', (data) => {
        // Yetki Kontrolü (En Önemli Kısım)
        if (!admins.has(socket.id)) {
            // Biri admin olmadığı halde bu komutu yollarsa onu at!
            socket.disconnect(true);
            return;
        }

        const targetId = data.targetId;
        const action = data.action;

        if (action === 'ban' && users[targetId]) {
            const targetIP = users[targetId].ip;
            bannedIPs.add(targetIP);
            // Hedef soketi zorla kapat
            const targetSocket = io.sockets.sockets.get(targetId);
            if (targetSocket) {
                targetSocket.emit('force_disconnect', 'Yasaklandınız.');
                targetSocket.disconnect(true);
            }
            delete users[targetId];
            io.emit('update_user_list', users);
            io.emit('chat_message', { user: 'SİSTEM', text: `🔴 Bir kullanıcı uzaklaştırıldı.`, type: 'warn' });
        } 
        else if (action === 'mute' && users[targetId]) {
            users[targetId].muted = !users[targetId].muted;
            io.to(targetId).emit('toggle_mute_lock', users[targetId].muted);
            io.emit('update_user_list', users);
        }
    });

    // Video Kontrolü
    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            // Gelen verinin tipini kontrol et (Güvenlik)
            if (typeof data !== 'object') return;
            socket.broadcast.emit('sync_video', data);
            
            if (data.type === 'change') {
                io.emit('chat_message', { user: 'SİSTEM', text: `🎬 Video değiştirildi.`, type: 'info' });
            }
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
    console.log(`KALE MODU AKTİF: Port ${PORT}`);
});
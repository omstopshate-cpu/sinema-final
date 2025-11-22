const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const ADMIN_SIFRESI = "1680"; 

// --- GÜVENLİK AYARLARI ---
const MAX_ATTEMPTS = 3; // Maksimum deneme hakkı
const LOCK_TIME = 5 * 60 * 1000; // 5 Dakika (milisaniye cinsinden)
const loginAttempts = {}; // { 'IP_ADRESI': { count: 0, lockUntil: 0 } }

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const admins = new Set();
const users = {}; 
const bannedIPs = new Set(); 

// XSS Temizleme Fonksiyonu (Html kodlarını etkisizleştirir)
function escapeHtml(text) {
    if (!text) return text;
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

io.on('connection', (socket) => {
    // İstemci IP adresini al (Render/Proxy arkasında çalışıyorsa x-forwarded-for bakar)
    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;

    // 1. BAN KONTROLÜ (Girişte atar)
    if (bannedIPs.has(clientIP)) {
        socket.emit('force_disconnect', 'Bu sunucudan kalıcı olarak uzaklaştırıldınız.');
        socket.disconnect(true);
        return;
    }

    users[socket.id] = { name: "Misafir", muted: false, ip: clientIP };
    io.emit('update_user_list', users);

    // İsim Belirleme (XSS Korumalı + Max 20 Karakter)
    socket.on('set_username', (name) => {
        if(users[socket.id]) {
            let safeName = escapeHtml(name).substring(0, 20); // Max 20 harf
            users[socket.id].name = safeName || "Misafir";
            io.emit('update_user_list', users);
            io.emit('chat_message', { user: 'SİSTEM', text: `🟢 ${safeName} katıldı.`, type: 'system' });
        }
    });

    // Chat Mesajı (XSS Korumalı + Max 200 Karakter)
    socket.on('send_message', (msg) => {
        const user = users[socket.id];
        if (user) {
            if (user.muted) return; // Mute kontrolü
            let safeMsg = escapeHtml(msg).substring(0, 200); // Max 200 harf
            if(safeMsg.trim().length > 0) {
                io.emit('chat_message', { user: user.name, text: safeMsg, type: 'user' });
            }
        }
    });

    // --- GÜVENLİ ADMİN GİRİŞİ (Brute-Force Korumalı) ---
    socket.on('admin_girisi', (sifre) => {
        const now = Date.now();
        
        // Kayıt yoksa oluştur
        if (!loginAttempts[clientIP]) {
            loginAttempts[clientIP] = { count: 0, lockUntil: 0 };
        }

        const attemptData = loginAttempts[clientIP];

        // 1. Kilitli mi kontrol et
        if (attemptData.lockUntil > now) {
            const remainingSeconds = Math.ceil((attemptData.lockUntil - now) / 1000);
            socket.emit('admin_error', `⚠️ Çok fazla deneme! ${Math.ceil(remainingSeconds/60)} dakika bekleyin.`);
            return;
        }

        // 2. Şifre Kontrolü
        if (sifre === ADMIN_SIFRESI) {
            // Başarılı: Sayacı sıfırla
            attemptData.count = 0;
            attemptData.lockUntil = 0;
            
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
            socket.emit('chat_message', { user: 'SİSTEM', text: `🛡️ Yönetici girişi yapıldı.`, type: 'system' });
        } else {
            // Başarısız: Sayacı artır
            attemptData.count++;
            
            if (attemptData.count >= MAX_ATTEMPTS) {
                attemptData.lockUntil = now + LOCK_TIME; // 5 Dakika kilitle
                socket.emit('admin_error', `⛔ Hatalı şifre! Erişim 5 dakika kilitlendi.`);
            } else {
                const kalanHak = MAX_ATTEMPTS - attemptData.count;
                socket.emit('admin_error', `❌ Yanlış Şifre! Kalan hakkınız: ${kalanHak}`);
            }
            socket.emit('admin_basarili', false);
        }
    });

    // Yönetici İşlemleri (Sunucu Taraflı Doğrulama Şart)
    socket.on('admin_action', (data) => {
        if (!admins.has(socket.id)) return; // HACK KORUMASI: Listede yoksa işlemi yapma

        const targetId = data.targetId;
        const action = data.action;

        if (action === 'ban' && users[targetId]) {
            const targetIP = users[targetId].ip;
            bannedIPs.add(targetIP);
            io.to(targetId).emit('force_disconnect', 'Yönetici tarafından yasaklandınız.');
            io.sockets.sockets.get(targetId)?.disconnect(true);
            io.emit('chat_message', { user: 'SİSTEM', text: `🔴 ${users[targetId].name} yasaklandı.`, type: 'warn' });
            delete users[targetId];
            io.emit('update_user_list', users);
        } 
        else if (action === 'mute' && users[targetId]) {
            users[targetId].muted = !users[targetId].muted;
            io.to(targetId).emit('toggle_mute_lock', users[targetId].muted);
            io.emit('update_user_list', users);
        }
    });

    // Video Kontrolü (Sadece Admin)
    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            socket.broadcast.emit('sync_video', data);
            if (data.type === 'change') {
                io.emit('chat_message', { user: 'SİSTEM', text: `🎬 Yeni video açıldı.`, type: 'info' });
            }
        }
    });

    socket.on('disconnect', () => {
        delete users[socket.id];
        admins.delete(socket.id);
        io.emit('update_user_list', users);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Güvenli Sunucu Aktif: ${PORT}`);
});
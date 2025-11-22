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

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const admins = new Set();
const users = {}; // { socketId: { name: "Ahmet", muted: false } }
const bannedIPs = new Set(); // Banlanan IP'ler

io.on('connection', (socket) => {
    const clientIP = socket.handshake.address;

    // 1. BAN KONTROLÜ
    if (bannedIPs.has(clientIP)) {
        socket.emit('force_disconnect', 'Bu odadan yasaklandınız.');
        socket.disconnect(true);
        return;
    }

    // Varsayılan kullanıcı
    users[socket.id] = { name: "Misafir", muted: false, ip: clientIP };
    
    // Herkese güncel listeyi yolla
    io.emit('update_user_list', users);

    // İsim Belirleme
    socket.on('set_username', (name) => {
        if(users[socket.id]) {
            users[socket.id].name = name || "Misafir";
            io.emit('update_user_list', users);
            io.emit('chat_message', { user: 'SİSTEM', text: `🟢 ${name} katıldı.`, type: 'system' });
        }
    });

    // Chat Mesajı
    socket.on('send_message', (msg) => {
        const user = users[socket.id];
        if (user) {
            // Eğer kullanıcı muted ise mesaj atamasın (İstersen bunu kaldırabilirsin)
            // if (user.muted) return; 
            io.emit('chat_message', { user: user.name, text: msg, type: 'user' });
        }
    });

    // Admin Girişi
    socket.on('admin_girisi', (sifre) => {
        if (sifre === ADMIN_SIFRESI) {
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
            socket.emit('chat_message', { user: 'SİSTEM', text: `🛡️ Yönetici yetkileri aktif edildi.`, type: 'system' });
        } else {
            socket.emit('admin_basarili', false);
        }
    });

    // --- YÖNETİCİ AKSİYONLARI (BAN / MUTE) ---
    socket.on('admin_action', (data) => {
        // Sadece admin yapabilir
        if (!admins.has(socket.id)) return;

        const targetId = data.targetId;
        const action = data.action; // 'ban' veya 'mute'

        if (action === 'ban') {
            if (users[targetId]) {
                const targetIP = users[targetId].ip;
                bannedIPs.add(targetIP); // IP Ban at
                io.to(targetId).emit('force_disconnect', 'Yönetici tarafından yasaklandınız.');
                io.sockets.sockets.get(targetId)?.disconnect(true);
                io.emit('chat_message', { user: 'SİSTEM', text: `🔴 ${users[targetId].name} yasaklandı.`, type: 'warn' });
                delete users[targetId];
                io.emit('update_user_list', users);
            }
        } 
        else if (action === 'mute') {
            if (users[targetId]) {
                users[targetId].muted = !users[targetId].muted; // Durumu tersine çevir
                const isMuted = users[targetId].muted;
                // Hedef kişiye özel sinyal yolla
                io.to(targetId).emit('toggle_mute_lock', isMuted);
                // Listeyi güncelle (ikon değişsin)
                io.emit('update_user_list', users);
            }
        }
    });

    // Video Kontrolü
    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            socket.broadcast.emit('sync_video', data);
            if (data.type === 'change') {
                io.emit('chat_message', { user: 'SİSTEM', text: `🎬 Yeni video açıldı.`, type: 'info' });
            }
        }
    });

    socket.on('disconnect', () => {
        if (users[socket.id]) {
            io.emit('update_user_list', users); // Listeden düş
        }
        delete users[socket.id];
        admins.delete(socket.id);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Sunucu Aktif: ${PORT}`);
});
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
const users = {}; // Kullanıcı isimlerini tutmak için

io.on('connection', (socket) => {
    // 1. Yeni gelen kullanıcıyı kaydet (Başta isimsiz)
    users[socket.id] = "Bilinmeyen Ajan"; 

    // Kullanıcı ismini girince
    socket.on('set_username', (name) => {
        users[socket.id] = name || "Bilinmeyen";
        // Herkese haber ver
        io.emit('notification', { msg: `🟢 ${users[socket.id]} sisteme giriş yaptı.`, type: 'success' });
        io.emit('update_user_count', Object.keys(users).length);
    });

    socket.on('admin_girisi', (sifre) => {
        if (sifre === ADMIN_SIFRESI) {
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
            io.emit('notification', { msg: `🛡️ Sistem Yöneticisi yetki aldı.`, type: 'info' });
        } else {
            socket.emit('admin_basarili', false);
        }
    });

    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            socket.broadcast.emit('sync_video', data);
            
            // Video değişirse bildirim at
            if (data.type === 'change') {
                io.emit('notification', { msg: `🎬 Yeni video yüklendi.`, type: 'info' });
            }
        }
    });

    socket.on('disconnect', () => {
        const leavingUser = users[socket.id];
        delete users[socket.id];
        admins.delete(socket.id);
        
        if (leavingUser) {
            io.emit('notification', { msg: `🔴 ${leavingUser} ayrıldı.`, type: 'warn' });
            io.emit('update_user_count', Object.keys(users).length);
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Sunucu Aktif: ${PORT}`);
});
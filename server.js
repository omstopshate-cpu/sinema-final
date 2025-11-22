const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// ŞİFRE: 1680
const ADMIN_SIFRESI = "1680"; 

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const admins = new Set();

io.on('connection', (socket) => {
    console.log('Biri bağlandı: ' + socket.id);

    socket.on('admin_girisi', (sifre) => {
        if (sifre === ADMIN_SIFRESI) {
            admins.add(socket.id);
            socket.emit('admin_basarili', true);
        } else {
            socket.emit('admin_basarili', false);
        }
    });

    socket.on('video_action', (data) => {
        if (admins.has(socket.id)) {
            socket.broadcast.emit('sync_video', data);
        }
    });

    socket.on('disconnect', () => {
        admins.delete(socket.id);
    });
});

// OTOMATİK PORT AYARI (Render için gerekli kısım)
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Sunucu çalışıyor! Port: ${PORT}`);
});
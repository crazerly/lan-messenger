const express = require('express');
const http = require('http');
const path = require('path');
const { run, get, all } = require('./database/db');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');

const app = express();
const server = http.createServer(app);
const io = require('socket.io')(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'public', 'uploads');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const time_ms = Date.now(); // Ensures no duplicate files
    const safe = file.originalname.replace(/[^a-z0-9.\-_]/gi, '_'); // Converts spaces, emojis, slashes, etc. to '_'
    cb(null, `${time_ms}_${safe}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // Limit to 50MB
  fileFilter: (req, file, cb) => {
    if (/^(image|audio|video)\//.test(file.mimetype)) {
      cb(null, true);
      return;
    }

    // Allow encrypted uploads
    if (/\.enc$/i.test(file.originalname)) {
      cb(null, true);
      return;
    }
    if (req.headers && req.headers['x-encrypted'] === '1') {
      cb(null, true);
      return;
    }

    cb(new Error('Only image, audio and video files allowed'));
  }
});


const userSockets = new Map();

async function markUserLastSeen(userId) {
  try {
    await run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [userId]);
    const row = await get('SELECT id, username, status, profile_pic, last_seen, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE id = ?', [userId]);
    return row;
  }
  catch (e) {
    console.error('Mark last seen error', e);
    return null;
  }
}

async function broadcastUserStatus(userId, online) {
  try {
    let user;
    if (online) { user = await get('SELECT id, username, status, profile_pic, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE id = ?', [userId]); }
    else { user = await markUserLastSeen(userId); }
    io.emit('user_status', {
      id: userId,
      online: !!online,
      last_seen_ms: user ? user.last_seen_ms : null,
      username: user ? user.username : null
    });
  }
  catch (e) { console.error('Status broadcast error', e); }
}

app.post('/api/register', async (req, res) => {
  const { username, password, publicKey } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const existing = await get('SELECT * FROM users WHERE username = ?', [username]);
    if (existing) return res.status(400).json({ error: 'Username taken' });

    const hash = await bcrypt.hash(password, 10);
    const new_user = await run('INSERT INTO users (username, password_hash, last_seen, public_key) VALUES (?, ?, CURRENT_TIMESTAMP, ?)', [username, hash, publicKey || null]);
    const user = await get('SELECT id, username, status, profile_pic, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE id = ?', [new_user.lastID]);
    io.emit('new_user', user);
    res.json({ user });
  }
  catch (e) {
    console.error('Register error', e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.put('/api/users/:id/public_key', async (req, res) => {
  const userId = req.params.id;
  const { publicKey } = req.body;
  if (!userId || !publicKey) return res.status(400).json({ error: 'userId and publicKey required' });
  try {
    await run('UPDATE users SET public_key = ? WHERE id = ?', [publicKey, userId]);
    const user = await get('SELECT id, username, public_key FROM users WHERE id = ?', [userId]);
    res.json({ ok: true, user });
  }
  catch (e) {
    console.error(e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/chats/:chatId/members_public_keys', async (req, res) => {
  const chatId = req.params.chatId;
  if (!chatId) return res.status(400).json({ error: 'Invalid chatId' });
  try {
    const rows = await all(
      `SELECT u.id AS user_id, u.username, u.public_key
       FROM chat_members cm
       JOIN users u ON cm.user_id = u.id
       WHERE cm.chat_id = ?`, [chatId]
    );
    res.json({ members: rows });
  }
  catch (e) {
    console.error(e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const user = await get('SELECT id, username, password_hash, status, profile_pic, last_seen, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE username = ?', [username]);
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (!user.password_hash) return res.status(400).json({ error: 'User has no password' });
    
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect password' });

    await run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
    const fresh = await get('SELECT id, username, status, profile_pic, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE id = ?', [user.id]);
    res.json({ user: fresh });
  }
  catch (e) {
    console.error('Login error', e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/contacts', async (req, res) => {
  const exclude = req.query.exclude || 0;
  try {
    const rows = await all(
      `SELECT id, username, status, profile_pic, last_seen, (strftime('%s', last_seen) * 1000) AS last_seen_ms
       FROM users WHERE id != ? ORDER BY username COLLATE NOCASE`,
      [exclude]
    );
    const contactsList = rows.map(r => ({ ...r, online: userSockets.has(r.id) }));
    res.json({ contacts: contactsList });
  }
  catch (e) {
    console.error(e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/groups', async (req, res) => {
  const user_id = req.query.userId;
  if (!user_id) return res.status(400).json({ error: 'userId required' });
  try {
    const rows = await all(
      `SELECT c.*, c.creator_id AS creator_id
       FROM chats c
       JOIN chat_members cm ON cm.chat_id = c.id
       WHERE c.is_group = 1 AND cm.user_id = ?
       ORDER BY c.created_at DESC`,
      [user_id]
    );
    res.json({ groups: rows });
  }
  catch (e) {
    console.error('Get groups error', e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/groups', async (req, res) => {
  const { name, memberIds, creatorId } = req.body;
  if (!name || !Array.isArray(memberIds)) return res.status(400).json({ error: 'Name and memberIds required' });
  try {
    const new_group = await run('INSERT INTO chats (name, is_group, creator_id) VALUES (?, 1, ?)', [name, creatorId || null]);
    const chatId = new_group.lastID;
    const uniqueIds = Array.from(new Set([...(memberIds || []), creatorId].filter(Boolean)));
    for (const user_id of uniqueIds) {
      await run('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)', [chatId, user_id]);
      if (userSockets.has(user_id)) {
        for (const socket_id of userSockets.get(user_id)) {
          const socket = io.sockets.sockets.get(socket_id)
          if (socket) { socket.join(String(chatId)); }
        }
      }
    }

    const chat = await get('SELECT * FROM chats WHERE id = ?', [chatId]);
    io.emit('group_created', chat);
    res.json({ chat });
  }
  catch (e) {
    console.error('Create group error', e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/chats/find_or_create', async (req, res) => {
  const { userId, otherId } = req.body;
  if (!userId || !otherId) return res.status(400).json({ error: 'userId and otherId required' });
  try {
    const rows = await all(
      `SELECT cm.chat_id FROM chat_members cm
       JOIN chats c ON cm.chat_id = c.id
       WHERE c.is_group = 0 AND cm.user_id IN (?, ?)
       GROUP BY cm.chat_id HAVING COUNT(DISTINCT cm.user_id) = 2`,
      [userId, otherId]
    );

    if (rows.length) {
      const chat = await get('SELECT * FROM chats WHERE id = ?', [rows[0].chat_id]);
      return res.json({ chat });
    }

    const new_chat = await run('INSERT INTO chats (name, is_group) VALUES (?, 0)', [null]);
    const chatId = new_chat.lastID;
    await run('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)', [chatId, userId]);
    await run('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)', [chatId, otherId]);
    
    const chat = await get('SELECT * FROM chats WHERE id = ?', [chatId]);
    return res.json({ chat });
  }
  catch (e) {
    console.error(e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/chats/:chatId/messages', async (req, res) => {
  const chatId = req.params.chatId;
  if (!chatId) return res.status(400).json({ error: 'Invalid chatId' });
  try {
    const messages = await all(
      `SELECT m.id, m.chat_id, m.sender_id, m.content, m.type, m.media_url, m.status,
              u.username AS sender_name,
              (strftime('%s', m.created_at) * 1000) AS created_at_ms
       FROM messages m
       LEFT JOIN users u ON m.sender_id = u.id
       WHERE m.chat_id = ?
       ORDER BY m.created_at ASC`, [chatId]
    );
    res.json({ messages });
  }
  catch (e) {
    console.error(e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/chats/:chatId/members', async (req, res) => {
  const chatId = req.params.chatId;
  if (!chatId) return res.status(400).json({ error: 'invalid chatId' });
  try {
    const rows = await all(
      `SELECT u.id, u.username, u.profile_pic, u.status, (strftime('%s', u.last_seen) * 1000) AS last_seen_ms
       FROM chat_members cm
       JOIN users u ON cm.user_id = u.id
       WHERE cm.chat_id = ? ORDER BY u.username`, [chatId]
    );
    res.json({ members: rows });
  }
  catch (e) {
    console.error('Members error', e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/chats/:chatId/invite', async (req, res) => {
  const chatId = req.params.chatId;
  const { userId } = req.body;
  if (!chatId || !userId) return res.status(400).json({ error: 'chatId and userId required' });
  try {
    await run('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)', [chatId, userId]);
    if (userSockets.has(userId)) {
      for (const socket_id of userSockets.get(userId)) {
        const socket = io.sockets.sockets.get(socket_id);
        if (socket) { socket.join(String(chatId)); }
      }
    }

    const resChat = await get('SELECT * FROM chats WHERE id = ?', [chatId]);
    io.to(String(chatId)).emit('chat_updated', { chat: resChat });
    res.json({ ok: true, chat: resChat });
  }
  catch (e) {
    console.error('Invite error', e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/chats/:chatId/add_members', async (req, res) => {
  const chatId = req.params.chatId;
  const { memberIds } = req.body;
  if (!chatId || !Array.isArray(memberIds)) return res.status(400).json({ error: 'chatId and memberIds array required' });
  try {
    const notifiedSocketIds = [];
    const addedUserIds = [];

    for (const user_id of memberIds) {
      const result = await run('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)', [chatId, user_id]);
      const membership = await get('SELECT id FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, user_id]);
      if (membership) addedUserIds.push(Number(user_id));

      if (userSockets.has(user_id)) {
        for (const socket_id of userSockets.get(user_id)) {
          const socket = io.sockets.sockets.get(socket_id);
          if (socket) {
            socket.join(String(chatId));
            notifiedSocketIds.push(socket_id);
          }
        }
      }
    }

    const resChat = await get('SELECT * FROM chats WHERE id = ?', [chatId]);
    const members = await all(
      `SELECT u.id AS user_id, u.username, u.public_key
       FROM chat_members cm
       JOIN users u ON cm.user_id = u.id
       WHERE cm.chat_id = ?`, [chatId]
    );

    io.to(String(chatId)).emit('chat_updated', { chat: resChat, members });
    for (const user_id of addedUserIds) {
      if (userSockets.has(user_id)) {
        for (const socket_id of userSockets.get(user_id)) {
          const s = io.sockets.sockets.get(socket_id);
          if (s) s.emit('added_to_chat', { chat: resChat, members, added_by: req.userId || null });
        }
      }
    }
    res.json({ ok: true, chat: resChat, members });
  }
  catch (e) {
    console.error('Add members error', e);
    res.status(500).json({ error: 'DB error' });
  }
});


async function cleanupChatIfEmpty(chatId) {
  try {
    const row = await get('SELECT COUNT(*) AS count FROM chat_members WHERE chat_id = ?', [chatId]);
    const count = row ? row.count : 0;
    if (count == 0) {
      await run('DELETE FROM messages WHERE chat_id = ?', [chatId]);
      await run('DELETE FROM chats WHERE id = ?', [chatId]);
      io.emit('chat_deleted', { chatId });
    }
    else {
      const resChat = await get('SELECT * FROM chats WHERE id = ?', [chatId]);
      io.to(String(chatId)).emit('chat_updated', { chat: resChat });
    }
  }
  catch (e) { console.error('Cleanup chat error', e); }
}

app.post('/api/chats/:chatId/leave', async (req, res) => {
  const chatId = req.params.chatId;
  const { userId } = req.body;
  if (!chatId || !userId) return res.status(400).json({ error: 'chatId and userId required' });
  try {
    await run('DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, userId]);
    if (userSockets.has(userId)) {
      for (const socket_id of userSockets.get(userId)) {
        const socket = io.sockets.sockets.get(socket_id)
        if (socket) { socket.leave(String(chatId)); }
      }
    }
    await cleanupChatIfEmpty(chatId);
    res.json({ ok: true });
  }
  catch (e) {
    console.error('Leave error', e);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/chats/:chatId/kick', async (req, res) => {
  const chatId = req.params.chatId;
  const { userId, targetId } = req.body;
  if (!chatId || !userId || !targetId) return res.status(400).json({ error: 'Parameters required' });
  try {
    const chat = await get('SELECT * FROM chats WHERE id = ?', [chatId]);
    if (!chat) return res.status(404).json({ error: 'chat not found' });
    if (chat.creator_id != userId) return res.status(403).json({ error: 'Only creator can kick' });
    await run('DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, targetId]);

    if (userSockets.has(targetId)) {
      for (const sid of userSockets.get(targetId)) {
        const socket = io.sockets.sockets.get(sid);
        if (socket) {
          // Notify the kicked user
          socket.emit('removed_from_chat', { chatId, by: userId, chat_name: chat.name || null });
          socket.leave(String(chatId));
        }
      }
    }

    await cleanupChatIfEmpty(chatId);
    res.json({ ok: true });
  }
  catch (e) {
    console.error('Kick error', e);
    res.status(500).json({ error: 'DB error' });
  }
});


app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'File required' });
    const url = `/uploads/${req.file.filename}`;
    file_type = req.file.mimetype;
    let type = 'image';
    if (/^video\//.test(file_type)) type = 'video';
    else if (/^audio\//.test(file_type)) type = 'audio';
    else if (/^image\//.test(file_type)) type = 'image';
    res.json({ url, type });
  }
  catch (e) {
    console.error('Upload error', e);
    res.status(500).json({ error: 'Upload failed', details: e.message });
  }
});

app.post('/api/users/:userId/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const url = `/uploads/${req.file.filename}`;
    if (!req.file) return res.status(400).json({ error: 'File required' });
    await run('UPDATE users SET profile_pic = ? WHERE id = ?', [url, userId]);
    const user = await get('SELECT id, username, profile_pic, status, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE id = ?', [userId]);
    io.emit('user_updated', user);
    res.json({ ok: true, user });
  }
  catch (e) {
    console.error('Avatar error', e);
    res.status(500).json({ error: 'Avatar failed' });
  }
});

app.post('/api/users/:userId/status', async (req, res) => {
  try {
    const user_id = req.params.userId;
    const { status } = req.body;
    if (!user_id) return res.status(400).json({ error: 'userId required' });
    await run('UPDATE users SET status = ? WHERE id = ?', [status || null, user_id]);
    const user = await get('SELECT id, username, profile_pic, status, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE id = ?', [user_id]);
    io.emit('user_updated', user);
    res.json({ ok: true, user });
  }
  catch (e) {
    console.error('Status error', e);
    res.status(500).json({ error: 'Status failed' });
  }
});

io.on('connection', (socket) => {
  console.log('Socket connected: ', socket.id);

  socket.on('register', async (data) => {
    const { userId } = data || {};
    if (!userId) return;
    const prev = userSockets.get(userId);
    const wasConnected = prev && prev.size > 0;
    const socketSet = prev || new Set();
    socketSet.add(socket.id);
    userSockets.set(userId, socketSet);

    try {
      const rows = await all('SELECT chat_id FROM chat_members WHERE user_id = ?', [userId]);
      rows.forEach(row => socket.join(String(row.chat_id)));
    }
    catch (e) { console.error('join rooms error', e); }

    if (!wasConnected) {
      await run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [userId]);
      io.emit('new_user', await get('SELECT id, username, status, profile_pic, (strftime(\'%s\', last_seen) * 1000) AS last_seen_ms FROM users WHERE id = ?', [userId]));
      broadcastUserStatus(userId, true);
    }
  });

  socket.on('join_chat', (payload) => {
    const { chatId } = payload || {};
    if (!chatId) return;
    socket.join(String(chatId));
  });

  socket.on('send_message', async (payload, cb) => {
    try {
      const { chatId, senderId, content, media_url, type } = payload;
      if (!chatId || !senderId) {
        if (cb) cb({
          ok: false,
          error: 'Invalid payload'
        });
        return;
      }

      const membership = await get('SELECT id FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, senderId]);
      if (!membership) {
        if (cb) cb({ ok: false, error: 'Not a member of this chat (permission denied)' });
        return;
      }

      const msgContent = typeof content != 'undefined' ? content : null;
      const msgType = type || (media_url ? 'image' : 'text');
      const res = await run(
        `INSERT INTO messages (chat_id, sender_id, content, type, media_url, created_at, status) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'sent')`,
        [chatId, senderId, msgContent, msgType, media_url || null]
      );

      const insertedId = res.lastID;
      const msg = await get(
        `SELECT m.id, m.chat_id, m.sender_id, m.content, m.type, m.media_url, m.status,
                u.username AS sender_name,
                (strftime('%s', m.created_at) * 1000) AS created_at_ms
         FROM messages m
         LEFT JOIN users u ON m.sender_id = u.id
         WHERE m.id = ?`, [insertedId]
      );

      io.to(String(chatId)).emit('receive_message', msg);
      if (cb) cb({
        ok: true,
        message: msg
      });
    }
    catch (e) {
      console.error('send_message error', e);
      if (cb) cb({
        ok: false,
        error: 'server error'
      });
    }
  });

  socket.on('disconnect', async () => {
    console.log('socket disconnect', socket.id);
    for (const [userId, set] of userSockets.entries()) {
      if (set.has(socket.id)) {
        set.delete(socket.id);

        if (set.size == 0) {
          userSockets.delete(userId);
          await markUserLastSeen(userId);
          broadcastUserStatus(userId, false);
        }
        else { userSockets.set(userId, set); }
        break;
      }
    }
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

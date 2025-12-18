const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const dbPath = path.join(__dirname, 'database.db');

const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (e) {
      if (e) return reject(e);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (e, row) => {
      if (e) return reject(e);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (e, rows) => {
      if (e) return reject(e);
      resolve(rows);
    });
  });
}

async function ensureColumn(table, col, colDef) {
  const rows = await all(`PRAGMA table_info(${table})`);
  const found = rows.some(row => row.name == col);
  if (!found) { await run(`ALTER TABLE ${table} ADD COLUMN ${colDef}`); }
}

db.serialize(async () => {
  db.run(`PRAGMA foreign_keys = ON;`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    profile_pic TEXT,
    last_seen DATETIME,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    is_group INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chat_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER,
    user_id INTEGER,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(chat_id, user_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER,
    sender_id INTEGER,
    content TEXT,
    type TEXT DEFAULT 'text',
    media_url TEXT,
    status TEXT DEFAULT 'sent',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY(sender_id) REFERENCES users(id)
  )`);

  try {
    await ensureColumn('users', 'password_hash', 'password_hash TEXT');
    await ensureColumn('users', 'profile_pic', 'profile_pic TEXT');
    await ensureColumn('chats', 'creator_id', 'creator_id INTEGER');
    await ensureColumn('users', 'public_key', 'public_key TEXT');
  }
  catch (e) { console.error('Error checking columns: ', e); }
});

module.exports = { db, run, get, all };

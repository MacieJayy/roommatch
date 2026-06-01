require('dotenv').config();
const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const { EventEmitter } = require('events');
const path       = require('path');
const fs         = require('fs');
const initSqlJs  = require('sql.js');

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'roommatch-dev-secret-change-me';
const DB_PATH    = process.env.DB_PATH    || 'roommatch.db';
const MAX_USERS  = 30;

// ─── App ─────────────────────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });
const bus    = new EventEmitter();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Boot ─────────────────────────────────────────────────────────────────────
async function main() {
  const SQL = await initSqlJs();

  // Load existing DB file or create fresh
  let db;
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }

  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");

  // ─── DB helpers ────────────────────────────────────────────────────────────
  function persist() {
    try { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); }
    catch (e) { console.error('DB persist error:', e.message); }
  }

  // SELECT one row
  function dbGet(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return row;
  }

  // SELECT many rows
  function dbAll(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  }

  // INSERT / UPDATE / DELETE — returns { lastInsertRowid }
  function dbRun(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.run(params);
    stmt.free();
    const res = db.exec("SELECT last_insert_rowid()");
    const id  = res[0]?.values[0][0] ?? null;
    persist();
    return { lastInsertRowid: id };
  }

  // Write with no return value (e.g. INSERT OR IGNORE)
  function dbWrite(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.run(params);
    stmt.free();
    persist();
  }

  // ─── Schema ────────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT    NOT NULL UNIQUE,
      age           INTEGER NOT NULL,
      city          TEXT    NOT NULL,
      description   TEXT    NOT NULL DEFAULT '',
      type          TEXT    NOT NULL,
      password_hash TEXT    NOT NULL,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS swipes (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      swiper_id  INTEGER NOT NULL,
      swiped_id  INTEGER NOT NULL,
      direction  TEXT    NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(swiper_id, swiped_id)
    );

    CREATE TABLE IF NOT EXISTS matches (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user1_id   INTEGER NOT NULL,
      user2_id   INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      match_id   INTEGER NOT NULL,
      sender_id  INTEGER NOT NULL,
      content    TEXT    NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  persist();

  // ─── Auth middleware ────────────────────────────────────────────────────────
  function auth(req, res, next) {
    const header = req.headers.authorization || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Brak tokenu' });
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch {
      res.status(401).json({ error: 'Token wygasł lub jest nieprawidłowy' });
    }
  }

  // ─── Routes ────────────────────────────────────────────────────────────────

  // POST /api/register
  app.post('/api/register', (req, res) => {
    const { name, age, city, description, type, password } = req.body || {};

    if (!name?.trim() || !age || !city?.trim() || !type || !password) {
      return res.status(400).json({ error: 'Wypełnij wszystkie wymagane pola' });
    }
    if (!['roommate', 'room'].includes(type)) {
      return res.status(400).json({ error: 'Nieprawidłowy typ' });
    }
    if (parseInt(age) < 18 || parseInt(age) > 99) {
      return res.status(400).json({ error: 'Wiek musi być między 18 a 99' });
    }

    const userCount = dbGet('SELECT COUNT(*) AS n FROM users')?.n || 0;
    if (userCount >= MAX_USERS) {
      return res.status(400).json({
        error: `Demo obsługuje max ${MAX_USERS} użytkowników (${userCount}/${MAX_USERS}).`
      });
    }

    try {
      const hash = bcrypt.hashSync(password, 10);
      const { lastInsertRowid: id } = dbRun(
        'INSERT INTO users (name, age, city, description, type, password_hash) VALUES (?,?,?,?,?,?)',
        [name.trim(), parseInt(age), city.trim(), (description || '').trim(), type, hash]
      );

      const user  = { id, name: name.trim(), age: parseInt(age), city: city.trim(), description: (description || '').trim(), type };
      const token = jwt.sign({ id, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user });
    } catch (err) {
      const msg = String(err.message).includes('UNIQUE')
        ? 'Ta nazwa użytkownika jest już zajęta'
        : 'Błąd rejestracji: ' + err.message;
      res.status(400).json({ error: msg });
    }
  });

  // POST /api/login
  app.post('/api/login', (req, res) => {
    const { name, password } = req.body || {};
    if (!name?.trim() || !password) return res.status(400).json({ error: 'Podaj nazwę i hasło' });

    const user = dbGet('SELECT * FROM users WHERE name = ?', [name.trim()]);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });
    }

    const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user.id, name: user.name, age: user.age, city: user.city, description: user.description, type: user.type }
    });
  });

  // GET /api/stats
  app.get('/api/stats', (_req, res) => {
    const count = dbGet('SELECT COUNT(*) AS n FROM users')?.n || 0;
    res.json({ userCount: count, maxUsers: MAX_USERS });
  });

  // GET /api/profiles
  app.get('/api/profiles', auth, (req, res) => {
    const profiles = dbAll(
      `SELECT id, name, age, city, description, type FROM users
       WHERE id != ? AND id NOT IN (SELECT swiped_id FROM swipes WHERE swiper_id = ?)
       ORDER BY RANDOM() LIMIT 20`,
      [req.user.id, req.user.id]
    );
    res.json(profiles);
  });

  // POST /api/swipe
  app.post('/api/swipe', auth, (req, res) => {
    const { targetId, direction } = req.body || {};
    if (!targetId || !['like', 'pass'].includes(direction)) {
      return res.status(400).json({ error: 'Nieprawidłowe dane' });
    }

    try {
      dbWrite('INSERT OR IGNORE INTO swipes (swiper_id, swiped_id, direction) VALUES (?,?,?)',
        [req.user.id, targetId, direction]);

      if (direction !== 'like') return res.json({ matched: false });

      const mutual = dbGet(
        'SELECT id FROM swipes WHERE swiper_id = ? AND swiped_id = ? AND direction = ?',
        [targetId, req.user.id, 'like']
      );

      if (!mutual) return res.json({ matched: false });

      const existing = dbGet(
        'SELECT id FROM matches WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)',
        [req.user.id, targetId, targetId, req.user.id]
      );

      if (existing) return res.json({ matched: true, matchId: existing.id });

      const { lastInsertRowid: matchId } = dbRun(
        'INSERT INTO matches (user1_id, user2_id) VALUES (?,?)',
        [req.user.id, targetId]
      );

      const me      = dbGet('SELECT name, city, type FROM users WHERE id = ?', [req.user.id]);
      const partner = dbGet('SELECT name, city, type FROM users WHERE id = ?', [targetId]);

      bus.emit('new_match', {
        matchId,
        user1: { id: req.user.id,  ...me },
        user2: { id: targetId, ...partner }
      });

      res.json({ matched: true, matchId });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/matches
  app.get('/api/matches', auth, (req, res) => {
    const uid = req.user.id;
    // sql.js doesn't support subqueries in SELECT with CASE WHEN easily,
    // so fetch matches + partner info separately for clarity
    const rows = dbAll(
      `SELECT m.id AS matchId,
              CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END AS partnerId,
              m.created_at
       FROM matches m
       WHERE m.user1_id = ? OR m.user2_id = ?
       ORDER BY m.created_at DESC`,
      [uid, uid, uid]
    );

    const matches = rows.map(row => {
      const partner = dbGet('SELECT name, age, city, type FROM users WHERE id = ?', [row.partnerId]);
      const lastMsg = dbGet(
        'SELECT content FROM messages WHERE match_id = ? ORDER BY created_at DESC LIMIT 1',
        [row.matchId]
      );
      return { ...row, ...partner, lastMessage: lastMsg?.content || null };
    });

    res.json(matches);
  });

  // GET /api/matches/:id/messages
  app.get('/api/matches/:id/messages', auth, (req, res) => {
    const match = dbGet(
      'SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
      [req.params.id, req.user.id, req.user.id]
    );
    if (!match) return res.status(403).json({ error: 'Brak dostępu do tej rozmowy' });

    const messages = dbAll(
      `SELECT msg.id, msg.content, msg.created_at, msg.sender_id, u.name AS sender_name
       FROM messages msg JOIN users u ON u.id = msg.sender_id
       WHERE msg.match_id = ? ORDER BY msg.created_at ASC`,
      [req.params.id]
    );
    res.json(messages);
  });

  // POST /api/matches/:id/messages  (REST fallback — WebSocket is primary)
  app.post('/api/matches/:id/messages', auth, (req, res) => {
    const { content } = req.body || {};
    if (!content?.trim()) return res.status(400).json({ error: 'Pusta wiadomość' });

    const match = dbGet(
      'SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
      [req.params.id, req.user.id, req.user.id]
    );
    if (!match) return res.status(403).json({ error: 'Brak dostępu do tej rozmowy' });

    const sender = dbGet('SELECT name FROM users WHERE id = ?', [req.user.id]);
    const { lastInsertRowid: msgId } = dbRun(
      'INSERT INTO messages (match_id, sender_id, content) VALUES (?,?,?)',
      [req.params.id, req.user.id, content.trim()]
    );

    const message = {
      id: msgId,
      match_id: parseInt(req.params.id),
      sender_id: req.user.id,
      sender_name: sender.name,
      content: content.trim(),
      created_at: new Date().toISOString()
    };

    bus.emit('chat_message', {
      message,
      recipientIds: [match.user1_id, match.user2_id]
    });

    res.json(message);
  });

  // ─── WebSocket ──────────────────────────────────────────────────────────────
  const clients = new Map(); // userId -> WebSocket

  wss.on('connection', (ws) => {
    let uid = null;

    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      if (msg.type === 'auth') {
        try {
          const payload = jwt.verify(msg.token, JWT_SECRET);
          uid = payload.id;
          clients.set(uid, ws);
          ws.send(JSON.stringify({ type: 'auth_ok', userId: uid }));
        } catch {
          ws.send(JSON.stringify({ type: 'error', message: 'Nieprawidłowy token' }));
        }
        return;
      }

      if (!uid) {
        ws.send(JSON.stringify({ type: 'error', message: 'Nie uwierzytelniono' }));
        return;
      }

      if (msg.type === 'chat') {
        const { matchId, content } = msg;
        if (!matchId || !content?.trim()) return;

        const match = dbGet(
          'SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
          [matchId, uid, uid]
        );
        if (!match) return ws.send(JSON.stringify({ type: 'error', message: 'Brak dostępu' }));

        const sender = dbGet('SELECT name FROM users WHERE id = ?', [uid]);
        const { lastInsertRowid: msgId } = dbRun(
          'INSERT INTO messages (match_id, sender_id, content) VALUES (?,?,?)',
          [matchId, uid, content.trim()]
        );

        const message = {
          id: msgId,
          match_id: matchId,
          sender_id: uid,
          sender_name: sender.name,
          content: content.trim(),
          created_at: new Date().toISOString()
        };

        bus.emit('chat_message', {
          message,
          recipientIds: [match.user1_id, match.user2_id]
        });
      }
    });

    ws.on('close', () => { if (uid) clients.delete(uid); });
    ws.on('error', ()  => { if (uid) clients.delete(uid); });
  });

  bus.on('chat_message', ({ message, recipientIds }) => {
    const payload = JSON.stringify({ type: 'message', data: message });
    for (const id of recipientIds) {
      const client = clients.get(id);
      if (client?.readyState === WebSocket.OPEN) client.send(payload);
    }
  });

  bus.on('new_match', ({ matchId, user1, user2 }) => {
    const pairs = [
      { uid: user1.id, partner: { id: user2.id, name: user2.name, city: user2.city, type: user2.type } },
      { uid: user2.id, partner: { id: user1.id, name: user1.name, city: user1.city, type: user1.type } }
    ];
    for (const { uid, partner } of pairs) {
      const client = clients.get(uid);
      if (client?.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'match', data: { matchId, partner } }));
      }
    }
  });

  // ─── Start ─────────────────────────────────────────────────────────────────
  server.listen(PORT, () => {
    console.log(`✅ RoomMatch działa na http://localhost:${PORT}`);
    console.log(`   Baza danych: ${DB_PATH}`);
    console.log(`   Limit użytkowników: ${MAX_USERS}`);
  });
}

main().catch(err => {
  console.error('Błąd startu:', err);
  process.exit(1);
});

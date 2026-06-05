const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'wifime-mvp-secret-2025';

const db = new Database(path.join(__dirname, 'wifime.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    phone           TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,
    codename        TEXT    NOT NULL,
    balance         REAL    DEFAULT 10.0,
    is_host         INTEGER DEFAULT 0,
    host_price      REAL    DEFAULT 0.08,
    host_speed      TEXT    DEFAULT '10 MB/s',
    host_max_users  INTEGER DEFAULT 3,
    earnings        REAL    DEFAULT 0.0,
    rating          REAL    DEFAULT 5.0,
    sessions_count  INTEGER DEFAULT 0,
    created_at      TEXT    DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    consumer_id  INTEGER NOT NULL REFERENCES users(id),
    host_id      INTEGER NOT NULL REFERENCES users(id),
    started_at   TEXT    DEFAULT (datetime('now')),
    ended_at     TEXT,
    seconds      INTEGER DEFAULT 0,
    mb_used      REAL    DEFAULT 0,
    cost         REAL    DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    type        TEXT    NOT NULL CHECK(type IN ('debit','credit')),
    amount      REAL    NOT NULL,
    description TEXT    NOT NULL,
    ref_id      INTEGER,
    created_at  TEXT    DEFAULT (datetime('now'))
  );
`);

const PLACES = [
  'Lisboa','Paris','Tokyo','Berlin','Dubai','Sydney','Cairo','Roma','Seoul','Mumbai',
  'Barcelona','Amsterdam','Vienna','Prague','Istanbul','Bangkok','Singapore','Oslo',
  'Copenhagen','Stockholm','Helsinki','Dublin','Athens','Budapest','Warsaw','Zurich',
  'Geneva','Brussels','Toronto','Chicago','Miami','Boston','Seattle','Denver','Austin',
  'Bogota','Lima','Santiago','Lagos','Nairobi','Beirut','Riyadh','Tehran','Karachi',
  'Hanoi','Jakarta','Manila','Taipei','Hong Kong','Shanghai','Beijing','Osaka','Kyoto',
  'Auckland','Melbourne','Vancouver','Montreal','Havana','Quito','Caracas','Montevideo',
];

function getInitials(name) {
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 3) return (parts[0][0] + parts[1][0] + parts[2][0]).toUpperCase();
  if (parts.length === 2) return (parts[0][0] + parts[1][0] + '0').toUpperCase();
  return (parts[0][0] + '00').toUpperCase();
}

function makeCodename(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0;
  return PLACES[Math.abs(h) % PLACES.length] + ' ' + getInitials(name);
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token obrigatório' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
}

function sanitize(u) {
  return { id: u.id, name: u.name, phone: u.phone, codename: u.codename,
    balance: u.balance, is_host: u.is_host, host_price: u.host_price,
    host_speed: u.host_speed, host_max_users: u.host_max_users,
    earnings: u.earnings, rating: u.rating, sessions_count: u.sessions_count };
}

app.post('/api/auth/signup', (req, res) => {
  const { name, phone, password } = req.body || {};
  if (!name?.trim() || !phone?.trim() || !password)
    return res.status(400).json({ error: 'Nome, telefone e senha são obrigatórios' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
  const hash = bcrypt.hashSync(password, 10);
  const codename = makeCodename(name.trim());
  try {
    const { lastInsertRowid } = db
      .prepare('INSERT INTO users (name, phone, password_hash, codename) VALUES (?,?,?,?)')
      .run(name.trim(), phone.trim(), hash, codename);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(lastInsertRowid);
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ token, user: sanitize(user) });
  } catch (e) {
    if (e.message.includes('UNIQUE'))
      return res.status(409).json({ error: 'Telefone já cadastrado' });
    res.status(500).json({ error: 'Erro interno' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password)
    return res.status(400).json({ error: 'Telefone e senha obrigatórios' });
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Telefone ou senha incorretos' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: sanitize(user) });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  res.json({ user: sanitize(user) });
});

const HOST_COLORS = ['#1D4ED8', '#0F766E', '#7C3AED', '#B45309', '#BE185D'];

app.get('/api/hosts/nearby', auth, (req, res) => {
  const hosts = db
    .prepare('SELECT * FROM users WHERE is_host = 1 AND id != ? ORDER BY RANDOM() LIMIT 6')
    .all(req.user.id);
  const result = hosts.map((h, i) => ({
    id: h.id, codename: h.codename,
    price: `R$ ${h.host_price.toFixed(2)}`, priceNum: h.host_price,
    speed: h.host_speed, signal: 2 + (i % 3),
    dist: `${8 + i * 11}m`, color: HOST_COLORS[i % HOST_COLORS.length], rating: h.rating,
  }));
  res.json({ hosts: result });
});

app.post('/api/host/toggle', auth, (req, res) => {
  const { active } = req.body;
  db.prepare('UPDATE users SET is_host = ? WHERE id = ?').run(active ? 1 : 0, req.user.id);
  res.json({ is_host: !!active });
});

app.put('/api/host/settings', auth, (req, res) => {
  const { host_price, host_speed, host_max_users } = req.body;
  db.prepare('UPDATE users SET host_price=?, host_speed=?, host_max_users=? WHERE id=?')
    .run(host_price ?? 0.08, host_speed ?? '10 MB/s', host_max_users ?? 3, req.user.id);
  res.json({ ok: true });
});

app.get('/api/host/stats', auth, (req, res) => {
  const user = db.prepare('SELECT earnings, sessions_count, rating, host_max_users FROM users WHERE id=?').get(req.user.id);
  const activeSessions = db.prepare(`
    SELECT s.id, s.started_at, s.seconds, s.mb_used, s.cost, u.codename
    FROM sessions s JOIN users u ON s.consumer_id = u.id
    WHERE s.host_id = ? AND s.ended_at IS NULL
  `).all(req.user.id);
  res.json({ ...user, activeSessions });
});

app.post('/api/sessions/start', auth, (req, res) => {
  const { host_id } = req.body;
  const consumer = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  const host = db.prepare('SELECT * FROM users WHERE id=? AND is_host=1').get(host_id);
  if (!host) return res.status(404).json({ error: 'Host não encontrado ou offline' });
  if (consumer.balance < 0.5) return res.status(400).json({ error: 'Saldo insuficiente' });
  const { lastInsertRowid } = db
    .prepare('INSERT INTO sessions (consumer_id, host_id) VALUES (?,?)')
    .run(req.user.id, host_id);
  res.json({ session_id: lastInsertRowid,
    host: { id: host.id, codename: host.codename, price: host.host_price, speed: host.host_speed } });
});

app.put('/api/sessions/:id/end', auth, (req, res) => {
  const { seconds = 0, mb_used = 0 } = req.body;
  const session = db.prepare('SELECT * FROM sessions WHERE id=? AND consumer_id=? AND ended_at IS NULL')
    .get(req.params.id, req.user.id);
  if (!session) return res.status(404).json({ error: 'Sessão não encontrada' });
  const host = db.prepare('SELECT * FROM users WHERE id=?').get(session.host_id);
  const cost = Math.max(0, (seconds / 60) * host.host_price);
  db.prepare("UPDATE sessions SET ended_at=datetime('now'), seconds=?, mb_used=?, cost=? WHERE id=?")
    .run(seconds, mb_used, cost, session.id);
  db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(cost, req.user.id);
  db.prepare('INSERT INTO transactions (user_id,type,amount,description,ref_id) VALUES (?,?,?,?,?)')
    .run(req.user.id, 'debit', cost, `Sessão com ${host.codename}`, session.id);
  const hostCut = cost * 0.8;
  db.prepare('UPDATE users SET balance=balance+?, earnings=earnings+?, sessions_count=sessions_count+1 WHERE id=?')
    .run(hostCut, hostCut, session.host_id);
  db.prepare('INSERT INTO transactions (user_id,type,amount,description,ref_id) VALUES (?,?,?,?,?)')
    .run(session.host_id, 'credit', hostCut,
      `Sessão com ${db.prepare('SELECT codename FROM users WHERE id=?').get(req.user.id).codename}`, session.id);
  const newBalance = db.prepare('SELECT balance FROM users WHERE id=?').get(req.user.id).balance;
  res.json({ cost, new_balance: newBalance, seconds, mb_used });
});

app.get('/api/wallet', auth, (req, res) => {
  const user = db.prepare('SELECT balance FROM users WHERE id=?').get(req.user.id);
  const transactions = db.prepare(
    'SELECT * FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 30'
  ).all(req.user.id);
  res.json({ balance: user.balance, transactions });
});

app.post('/api/wallet/deposit', auth, (req, res) => {
  const { amount, method = 'Pix' } = req.body;
  if (!amount || amount <= 0 || amount > 1000)
    return res.status(400).json({ error: 'Valor inválido (máx R$ 1000)' });
  db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(amount, req.user.id);
  db.prepare('INSERT INTO transactions (user_id,type,amount,description) VALUES (?,?,?,?)')
    .run(req.user.id, 'credit', amount, `Recarga via ${method}`);
  const { balance } = db.prepare('SELECT balance FROM users WHERE id=?').get(req.user.id);
  res.json({ balance });
});

app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`\n🛜  WifiMe rodando em http://localhost:${PORT}\n`));

const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const sms = require('./smsService');

const pbkdf2 = promisify(crypto.pbkdf2);
const SECRET = process.env.JWT_SECRET || (console.warn('JWT_SECRET not set: using a random one (sessions reset on restart)'), crypto.randomBytes(32).toString('hex'));
const PHONE_SALT = 'anon-e2ee-messenger/phone-salt/v1'; // must match public/crypto.js
const OTP_TTL = 5 * 60 * 1000;

// ---- Storage: only hashes, public keys, ciphertext ----
const db = new Database(process.env.DB_FILE || path.join(__dirname, 'relay.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(phoneHash TEXT PRIMARY KEY, publicKeyJwk TEXT);
CREATE TABLE IF NOT EXISTS queue(id INTEGER PRIMARY KEY AUTOINCREMENT, toHash TEXT, fromHash TEXT, type TEXT, iv TEXT, data TEXT, ts INTEGER);`);
const otps = new Map(); // phoneHash -> { otpHash, expiresAt, attempts, lastSent }  (RAM only)

const logs = [];
const log = (s) => { logs.push(`[${new Date().toISOString().slice(11, 19)}] ${s}`); if (logs.length > 80) logs.shift(); console.log(s); };
const short = (h) => (h || '').slice(0, 8) + '…';
const normPhone = (p) => String(p || '').replace(/[^\d+]/g, '');
const hashPhone = async (p) => (await pbkdf2(p, PHONE_SALT, 100000, 32, 'sha256')).toString('base64');
const hashOtp = (otp, ph) => crypto.createHash('sha256').update(otp + ':' + ph).digest('hex');

// ---- Minimal HS256 JWT (no dependency) ----
const sign = (payload) => {
  const h = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'), b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${h}.${b}.${crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64url')}`;
};
const verifyJwt = (t) => {
  try {
    const [h, b, s] = String(t).split('.');
    const e = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64url');
    if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url'));
    return p.exp > Date.now() / 1000 ? p : null;
  } catch { return null; }
};
const auth = (req, res, next) => {
  const p = verifyJwt((req.headers.authorization || '').replace('Bearer ', ''));
  if (!p) return res.status(401).json({ error: 'unauthorized' });
  req.hash = p.sub; next();
};

const app = express();
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/api/config', (_req, res) => res.json({ sms: sms.provider, simulated: sms.simulated }));

// ---- OTP login ----
app.post('/api/auth/request-otp', async (req, res) => {
  const phone = normPhone(req.body?.phone);
  if (phone.length < 8 || phone.length > 16) return res.status(400).json({ error: 'invalid phone' });
  const ph = await hashPhone(phone);
  const prev = otps.get(ph);
  if (prev && Date.now() - prev.lastSent < 30000) return res.status(429).json({ error: 'wait 30s before requesting another code' });
  const otp = String(crypto.randomInt(100000, 1000000));
  try { await sms.send(phone, ph, otp); } catch (e) { log('SMS failed: ' + e.message); return res.status(502).json({ error: 'sms failed' }); }
  otps.set(ph, { otpHash: hashOtp(otp, ph), expiresAt: Date.now() + OTP_TTL, attempts: 0, lastSent: Date.now() });
  log(`OTP issued for ${short(ph)} (phone discarded)`);
  res.json({ ok: true });
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const ph = await hashPhone(normPhone(req.body?.phone));
  const rec = otps.get(ph), otp = String(req.body?.otp || '');
  if (!rec || rec.expiresAt < Date.now() || ++rec.attempts > 5) { otps.delete(ph); return res.status(401).json({ error: 'code expired or too many attempts' }); }
  const a = Buffer.from(hashOtp(otp, ph)), b = Buffer.from(rec.otpHash);
  if (!crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'wrong code' });
  otps.delete(ph);
  log(`LOGIN ${short(ph)}`);
  res.json({ token: sign({ sub: ph, exp: Math.floor(Date.now() / 1000) + 7 * 86400 }) });
});

// ---- Key directory ----
app.post('/api/keys', auth, (req, res) => {
  if (!req.body?.publicKeyJwk) return res.status(400).end();
  db.prepare('INSERT OR REPLACE INTO users VALUES (?,?)').run(req.hash, JSON.stringify(req.body.publicKeyJwk));
  log(`PUBKEY ${short(req.hash)}`); res.json({ ok: true });
});
app.get('/api/key/:hash', auth, (req, res) => {
  const row = db.prepare('SELECT publicKeyJwk FROM users WHERE phoneHash=?').get(req.params.hash);
  row ? res.json({ publicKeyJwk: JSON.parse(row.publicKeyJwk) }) : res.status(404).json({ error: 'not found' });
});

// ---- Demo tools ----
app.get('/api/sim-sms/:hash', (req, res) => sms.simulated ? res.json(sms.inbox.get(req.params.hash) || []) : res.status(404).end());
app.get('/api/inspect', (_req, res) => res.json({
  users: db.prepare('SELECT phoneHash FROM users').all().map((u) => u.phoneHash),
  online: [...online.keys()],
  pendingOtps: [...otps].map(([k, v]) => ({ phoneHash: k, otpHash: v.otpHash.slice(0, 16) + '…', expiresInSec: Math.max(0, Math.round((v.expiresAt - Date.now()) / 1000)) })),
  queue: db.prepare('SELECT * FROM queue ORDER BY id DESC LIMIT 15').all(),
  log: logs.slice(-40),
}));

// ---- Blind relay over WebSocket: envelope { to, from, type, iv, data } ----
const online = new Map();
function deliver(r) {
  const ws = online.get(r.toHash);
  if (!ws || ws.readyState !== 1) return;
  ws.send(JSON.stringify({ to: r.toHash, from: r.fromHash, type: r.type, iv: r.iv, data: r.data, ts: r.ts }));
  db.prepare('DELETE FROM queue WHERE id=?').run(r.id);
  log(`DELIVERED+DELETED ${r.type} ${short(r.fromHash)} → ${short(r.toHash)}`);
}
const server = http.createServer(app);
new WebSocketServer({ server }).on('connection', (ws) => {
  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.type === 'auth') {
      const p = verifyJwt(m.token); if (!p) return ws.close();
      ws.hash = p.sub; online.set(ws.hash, ws); log(`ONLINE ${short(ws.hash)}`);
      db.prepare('SELECT * FROM queue WHERE toHash=? ORDER BY id').all(ws.hash).forEach((r) => deliver({ ...r }));
    } else if (ws.hash && typeof m.to === 'string' && ['hs', 'ack', 'msg'].includes(m.type)) {
      const ts = Date.now(), iv = String(m.iv || ''), data = String(m.data || '');
      if (data.length > 20000) return;
      const id = db.prepare('INSERT INTO queue(toHash,fromHash,type,iv,data,ts) VALUES (?,?,?,?,?,?)').run(m.to, ws.hash, m.type, iv, data, ts).lastInsertRowid;
      log(`RELAY ${m.type} ${short(ws.hash)} → ${short(m.to)} data=${data.slice(0, 24)}…`); // "from" is always set by the server
      deliver({ id, toHash: m.to, fromHash: ws.hash, type: m.type, iv, data, ts });
    }
  });
  ws.on('close', () => { if (ws.hash && online.get(ws.hash) === ws) { online.delete(ws.hash); log(`OFFLINE ${short(ws.hash)}`); } });
});

server.listen(process.env.PORT || 3000, () => console.log(`Running on :${process.env.PORT || 3000} (SMS provider: ${sms.provider})`));

// Blind relay: stores only hashed IDs, public keys and opaque ciphertext.
const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, 'relay.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(phoneHash TEXT PRIMARY KEY, publicKeyJwk TEXT);
CREATE TABLE IF NOT EXISTS queue(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  toPhoneHash TEXT, fromPhoneHash TEXT, kind TEXT,
  iv TEXT, ciphertext TEXT, timestamp INTEGER);`);

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const online = new Map(); // phoneHash -> ws
const logs = [];
const log = (s) => { logs.push(`[${new Date().toISOString().slice(11, 19)}] ${s}`); if (logs.length > 80) logs.shift(); console.log(s); };
const short = (h) => (h || '').slice(0, 8) + '…';
const okHash = (h) => typeof h === 'string' && h.length > 20 && h.length < 100;

app.post('/api/register', (req, res) => {
  const { phoneHash, publicKeyJwk } = req.body || {};
  if (!okHash(phoneHash) || !publicKeyJwk) return res.status(400).json({ error: 'bad request' });
  db.prepare('INSERT OR REPLACE INTO users VALUES (?,?)').run(phoneHash, JSON.stringify(publicKeyJwk));
  log(`REGISTER ${short(phoneHash)} pubkey.x=${short(publicKeyJwk.x)}`);
  res.json({ ok: true });
});

app.get('/api/key/:hash', (req, res) => {
  const row = db.prepare('SELECT publicKeyJwk FROM users WHERE phoneHash=?').get(req.params.hash);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ publicKeyJwk: JSON.parse(row.publicKeyJwk) });
});

// Server Inspector: exactly what the server can see.
app.get('/api/inspect', (_req, res) => {
  res.json({
    users: db.prepare('SELECT phoneHash, publicKeyJwk FROM users').all().map(u => ({ phoneHash: u.phoneHash, pubX: JSON.parse(u.publicKeyJwk).x })),
    queue: db.prepare('SELECT * FROM queue ORDER BY id DESC LIMIT 20').all(),
    online: [...online.keys()],
    log: logs.slice(-40),
  });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

function deliver(row) {
  const ws = online.get(row.toPhoneHash);
  if (!ws || ws.readyState !== 1) return false;
  ws.send(JSON.stringify({ t: 'msg', from: row.fromPhoneHash, kind: row.kind, iv: row.iv, ct: row.ciphertext, ts: row.timestamp }));
  db.prepare('DELETE FROM queue WHERE id=?').run(row.id); // delete immediately after delivery
  log(`DELIVERED+DELETED ${row.kind} ${short(row.fromPhoneHash)} → ${short(row.toPhoneHash)}`);
  return true;
}

wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    let m; try { m = JSON.parse(data); } catch { return; }
    if (m.t === 'auth' && okHash(m.phoneHash)) {
      ws.hash = m.phoneHash; online.set(m.phoneHash, ws);
      log(`ONLINE ${short(m.phoneHash)}`);
      for (const row of db.prepare('SELECT * FROM queue WHERE toPhoneHash=? ORDER BY id').all(m.phoneHash)) deliver(row);
    } else if (m.t === 'send' && ws.hash && okHash(m.to) && ['hs', 'ack', 'msg'].includes(m.kind)) {
      const ts = Date.now();
      const info = db.prepare('INSERT INTO queue(toPhoneHash,fromPhoneHash,kind,iv,ciphertext,timestamp) VALUES (?,?,?,?,?,?)')
        .run(m.to, ws.hash, m.kind, String(m.iv || ''), String(m.ct || ''), ts);
      log(`RELAY ${m.kind} ${short(ws.hash)} → ${short(m.to)} iv=${String(m.iv || '').slice(0, 10)}… ct=${String(m.ct || '').slice(0, 24)}…`);
      deliver({ id: info.lastInsertRowid, toPhoneHash: m.to, fromPhoneHash: ws.hash, kind: m.kind, iv: m.iv || '', ciphertext: m.ct || '', timestamp: ts });
    }
  });
  ws.on('close', () => { if (ws.hash && online.get(ws.hash) === ws) { online.delete(ws.hash); log(`OFFLINE ${short(ws.hash)}`); } });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Messenger running at http://localhost:${PORT}`));

const $ = (id) => document.getElementById(id);
let TOKEN = sessionStorage.getItem('token'), ME = null, V = null, PIN = null, T = null;
let cur = null, hs = null, tick = null, simHash = null, smsTimer = null, inspTimer = null;
const show = (id) => ['login', 'vault', 'app'].forEach((s) => $(s).classList.toggle('hidden', s !== id));
const api = (u, body) => fetch(u, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN }, body: body && JSON.stringify(body) });
const jwt = (t) => { try { const p = JSON.parse(atob(t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); return p.exp * 1000 > Date.now() ? p : null; } catch { return null; } };
const vaultKey = () => 'vault:' + ME;
const save = async () => localStorage.setItem(vaultKey(), JSON.stringify(await C.seal(PIN, V)));
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

// ---------- 1. OTP login ----------
let otpStep = false;
$('loginbtn').onclick = async () => {
  const phone = $('phone').value.trim(), msg = (t) => ($('loginmsg').textContent = t);
  if (phone.replace(/\D/g, '').length < 8) return msg('Enter your phone number with country code.');
  $('loginbtn').disabled = true; msg('');
  try {
    if (!otpStep) {
      const r = await fetch('/api/auth/request-otp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone }) });
      if (!r.ok) return msg((await r.json()).error);
      simHash = await C.phoneHash(phone); // lets the simulated inbox find this login's SMS
      otpStep = true; $('otp').classList.remove('hidden'); $('loginbtn').textContent = 'Verify code';
      msg('Code sent. Check the SMS inbox if you are testing.');
    } else {
      const r = await fetch('/api/auth/verify-otp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone, otp: $('otp').value.trim() }) });
      const d = await r.json(); if (!r.ok) return msg(d.error);
      TOKEN = d.token; sessionStorage.setItem('token', TOKEN);
      $('phone').value = ''; $('otp').value = ''; // plaintext number is not kept
      toVault();
    }
  } finally { $('loginbtn').disabled = false; }
};

// ---------- 2. Local encrypted vault ----------
function toVault() {
  ME = jwt(TOKEN).sub; show('vault');
  const exists = !!localStorage.getItem(vaultKey());
  $('alias').classList.toggle('hidden', exists);
  $('vtitle').textContent = exists ? 'Unlock your vault' : 'Create your vault';
  $('vbtn').textContent = exists ? 'Unlock' : 'Create vault';
}
$('vbtn').onclick = async () => {
  const pin = $('pin').value, msg = (t) => ($('vmsg').textContent = t);
  if (pin.length < 4) return msg('Use a PIN of at least 4 characters.');
  if (localStorage.getItem(vaultKey())) {
    try { V = await C.open(pin, JSON.parse(localStorage.getItem(vaultKey()))); } catch { return msg('Wrong PIN.'); }
  } else {
    const alias = $('alias').value.trim(); if (!alias) return msg('Choose an alias.');
    const kp = await C.genKeys();
    const r = await api('/api/keys', { publicKeyJwk: kp.pub }); if (!r.ok) return msg('Session expired. Sign in again.');
    V = { alias, privateKeyJwk: kp.priv, publicKeyJwk: kp.pub, contacts: {}, messages: {} };
    PIN = pin; await save();
  }
  PIN = pin; $('pin').value = ''; start();
};

function start() {
  show('app'); $('me').textContent = V.alias; $('myhash').textContent = 'ID ' + ME.slice(0, 12) + '…';
  T = new WebSocketTransport(); // swap for new LoRaSerialTransport() in Phase 2
  T.onPacket(onPacket); T.onStatus((s) => ($('status').textContent = V.contacts[cur] ? (s === 'online' ? 'end-to-end encrypted' : 'offline, reconnecting…') : ''));
  T.connect({ token: TOKEN }); render();
}
$('logout').onclick = () => { T?.close(); sessionStorage.removeItem('token'); location.reload(); };
const out = (to, type, extra = {}) => T.sendPacket({ to, from: ME, type, iv: '', data: '', ...extra });

// ---------- 3. Incoming packets ----------
async function onPacket(p) {
  if (p.type === 'hs') return beginHandshake(p.from, false);
  if (p.type === 'ack') { if (hs && hs.peer === p.from) hs.key ? verifyAck(p) : (hs.ack = p); return; }
  const c = V.contacts[p.from]; if (!c || p.type !== 'msg') return; // ignore unverified senders
  try {
    (V.messages[p.from] ||= []).push({ me: false, text: await C.dec(c.key, p.iv, p.data), ts: p.ts || Date.now() });
    await save(); render();
  } catch { /* undecryptable: drop */ }
}

// ---------- 4. Alphanumeric mutual handshake ----------
$('newbtn').onclick = async () => {
  const phone = $('newphone').value.trim(); if (!phone || hs) return;
  const peer = await C.phoneHash(phone);
  if (peer === ME) return alert('That is your own number.');
  if (await beginHandshake(peer, true)) { out(peer, 'hs'); $('newphone').value = ''; }
};
async function beginHandshake(peer, outgoing) {
  if (hs) return false;
  const r = await api('/api/key/' + encodeURIComponent(peer));
  if (!r.ok) { alert('No user registered with that number.'); return false; }
  hs = { peer, pub: (await r.json()).publicKeyJwk, code: C.code(), end: Date.now() + 90000, key: null, ack: null, name: V.contacts[peer]?.alias || '' };
  $('mtitle').textContent = outgoing ? 'Verify the contact you are adding' : 'Incoming verification request';
  $('mcode').textContent = C.fmtCode(hs.code); $('mname').value = hs.name;
  $('mtheir').value = ''; $('mown').value = ''; $('mstat').textContent = '';
  $('modal').classList.remove('hidden'); clearInterval(tick); tick = setInterval(countdown, 500); countdown();
  return true;
}
function countdown() {
  if (!hs) return;
  const left = Math.ceil((hs.end - Date.now()) / 1000);
  if (left <= 0) { closeHs(); return alert('Verification expired. Start again.'); }
  $('mcount').textContent = `Expires in ${left}s`;
}
function closeHs() { clearInterval(tick); hs = null; $('modal').classList.add('hidden'); }
$('mcancel').onclick = closeHs;

$('mok').onclick = async () => {
  if (!hs) return;
  const theirs = C.normCode($('mtheir').value), own = C.normCode($('mown').value), name = $('mname').value.trim();
  const st = (t) => ($('mstat').textContent = t);
  if (!name) return st('Give this contact a name.');
  if (!C.validCode(theirs)) return st("Enter your contact's 6-character code.");
  if (own !== hs.code) return st('Your own code does not match the one on screen.');
  hs.name = name;
  hs.key = await C.sharedKey(V.privateKeyJwk, hs.pub, hs.code, theirs);
  out(hs.peer, 'ack', await C.enc(hs.key, 'HANDSHAKE_ACK'));
  st("Waiting for your contact's confirmation…");
  if (hs.ack) verifyAck(hs.ack);
};
async function verifyAck(p) {
  try { if ((await C.dec(hs.key, p.iv, p.data)) !== 'HANDSHAKE_ACK') throw 0; }
  catch { hs.ack = null; hs.key = null; return ($('mstat').textContent = 'Verification failed: the codes do not match. Check them and try again.'); }
  V.contacts[hs.peer] = { alias: hs.name, key: hs.key, pub: hs.pub };
  V.messages[hs.peer] ||= []; cur = hs.peer; await save(); closeHs(); render();
}

// ---------- 5. Chat ----------
$('form').onsubmit = async (e) => {
  e.preventDefault();
  const text = $('text').value.trim(), c = V.contacts[cur]; if (!text || !c) return;
  out(cur, 'msg', await C.enc(c.key, text));
  V.messages[cur].push({ me: true, text, ts: Date.now() });
  $('text').value = ''; await save(); render();
};
function render() {
  const list = $('contacts'); list.innerHTML = '';
  const ids = Object.keys(V.contacts);
  if (!ids.length) list.innerHTML = '<p class="dim">No verified contacts yet.</p>';
  ids.forEach((id) => {
    const d = document.createElement('div'); d.className = 'ct' + (id === cur ? ' on' : ''); d.textContent = V.contacts[id].alias;
    d.onclick = () => { cur = id; render(); }; list.appendChild(d);
  });
  const c = V.contacts[cur], box = $('msgs');
  $('form').classList.toggle('hidden', !c); $('peer').textContent = c ? c.alias : 'No chat selected';
  $('status').textContent = c ? 'end-to-end encrypted' : '';
  if (!c) return;
  box.innerHTML = '';
  (V.messages[cur] || []).forEach((m) => {
    const d = document.createElement('div'); d.className = 'b' + (m.me ? ' me' : ''); d.textContent = m.text;
    const t = document.createElement('small'); t.textContent = new Date(m.ts).toLocaleTimeString(); d.appendChild(t); box.appendChild(d);
  });
  box.scrollTop = box.scrollHeight;
}

// ---------- 6. Demo tools: simulated SMS inbox + blind server inspector ----------
fetch('/api/config').then((r) => r.json()).then((c) => { if (!c.simulated) $('smsbtn').classList.add('hidden'); });
function toggle(id, fn, ms) {
  const el = $(id); el.classList.toggle('hidden');
  const timer = id === 'sms' ? 'smsTimer' : 'inspTimer';
  clearInterval(window[timer] ?? (id === 'sms' ? smsTimer : inspTimer));
  const t = !el.classList.contains('hidden') ? (fn(), setInterval(fn, ms)) : null;
  id === 'sms' ? (smsTimer = t) : (inspTimer = t);
}
$('smsbtn').onclick = () => toggle('sms', pollSms, 1500);
$('inspbtn').onclick = () => toggle('insp', pollInsp, 1500);
async function pollSms() {
  const h = ME || simHash, el = $('sms');
  if (!h) return (el.innerHTML = '<h3>Simulated SMS inbox</h3><p class="dim">Request a code first. Messages for that number appear here.</p>');
  const msgs = await (await fetch('/api/sim-sms/' + encodeURIComponent(h))).json();
  el.innerHTML = '<h3>Simulated SMS inbox</h3>' + (msgs.map((m) => `<div class="sms">${esc(m.text)}<div class="dim">${new Date(m.ts).toLocaleTimeString()}</div></div>`).join('') || '<p class="dim">No messages yet.</p>');
}
async function pollInsp() {
  const d = await (await fetch('/api/inspect')).json();
  $('insp').innerHTML = '<h3>What the server sees</h3><pre>Hashed IDs, public keys, OTP hashes, ciphertext. No phone numbers, names or plaintext.</pre>' +
    `<h3>Users (hashed)</h3><pre>${esc(d.users.map((u) => u + (d.online.includes(u) ? '  [online]' : '')).join('\n') || '-')}</pre>` +
    `<h3>Pending OTPs (RAM)</h3><pre>${esc(d.pendingOtps.map((o) => `${o.phoneHash.slice(0, 12)}… otpHash=${o.otpHash} ttl=${o.expiresInSec}s`).join('\n') || 'none')}</pre>` +
    `<h3>Offline queue (ciphertext)</h3><pre>${esc(d.queue.map((q) => `#${q.id} ${q.type} ${q.fromHash.slice(0, 8)}→${q.toHash.slice(0, 8)}\niv=${q.iv}\ndata=${q.data}`).join('\n\n') || 'empty')}</pre>` +
    `<h3>Relay log</h3><pre>${esc(d.log.join('\n'))}</pre>`;
}

// ---------- Boot ----------
if (TOKEN && jwt(TOKEN)) toVault(); else show('login');

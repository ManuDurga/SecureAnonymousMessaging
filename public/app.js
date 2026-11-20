const $ = (id) => document.getElementById(id);
// Use a URL hash to run several identities in one browser: http://localhost:3000/#alice
const slot = 'vault' + (location.hash || '');
let V = null, PIN = null, ws = null, cur = null, hs = null, tick = null, inspTimer = null;
const hasVault = () => !!localStorage.getItem(slot);
const save = async () => localStorage.setItem(slot, JSON.stringify(await C.seal(PIN, V)));
const send = (o) => ws && ws.readyState === 1 && ws.send(JSON.stringify(o));
const post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });

// ---------- Registration / unlock ----------
if (hasVault()) {
  $('alias').classList.add('hidden'); $('phone').classList.add('hidden');
  $('go').textContent = 'Unlock vault'; $('authhint').textContent = 'Enter your Local Vault PIN to decrypt your identity, contacts and chats.';
}
$('go').onclick = async () => {
  const pin = $('pin').value, msg = (t) => ($('authmsg').textContent = t);
  if (!pin) return msg('Enter a PIN.');
  $('go').disabled = true;
  try {
    if (hasVault()) {
      try { V = await C.open(pin, JSON.parse(localStorage.getItem(slot))); } catch { return msg('Wrong PIN.'); }
    } else {
      const alias = $('alias').value.trim(), phone = $('phone').value.trim();
      if (!alias || !phone) return msg('Enter an alias and a phone number.');
      const kp = await C.genKeys(), phoneHash = await C.phoneHash(phone);
      const r = await post('/api/register', { phoneHash, publicKeyJwk: kp.pub });
      if (!r.ok) return msg('Could not reach the server.');
      V = { alias, phoneNumber: phone, phoneHash, privateKeyJwk: kp.priv, publicKeyJwk: kp.pub, contacts: {}, messages: {} };
      PIN = pin; await save();
    }
    PIN = pin; start();
  } finally { $('go').disabled = false; }
};

function start() {
  $('auth').classList.add('hidden'); $('app').classList.remove('hidden');
  $('me').textContent = V.alias; $('myhash').textContent = 'ID ' + V.phoneHash.slice(0, 12) + '…';
  document.title = V.alias + ' – Anon Messenger';
  connect(); render();
}
function connect() {
  ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
  ws.onopen = () => send({ t: 'auth', phoneHash: V.phoneHash });
  ws.onmessage = (e) => onMsg(JSON.parse(e.data));
  ws.onclose = () => { $('status').textContent = 'reconnecting…'; setTimeout(connect, 2000); };
}

// ---------- Incoming relay traffic ----------
async function onMsg(m) {
  if (m.t !== 'msg') return;
  if (m.kind === 'hs') return beginHandshake(m.from, null);
  if (m.kind === 'ack') {
    if (!hs || hs.peer !== m.from) return;
    return hs.key ? verifyAck(m) : (hs.ack = m);
  }
  const c = V.contacts[m.from];
  if (!c) return; // unverified sender: ignore
  try {
    const text = await C.dec(c.key, m.iv, m.ct);
    (V.messages[m.from] ||= []).push({ me: false, text, ts: m.ts });
    await save(); render();
  } catch { /* undecryptable: drop */ }
}

// ---------- Mutual OTP handshake ----------
$('newbtn').onclick = async () => {
  const phone = $('newphone').value.trim(); if (!phone || hs) return;
  const peer = await C.phoneHash(phone);
  if (peer === V.phoneHash) return alert('That is your own number.');
  const ok = await beginHandshake(peer, true);
  if (ok) { send({ t: 'send', to: peer, kind: 'hs' }); $('newphone').value = ''; }
};

async function beginHandshake(peer, outgoing) {
  if (hs) return false;
  const r = await fetch('/api/key/' + encodeURIComponent(peer));
  if (!r.ok) { alert('No user registered with that number.'); return false; }
  const pub = (await r.json()).publicKeyJwk;
  hs = { peer, pub, otp: C.otp(), end: Date.now() + 90000, key: null, ack: null, name: V.contacts[peer]?.alias || '' };
  $('mtitle').textContent = outgoing ? 'Verify the contact you are adding' : 'Incoming verification request';
  $('motp').textContent = hs.otp; $('mname').value = hs.name;
  $('mtheir').value = ''; $('mown').value = ''; $('mstat').textContent = '';
  $('modal').classList.remove('hidden');
  clearInterval(tick); tick = setInterval(countdown, 500); countdown();
  return true;
}
function countdown() {
  if (!hs) return;
  const left = Math.ceil((hs.end - Date.now()) / 1000);
  if (left <= 0) { $('mstat').textContent = ''; closeHs(); return alert('Handshake expired. Start again.'); }
  $('mcount').textContent = `Expires in ${left}s`;
}
function closeHs() { clearInterval(tick); hs = null; $('modal').classList.add('hidden'); }
$('mcancel').onclick = closeHs;

$('mok').onclick = async () => {
  if (!hs) return;
  const theirs = $('mtheir').value.trim(), own = $('mown').value.trim(), name = $('mname').value.trim();
  const st = (t) => ($('mstat').textContent = t);
  if (!name) return st('Give this contact a name.');
  if (!/^\d{6}$/.test(theirs)) return st("Enter the contact's 6-digit code.");
  if (own !== hs.otp) return st('Your own code does not match the one on screen.');
  hs.name = name;
  hs.key = await C.sharedKey(V.privateKeyJwk, hs.pub, hs.otp, theirs); // salt = sorted OTPs
  const { iv, ct } = await C.enc(hs.key, 'HANDSHAKE_ACK');
  send({ t: 'send', to: hs.peer, kind: 'ack', iv, ct });
  st("Waiting for your contact's confirmation…");
  if (hs.ack) verifyAck(hs.ack);
};

async function verifyAck(m) {
  try {
    if ((await C.dec(hs.key, m.iv, m.ct)) !== 'HANDSHAKE_ACK') throw 0;
  } catch {
    hs.ack = null; hs.key = null;
    return ($('mstat').textContent = 'Verification failed: the codes do not match. Check them and try again.');
  }
  V.contacts[hs.peer] = { alias: hs.name, key: hs.key, pub: hs.pub };
  V.messages[hs.peer] ||= [];
  cur = hs.peer; await save(); closeHs(); render();
}

// ---------- Chat ----------
$('form').onsubmit = async (e) => {
  e.preventDefault();
  const text = $('text').value.trim(), c = V.contacts[cur]; if (!text || !c) return;
  const { iv, ct } = await C.enc(c.key, text);
  send({ t: 'send', to: cur, kind: 'msg', iv, ct });
  V.messages[cur].push({ me: true, text, ts: Date.now() });
  $('text').value = ''; await save(); render();
};

function render() {
  const list = $('contacts'); list.innerHTML = '';
  const ids = Object.keys(V.contacts);
  if (!ids.length) list.innerHTML = '<p class="dim">No verified contacts yet.</p>';
  ids.forEach((id) => {
    const d = document.createElement('div');
    d.className = 'ct' + (id === cur ? ' on' : ''); d.textContent = V.contacts[id].alias;
    d.onclick = () => { cur = id; render(); };
    list.appendChild(d);
  });
  const box = $('msgs'), c = V.contacts[cur];
  $('form').classList.toggle('hidden', !c);
  $('peer').textContent = c ? c.alias : 'No chat selected';
  $('status').textContent = c ? 'end-to-end encrypted' : '';
  if (!c) return;
  box.innerHTML = '';
  (V.messages[cur] || []).forEach((m) => {
    const d = document.createElement('div'); d.className = 'b' + (m.me ? ' me' : '');
    d.textContent = m.text;
    const t = document.createElement('small'); t.textContent = new Date(m.ts).toLocaleTimeString();
    d.appendChild(t); box.appendChild(d);
  });
  box.scrollTop = box.scrollHeight;
}

// ---------- Server inspector ----------
$('inspbtn').onclick = () => {
  const el = $('insp'); el.classList.toggle('hidden');
  clearInterval(inspTimer);
  if (!el.classList.contains('hidden')) { pollInspector(); inspTimer = setInterval(pollInspector, 1500); }
};
async function pollInspector() {
  const d = await (await fetch('/api/inspect')).json();
  const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  $('insp').innerHTML =
    '<h3>What the server sees</h3><pre>No names, no phone numbers, no plaintext.</pre>' +
    `<h3>Users (hashed IDs)</h3><pre>${d.users.map((u) => esc(u.phoneHash + (d.online.includes(u.phoneHash) ? '  [online]' : ''))).join('\n') || '-'}</pre>` +
    `<h3>Offline queue (ciphertext only)</h3><pre>${d.queue.map((q) => esc(`#${q.id} ${q.kind} ${q.fromPhoneHash.slice(0, 8)}→${q.toPhoneHash.slice(0, 8)}\niv=${q.iv}\nct=${q.ciphertext}`)).join('\n\n') || 'empty'}</pre>` +
    `<h3>Relay log</h3><pre>${esc(d.log.join('\n'))}</pre>`;
}

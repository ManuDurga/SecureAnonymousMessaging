// Pluggable SMS delivery. Select with SMS_PROVIDER = simulated (default) | twilio | fast2sms
// The plaintext phone number is used for the send call only. Nothing here persists it.
const provider = (process.env.SMS_PROVIDER || 'simulated').toLowerCase();
const inbox = new Map(); // phoneHash -> [{ text, ts }]  (simulated mode only; no phone stored)

async function send(phone, phoneHash, otp) {
  const text = `Your Anon Messenger code is ${otp}. It expires in 5 minutes.`;

  if (provider === 'twilio') {
    const { TWILIO_SID: sid, TWILIO_TOKEN: tok, TWILIO_FROM: from } = process.env;
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(`${sid}:${tok}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ To: phone, From: from, Body: text }),
    });
    if (!r.ok) throw new Error('Twilio error ' + r.status);
    return;
  }

  if (provider === 'fast2sms') { // India; route "otp" needs a funded account
    const r = await fetch('https://www.fast2sms.com/dev/bulkV2', {
      method: 'POST',
      headers: { authorization: process.env.FAST2SMS_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ route: 'otp', variables_values: otp, numbers: phone.replace(/\D/g, '').slice(-10) }),
    });
    if (!r.ok) throw new Error('Fast2SMS error ' + r.status);
    return;
  }

  // ---- Simulated inbox (free testing). Add another provider by adding a branch above. ----
  console.log(`[SIMULATED SMS] ${text}`);
  const list = inbox.get(phoneHash) || [];
  list.unshift({ text, ts: Date.now() });
  inbox.set(phoneHash, list.slice(0, 5));
  setTimeout(() => { const l = inbox.get(phoneHash); if (l) { l.pop(); if (!l.length) inbox.delete(phoneHash); } }, 5 * 60 * 1000).unref();
}

module.exports = { send, inbox, provider, simulated: provider === 'simulated' };

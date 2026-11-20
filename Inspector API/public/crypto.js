// Native Web Crypto only.
const S = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const PHONE_SALT = 'anon-e2ee-messenger/phone-salt/v1'; // must match server.js
const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // 32 symbols, no 0/O/1/I

async function pbkdf2(str, salt, bits = 256) {
  const k = await S.importKey('raw', enc.encode(str), 'PBKDF2', false, ['deriveBits']);
  return S.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: typeof salt === 'string' ? enc.encode(salt) : salt, iterations: 100000 }, k, bits);
}
const aesKey = (raw, use) => S.importKey('raw', raw, 'AES-GCM', false, use);

const C = {
  phoneHash: async (phone) => b64(await pbkdf2(phone.replace(/[^\d+]/g, ''), PHONE_SALT)),
  async genKeys() {
    const kp = await S.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return { pub: await S.exportKey('jwk', kp.publicKey), priv: await S.exportKey('jwk', kp.privateKey) };
  },
  // 6 chars from a 32-symbol alphabet (256 % 32 == 0, so masking is unbiased)
  code: () => [...crypto.getRandomValues(new Uint8Array(6))].map((b) => ALPHABET[b & 31]).join(''),
  normCode: (s) => s.toUpperCase().replace(/[^A-Z0-9]/g, ''),
  validCode: (s) => new RegExp(`^[${ALPHABET}]{6}$`).test(s),
  fmtCode: (c) => c.slice(0, 3) + '-' + c.slice(3),
  async enc(keyB64, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await S.encrypt({ name: 'AES-GCM', iv }, await aesKey(unb64(keyB64), ['encrypt']), enc.encode(text));
    return { iv: b64(iv), data: b64(ct) };
  },
  async dec(keyB64, iv, data) {
    return dec.decode(await S.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await aesKey(unb64(keyB64), ['decrypt']), unb64(data)));
  },
  // sharedAesKey = HKDF(ECDH(myPriv, peerPub), salt = sorted codes joined by ":")
  async sharedKey(myPrivJwk, peerPubJwk, codeA, codeB) {
    const priv = await S.importKey('jwk', myPrivJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const pub = await S.importKey('jwk', peerPubJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const secret = await S.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
    const hk = await S.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    const salt = enc.encode([codeA, codeB].sort().join(':'));
    return b64(await S.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('e2ee-v2') }, hk, 256));
  },
  async seal(pin, obj) {
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await S.encrypt({ name: 'AES-GCM', iv }, await aesKey(await pbkdf2(pin, salt), ['encrypt']), enc.encode(JSON.stringify(obj)));
    return { salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  },
  async open(pin, blob) { // throws on wrong PIN
    const pt = await S.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, await aesKey(await pbkdf2(pin, unb64(blob.salt)), ['decrypt']), unb64(blob.ct));
    return JSON.parse(dec.decode(pt));
  },
};

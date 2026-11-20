// Client-side crypto using only the native Web Crypto API.
const S = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const APP_SALT = 'anon-e2ee-messenger/phone-salt/v1';

async function pbkdf2(str, salt, bits = 256) {
  const k = await S.importKey('raw', enc.encode(str), 'PBKDF2', false, ['deriveBits']);
  return S.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, k, bits);
}
const aesKey = (raw, use) => S.importKey('raw', raw, 'AES-GCM', false, use);

const C = {
  // PBKDF2(SHA-256, 100k, fixed salt) of the normalised phone number
  async phoneHash(phone) {
    return b64(await pbkdf2(phone.replace(/[^\d+]/g, ''), enc.encode(APP_SALT)));
  },
  async genKeys() {
    const kp = await S.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return { pub: await S.exportKey('jwk', kp.publicKey), priv: await S.exportKey('jwk', kp.privateKey) };
  },
  // AES-GCM encrypt a string with a raw base64 key
  async enc(keyB64, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await S.encrypt({ name: 'AES-GCM', iv }, await aesKey(unb64(keyB64), ['encrypt']), enc.encode(text));
    return { iv: b64(iv), ct: b64(ct) };
  },
  async dec(keyB64, iv, ct) {
    const pt = await S.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await aesKey(unb64(keyB64), ['decrypt']), unb64(ct));
    return dec.decode(pt);
  },
  // SharedKey = HKDF(ECDH(myPriv, peerPub), salt = sort([OTP_S, OTP_R]).join(":"))
  async sharedKey(myPrivJwk, peerPubJwk, otpA, otpB) {
    const priv = await S.importKey('jwk', myPrivJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const pub = await S.importKey('jwk', peerPubJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const secret = await S.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
    const hk = await S.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    const salt = enc.encode([otpA, otpB].sort().join(':'));
    return b64(await S.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('e2ee-v1') }, hk, 256));
  },
  // PIN-encrypted local vault
  async seal(pin, obj) {
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await aesKey(await pbkdf2(pin, salt), ['encrypt']);
    const ct = await S.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  },
  async open(pin, blob) { // throws on wrong PIN
    const key = await aesKey(await pbkdf2(pin, unb64(blob.salt)), ['decrypt']);
    return JSON.parse(dec.decode(await S.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct))));
  },
  otp: () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 900000 + 100000),
};

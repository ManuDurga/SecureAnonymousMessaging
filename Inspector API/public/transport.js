// Transport layer. The app only talks to this interface, so swapping the Internet for LoRa
// later means swapping one class. Envelope: { to, from, type, iv, data }
//   type: 'hs' (handshake request) | 'ack' (handshake proof) | 'msg' (chat message)
//   iv, data: base64 strings (AES-GCM). Keys are short so the JSON stays LoRa-friendly.

class Transport {
  constructor() { this.handlers = []; this.statusHandlers = []; }
  async connect(_ctx) { throw new Error('not implemented'); }
  sendPacket(_packet) { throw new Error('not implemented'); }
  onPacket(fn) { this.handlers.push(fn); }
  onStatus(fn) { this.statusHandlers.push(fn); }
  _emit(p) { this.handlers.forEach((h) => h(p)); }
  _status(s) { this.statusHandlers.forEach((h) => h(s)); }
}

// Phase 1: Internet. ws:// on localhost, wss:// on Render/Railway (follows the page protocol).
class WebSocketTransport extends Transport {
  async connect({ token }) {
    this.token = token; this.closed = false;
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
    this.ws = new WebSocket(url);
    this.ws.onopen = () => { this.ws.send(JSON.stringify({ type: 'auth', token })); this._status('online'); };
    this.ws.onmessage = (e) => { try { this._emit(JSON.parse(e.data)); } catch {} };
    this.ws.onclose = () => { this._status('offline'); if (!this.closed) setTimeout(() => this.connect({ token }), 2000); };
  }
  sendPacket(p) { if (this.ws?.readyState === 1) this.ws.send(JSON.stringify(p)); }
  close() { this.closed = true; this.ws?.close(); }
}

// Phase 2 (placeholder): offline LoRa mesh through a USB/serial LoRa radio (ESP32 + SX126x etc.)
// Plan:
//   connect():    port = await navigator.serial.requestPort(); await port.open({ baudRate: 115200 });
//                 writer = port.writable.getWriter(); read port.readable lines in a loop.
//   sendPacket(): write JSON.stringify(p) + "\n". Keep it under ~200 bytes (LoRa payload limit);
//                 switch to a binary envelope (type 1B | to 8B | from 8B | iv 12B | data) and fragment if needed.
//   incoming:     parse each line and call this._emit(packet).
// Note: with no server, "from" must be set by the sender, so sign packets or rely on the AES-GCM key bound at handshake.
class LoRaSerialTransport extends Transport {
  async connect() {
    if (!('serial' in navigator)) throw new Error('Web Serial API not supported in this browser');
    throw new Error('LoRaSerialTransport is a Phase 2 placeholder');
  }
  sendPacket() { throw new Error('LoRaSerialTransport is a Phase 2 placeholder'); }
}

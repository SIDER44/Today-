// ============================================================
//  ALMEER TUNNEL - Cloudflare Worker
//  Protocols : VLESS + WebSocket + TLS
//              Trojan + WebSocket + TLS
//  Features  : ProxyIP, Subscription links, Config page
// ============================================================
//
//  ENV VARIABLES (set in Cloudflare Pages/Worker settings):
//    UUID      - your VLESS uuid  (required)
//    TROJAN_PW - your trojan password (optional, defaults to UUID)
//    PROXYIP   - proxy IP for Cloudflare-blocked sites (optional)
//                example: "cdn-all.xn--b6gac.eu.org"
//
// ============================================================

import { connect } from 'cloudflare:sockets';

// ── Defaults ─────────────────────────────────────────────────
const DEFAULT_UUID    = 'edbe9b39-3d6e-4286-a507-ce123456789a'; // overridden by env.UUID
const DEFAULT_PROXYIP = '';  // optional: set a proxyIP in env

// ── Cloudflare IP ranges (need ProxyIP routing) ───────────────
const CF_PREFIXES = [
  '172.64.', '172.65.', '172.66.', '172.67.',
  '104.16.', '104.17.', '104.18.', '104.19.',
  '104.20.', '104.21.', '104.22.', '104.23.',
  '104.24.', '104.25.', '104.26.', '104.27.',
  '104.28.', '104.29.', '104.30.', '104.31.',
  '141.101.', '108.162.', '190.93.', '188.114.',
  '197.234.', '198.41.', '162.158.', '104.160.',
  '104.161.', '104.162.', '104.163.', '104.164.',
  '104.165.'
];

// ─────────────────────────────────────────────────────────────
//  MAIN FETCH HANDLER
// ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    try {
      const uuid     = (env.UUID      || DEFAULT_UUID).trim().toLowerCase();
      const trojanPw = (env.TROJAN_PW || uuid).trim();
      const proxyIP  = (env.PROXYIP   || DEFAULT_PROXYIP).trim();
      const url      = new URL(request.url);
      const host     = request.headers.get('Host');
      const upgrade  = request.headers.get('Upgrade') || '';
      const path     = url.pathname;

      // ── Config / Subscription pages ────────────────────────
      if (path === `/${uuid}`) {
        return buildConfigPage(uuid, trojanPw, host);
      }
      if (path === `/${uuid}/sub`) {
        return buildSubscription(uuid, trojanPw, host);
      }
      if (path === `/${uuid}/clash`) {
        return buildClashConfig(uuid, trojanPw, host);
      }

      // ── WebSocket upgrade → detect protocol ────────────────
      if (upgrade.toLowerCase() === 'websocket') {
        // Trojan: path starts with /trojan or has trojan password
        if (path.startsWith('/trojan') || path.includes(trojanPw)) {
          return handleTrojanWS(request, trojanPw, proxyIP);
        }
        // Default: VLESS
        return handleVlessWS(request, uuid, proxyIP);
      }

      // ── Root page ──────────────────────────────────────────
      if (path === '/') {
        return new Response(
          `ALMEER TUNNEL ⚡ — Visit /${uuid} for your config`,
          { status: 200, headers: { 'Content-Type': 'text/plain' } }
        );
      }

      return new Response('Not Found', { status: 404 });

    } catch (err) {
      return new Response(`Server Error: ${err.message}`, { status: 500 });
    }
  }
};

// ─────────────────────────────────────────────────────────────
//  VLESS OVER WEBSOCKET
// ─────────────────────────────────────────────────────────────
async function handleVlessWS(request, uuid, proxyIP) {
  const [client, server] = new WebSocketPair();
  server.accept();
  vlessProcess(server, uuid, proxyIP);
  return new Response(null, { status: 101, webSocket: client });
}

async function vlessProcess(ws, uuid, proxyIP) {
  let tcpSocket   = null;
  let headerDone  = false;
  let msgQueue    = [];
  let draining    = false;

  async function drainQueue(writer) {
    if (draining) return;
    draining = true;
    for (const chunk of msgQueue) {
      await writer.write(chunk);
    }
    msgQueue = [];
    draining = false;
  }

  ws.addEventListener('message', async (event) => {
    try {
      const raw = toArrayBuffer(event.data);

      if (!headerDone) {
        headerDone = true;
        const parsed = parseVlessHeader(raw, uuid);
        if (parsed.error) { ws.close(1003, parsed.error); return; }

        // VLESS response: version + 0 addon bytes
        ws.send(new Uint8Array([parsed.version, 0]).buffer);

        const payload = raw.slice(parsed.dataOffset);
        const target  = resolveTarget(parsed.host, proxyIP);

        if (parsed.isUDP && parsed.port === 53) {
          await udpDNS(ws, payload); return;
        }

        tcpSocket = connect({ hostname: target.host, port: target.port || parsed.port });

        // Remote → WS
        tcpSocket.readable.pipeTo(new WritableStream({
          write(chunk) { ws.send(chunk); },
          close()      { ws.close(); },
          abort()      { ws.close(); }
        })).catch(() => ws.close());

        // Send first payload
        const writer = tcpSocket.writable.getWriter();
        if (payload.byteLength) await writer.write(new Uint8Array(payload));
        await drainQueue(writer);
        writer.releaseLock();

      } else if (tcpSocket) {
        const writer = tcpSocket.writable.getWriter();
        await writer.write(new Uint8Array(raw));
        writer.releaseLock();
      } else {
        msgQueue.push(new Uint8Array(raw));
      }
    } catch (e) { ws.close(1011, e.message); }
  });

  ws.addEventListener('close', () => tcpSocket?.close?.());
  ws.addEventListener('error', () => tcpSocket?.close?.());
}

// ─────────────────────────────────────────────────────────────
//  TROJAN OVER WEBSOCKET
// ─────────────────────────────────────────────────────────────
async function handleTrojanWS(request, password, proxyIP) {
  const [client, server] = new WebSocketPair();
  server.accept();
  trojanProcess(server, password, proxyIP);
  return new Response(null, { status: 101, webSocket: client });
}

async function trojanProcess(ws, password, proxyIP) {
  let tcpSocket  = null;
  let headerDone = false;

  ws.addEventListener('message', async (event) => {
    try {
      const raw = toArrayBuffer(event.data);

      if (!headerDone) {
        headerDone = true;
        const parsed = parseTrojanHeader(raw, password);
        if (parsed.error) { ws.close(1003, parsed.error); return; }

        const payload = raw.slice(parsed.dataOffset);
        const target  = resolveTarget(parsed.host, proxyIP);

        if (parsed.isUDP && parsed.port === 53) {
          await udpDNS(ws, payload); return;
        }

        tcpSocket = connect({ hostname: target.host, port: target.port || parsed.port });

        tcpSocket.readable.pipeTo(new WritableStream({
          write(chunk) { ws.send(chunk); },
          close()      { ws.close(); },
          abort()      { ws.close(); }
        })).catch(() => ws.close());

        const writer = tcpSocket.writable.getWriter();
        if (payload.byteLength) await writer.write(new Uint8Array(payload));
        writer.releaseLock();

      } else if (tcpSocket) {
        const writer = tcpSocket.writable.getWriter();
        await writer.write(new Uint8Array(raw));
        writer.releaseLock();
      }
    } catch (e) { ws.close(1011, e.message); }
  });

  ws.addEventListener('close', () => tcpSocket?.close?.());
  ws.addEventListener('error', () => tcpSocket?.close?.());
}

// ─────────────────────────────────────────────────────────────
//  HEADER PARSERS
// ─────────────────────────────────────────────────────────────
function parseVlessHeader(buffer, uuid) {
  try {
    const view = new DataView(buffer);
    let offset = 0;

    const version = view.getUint8(offset++);

    // UUID (16 bytes)
    const uuidBytes = new Uint8Array(buffer, offset, 16);
    offset += 16;
    if (bytesToUUID(uuidBytes) !== uuid) return { error: 'Bad UUID' };

    // Addon length
    const addonLen = view.getUint8(offset++);
    offset += addonLen;

    // Command: 1=TCP 2=UDP
    const cmd   = view.getUint8(offset++);
    const isUDP = cmd === 2;

    // Port
    const port = view.getUint16(offset); offset += 2;

    // Address
    const { host, newOffset } = readAddress(view, buffer, offset);
    offset = newOffset;

    return { version, isUDP, port, host, dataOffset: offset };
  } catch (e) { return { error: e.message }; }
}

function parseTrojanHeader(buffer, password) {
  try {
    const view    = new DataView(buffer);
    const decoder = new TextDecoder();
    let offset    = 0;

    // Password hash (56 hex chars)
    const pwBytes = new Uint8Array(buffer, 0, 56);
    const pwStr   = decoder.decode(pwBytes);
    offset += 56;

    // CRLF
    offset += 2;

    // Command: 1=TCP 3=UDP
    const cmd   = view.getUint8(offset++);
    const isUDP = cmd === 3;

    // Address type
    const { host, newOffset } = readAddress(view, buffer, offset);
    offset = newOffset;

    // Port
    const port = view.getUint16(offset); offset += 2;

    // CRLF
    offset += 2;

    return { isUDP, port, host, dataOffset: offset };
  } catch (e) { return { error: e.message }; }
}

function readAddress(view, buffer, offset) {
  const addrType = view.getUint8(offset++);
  let host = '';

  if (addrType === 1) {
    // IPv4
    host = Array.from(new Uint8Array(buffer, offset, 4)).join('.');
    offset += 4;
  } else if (addrType === 3) {
    // IPv6
    const parts = [];
    for (let i = 0; i < 8; i++) { parts.push(view.getUint16(offset).toString(16)); offset += 2; }
    host = parts.join(':');
  } else {
    // Domain (type 2)
    const len = view.getUint8(offset++);
    host = new TextDecoder().decode(new Uint8Array(buffer, offset, len));
    offset += len;
  }

  return { host, newOffset: offset };
}

// ─────────────────────────────────────────────────────────────
//  PROXY IP RESOLVER
// ─────────────────────────────────────────────────────────────
function resolveTarget(host, proxyIP) {
  if (!proxyIP) return { host };
  // If host is a Cloudflare IP, route through proxyIP
  const isCF = CF_PREFIXES.some(p => host.startsWith(p));
  if (isCF) return { host: proxyIP };
  return { host };
}

// ─────────────────────────────────────────────────────────────
//  DNS OVER HTTPS (UDP port 53)
// ─────────────────────────────────────────────────────────────
async function udpDNS(ws, data) {
  try {
    const res = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: data.byteLength > 2 ? data.slice(2) : data
    });
    const ans  = await res.arrayBuffer();
    const size = ans.byteLength;
    const out  = new Uint8Array(2 + size);
    out[0] = (size >> 8) & 0xff;
    out[1] =  size       & 0xff;
    out.set(new Uint8Array(ans), 2);
    ws.send(out.buffer);
  } catch (_) {}
}

// ─────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────
function toArrayBuffer(data) {
  if (data instanceof ArrayBuffer) return data;
  if (data instanceof Uint8Array)  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  return data;
}

function bytesToUUID(b) {
  const h = Array.from(b).map(x => x.toString(16).padStart(2, '0'));
  return `${h.slice(0,4).join('')}-${h.slice(4,6).join('')}-${h.slice(6,8).join('')}-${h.slice(8,10).join('')}-${h.slice(10).join('')}`;
}

function encodeBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

// ─────────────────────────────────────────────────────────────
//  SUBSCRIPTION LINKS
// ─────────────────────────────────────────────────────────────
function getLinks(uuid, trojanPw, host) {
  const vless   = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2F#ALMEER-VLESS`;
  const trojan  = `trojan://${trojanPw}@${host}:443?security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2Ftrojan#ALMEER-TROJAN`;
  return { vless, trojan };
}

function buildSubscription(uuid, trojanPw, host) {
  const { vless, trojan } = getLinks(uuid, trojanPw, host);
  const content = encodeBase64(`${vless}\n${trojan}`);
  return new Response(content, {
    headers: {
      'Content-Type': 'text/plain;charset=utf-8',
      'Profile-Title': 'ALMEER TUNNEL',
      'Subscription-Userinfo': 'upload=0; download=0; total=107374182400; expire=0'
    }
  });
}

function buildClashConfig(uuid, trojanPw, host) {
  const yaml = `
mixed-port: 7890
allow-lan: true
mode: Rule
log-level: info
proxies:
  - name: ALMEER-VLESS
    type: vless
    server: ${host}
    port: 443
    uuid: ${uuid}
    network: ws
    tls: true
    ws-opts:
      path: /
      headers:
        Host: ${host}
  - name: ALMEER-TROJAN
    type: trojan
    server: ${host}
    port: 443
    password: ${trojanPw}
    network: ws
    tls: true
    ws-opts:
      path: /trojan
      headers:
        Host: ${host}
proxy-groups:
  - name: ALMEER
    type: select
    proxies: [ALMEER-VLESS, ALMEER-TROJAN]
rules:
  - MATCH,ALMEER
`.trim();

  return new Response(yaml, {
    headers: { 'Content-Type': 'text/yaml;charset=utf-8' }
  });
}

// ─────────────────────────────────────────────────────────────
//  CONFIG PAGE (cyberpunk ALMEER UI)
// ─────────────────────────────────────────────────────────────
function buildConfigPage(uuid, trojanPw, host) {
  const { vless, trojan } = getLinks(uuid, trojanPw, host);
  const subLink   = `https://${host}/${uuid}/sub`;
  const clashLink = `https://${host}/${uuid}/clash`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ALMEER TUNNEL</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{background:#050505;color:#00ffcc;font-family:'Share Tech Mono',monospace;min-height:100vh;padding:16px}
canvas{position:fixed;top:0;left:0;z-index:0;opacity:.06;pointer-events:none}
.wrap{position:relative;z-index:1;max-width:680px;margin:0 auto}
h1{font-family:'Orbitron',monospace;color:#ff00ff;font-size:1.5rem;text-shadow:0 0 20px #ff00ff88;margin-bottom:2px}
.sub{color:#555;font-size:.75rem;margin-bottom:24px}
.card{background:#0c0c0c;border:1px solid #1a1a1a;border-radius:10px;padding:16px;margin-bottom:14px;border-left:2px solid #ff00ff}
.label{color:#ff00ff;font-size:.65rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:8px}
.val{color:#00ffcc;word-break:break-all;font-size:.72rem;line-height:1.7;background:#111;padding:10px 12px;border-radius:6px;border:1px solid #00ffcc11}
.btn{display:inline-block;margin-top:10px;margin-right:8px;background:transparent;color:#00ffcc;border:1px solid #00ffcc;padding:6px 16px;border-radius:20px;font-family:'Share Tech Mono',monospace;font-size:.7rem;cursor:pointer;transition:all .2s}
.btn:hover{background:#00ffcc;color:#000}
.btn.pink{border-color:#ff00ff;color:#ff00ff}
.btn.pink:hover{background:#ff00ff;color:#000}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:12px}
.info{background:#111;padding:10px;border-radius:6px}
.ikey{color:#444;font-size:.6rem;text-transform:uppercase;letter-spacing:1px}
.ival{color:#00ffcc;font-size:.75rem;margin-top:3px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#00ffcc;color:#000;padding:8px 20px;border-radius:20px;font-size:.75rem;font-family:'Orbitron',monospace;display:none;z-index:999}
.badge{display:inline-block;background:#ff00ff22;color:#ff00ff;border:1px solid #ff00ff33;padding:2px 10px;border-radius:20px;font-size:.65rem;margin-right:6px;margin-bottom:14px}
a.lnk{color:#ff00ff;font-size:.72rem;text-decoration:none;border-bottom:1px dotted #ff00ff44;padding-bottom:2px}
</style>
</head>
<body>
<canvas id="rain"></canvas>
<div class="wrap">
  <h1>⚡ ALMEER TUNNEL</h1>
  <p class="sub">Cloudflare Workers Proxy — ${host}</p>
  <span class="badge">VLESS</span><span class="badge">TROJAN</span><span class="badge">WS + TLS</span>

  <div class="card">
    <div class="label">VLESS + WebSocket + TLS</div>
    <div class="val" id="v1">${vless}</div>
    <button class="btn" onclick="cp('v1')">Copy VLESS</button>
  </div>

  <div class="card">
    <div class="label">Trojan + WebSocket + TLS</div>
    <div class="val" id="v2">${trojan}</div>
    <button class="btn" onclick="cp('v2')">Copy Trojan</button>
  </div>

  <div class="card">
    <div class="label">Subscription Links</div>
    <div class="val" id="v3">${subLink}</div>
    <button class="btn" onclick="cp('v3')">Copy Sub Link</button>
    <a class="btn pink lnk" href="${clashLink}" target="_blank">Clash Config</a>
  </div>

  <div class="card">
    <div class="label">Manual Config</div>
    <div class="grid">
      <div class="info"><div class="ikey">Address</div><div class="ival">${host}</div></div>
      <div class="info"><div class="ikey">Port</div><div class="ival">443</div></div>
      <div class="info"><div class="ikey">Security</div><div class="ival">TLS</div></div>
      <div class="info"><div class="ikey">Network</div><div class="ival">WebSocket</div></div>
      <div class="info"><div class="ikey">Path (VLESS)</div><div class="ival">/</div></div>
      <div class="info"><div class="ikey">Path (Trojan)</div><div class="ival">/trojan</div></div>
    </div>
    <div class="label" style="margin-top:14px">UUID</div>
    <div class="val" id="v4">${uuid}</div>
    <button class="btn" onclick="cp('v4')">Copy UUID</button>
    <div class="label" style="margin-top:12px">Trojan Password</div>
    <div class="val" id="v5">${trojanPw}</div>
    <button class="btn" onclick="cp('v5')">Copy Password</button>
  </div>
</div>

<div class="toast" id="toast">✓ Copied!</div>

<script>
function cp(id) {
  navigator.clipboard.writeText(document.getElementById(id).innerText).then(() => {
    const t = document.getElementById('toast');
    t.style.display = 'block';
    setTimeout(() => t.style.display = 'none', 1800);
  });
}

// Matrix rain
const c = document.getElementById('rain');
const x = c.getContext('2d');
c.width  = window.innerWidth;
c.height = window.innerHeight;
const cols  = Math.floor(c.width / 16);
const drops = Array(cols).fill(1);
setInterval(() => {
  x.fillStyle = 'rgba(0,0,0,.05)';
  x.fillRect(0, 0, c.width, c.height);
  x.fillStyle = '#00ffcc';
  x.font = '13px monospace';
  drops.forEach((y, i) => {
    x.fillText(String.fromCharCode(0x30A0 + Math.random()*96), i*16, y*16);
    if (y*16 > c.height && Math.random() > .975) drops[i] = 0;
    drops[i]++;
  });
}, 50);
</script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=utf-8' }
  });
}

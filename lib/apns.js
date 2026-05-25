// APNs HTTP/2 sender for ShareZPresso iOS.
//
// Zero new npm deps — uses Node's built-in `http2` + `crypto`. JWT (ES256)
// signed manually with the .p8 key. APNs requires a fresh token at least
// every hour, so we cache one and refresh after 55 minutes.
//
// Env vars (set in Coolify):
//   APNS_KEY_ID     — 10-char key ID from Apple Developer
//   APNS_TEAM_ID    — 10-char team ID
//   APNS_BUNDLE_ID  — the iOS app's bundle id (com.sharezpresso.ios)
//   APNS_KEY_P8     — the raw .p8 PEM contents (multi-line)
//
// If any are missing, send() becomes a no-op and logs once at boot.
// That makes it safe to push the code before the env vars are set.

const http2 = require('node:http2');
const crypto = require('node:crypto');

const KEY_ID    = process.env.APNS_KEY_ID    || '';
const TEAM_ID   = process.env.APNS_TEAM_ID   || '';
const BUNDLE_ID = process.env.APNS_BUNDLE_ID || 'com.sharezpresso.ios';
const KEY_P8    = process.env.APNS_KEY_P8    || '';

const PROD_HOST    = 'https://api.push.apple.com';
const SANDBOX_HOST = 'https://api.sandbox.push.apple.com';

const CONFIGURED = !!(KEY_ID && TEAM_ID && BUNDLE_ID && KEY_P8);
if (!CONFIGURED) {
  console.warn('[apns] not configured — push notifications disabled (missing APNS_* env vars)');
}

// ---------- JWT (ES256) ----------

let cachedJwt = null;
let cachedJwtIat = 0;

function makeJwt() {
  const header  = { alg: 'ES256', kid: KEY_ID, typ: 'JWT' };
  const payload = { iss: TEAM_ID, iat: Math.floor(Date.now() / 1000) };

  const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const signingInput = `${enc(header)}.${enc(payload)}`;

  // ES256 = ECDSA P-256 + SHA-256, signature must be raw R||S for JWS
  const sig = crypto.sign('SHA256', Buffer.from(signingInput), {
    key: KEY_P8,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');

  return `${signingInput}.${sig}`;
}

function jwt() {
  const now = Math.floor(Date.now() / 1000);
  // Refresh every 55 min; Apple kills tokens older than 60.
  if (!cachedJwt || (now - cachedJwtIat) > 55 * 60) {
    cachedJwt = makeJwt();
    cachedJwtIat = now;
  }
  return cachedJwt;
}

// ---------- HTTP/2 session pool ----------

const sessions = new Map();  // host -> ClientHttp2Session

function getSession(host) {
  let s = sessions.get(host);
  if (s && !s.closed && !s.destroyed) return s;
  s = http2.connect(host);
  s.on('error', (err) => {
    console.warn(`[apns] http2 session error (${host}):`, err.message);
    sessions.delete(host);
  });
  s.on('close', () => sessions.delete(host));
  sessions.set(host, s);
  return s;
}

// ---------- Public API ----------

/**
 * Send a push to one device token.
 *
 * @param {Object} opts
 * @param {string} opts.deviceToken — hex APNs device token
 * @param {string} [opts.env]       — 'production' (default) or 'sandbox'
 * @param {string} opts.title       — banner title
 * @param {string} opts.body        — banner body
 * @param {Object} [opts.data]      — custom payload merged at top level
 * @returns {Promise<{ok: boolean, status?: number, reason?: string}>}
 */
function send({ deviceToken, env = 'production', title, body, data = {} }) {
  if (!CONFIGURED) return Promise.resolve({ ok: false, reason: 'not_configured' });
  if (!deviceToken) return Promise.resolve({ ok: false, reason: 'no_device_token' });

  const host = env === 'sandbox' ? SANDBOX_HOST : PROD_HOST;
  const payload = JSON.stringify({
    aps: { alert: { title, body }, sound: 'default' },
    ...data,
  });

  return new Promise((resolve) => {
    let session;
    try {
      session = getSession(host);
    } catch (err) {
      return resolve({ ok: false, reason: `session_failed:${err.message}` });
    }

    const req = session.request({
      ':method': 'POST',
      ':path': `/3/device/${deviceToken}`,
      authorization: `bearer ${jwt()}`,
      'apns-topic': BUNDLE_ID,
      'apns-push-type': 'alert',
      'apns-priority': '10',
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
    });

    let status = 0;
    let respBody = '';
    req.on('response', (headers) => { status = headers[':status']; });
    req.setEncoding('utf8');
    req.on('data', (chunk) => { respBody += chunk; });
    req.on('end', () => {
      if (status >= 200 && status < 300) {
        resolve({ ok: true, status });
      } else {
        let reason = respBody;
        try { reason = JSON.parse(respBody).reason || respBody; } catch {}
        resolve({ ok: false, status, reason });
      }
    });
    req.on('error', (err) => resolve({ ok: false, reason: err.message }));
    req.setTimeout(10_000, () => {
      req.close();
      resolve({ ok: false, reason: 'timeout' });
    });

    req.end(payload);
  });
}

/**
 * Fan-out a push to every device token registered to a user. Returns
 * counts; failures (incl. BadDeviceToken / Unregistered) are logged but
 * never thrown — callers shouldn't have to handle push errors.
 *
 * @param {Array<{apns_token: string, apns_env: string}>} tokens
 * @param {{title: string, body: string, data?: Object}} alert
 * @returns {Promise<{sent: number, failed: number, stale: string[]}>}
 */
async function fanOut(tokens, { title, body, data }) {
  if (!CONFIGURED || !tokens.length) return { sent: 0, failed: 0, stale: [] };
  let sent = 0, failed = 0;
  const stale = [];
  await Promise.all(tokens.map(async (t) => {
    const r = await send({
      deviceToken: t.apns_token,
      env: t.apns_env,
      title,
      body,
      data,
    });
    if (r.ok) {
      sent += 1;
    } else {
      failed += 1;
      // 410 Unregistered or 400 BadDeviceToken → caller should delete the row
      if (r.status === 410 || (r.status === 400 && /BadDeviceToken/i.test(r.reason || ''))) {
        stale.push(t.apns_token);
      }
      console.warn(`[apns] send failed (${r.status}): ${r.reason}`);
    }
  }));
  return { sent, failed, stale };
}

module.exports = { send, fanOut, configured: CONFIGURED };

// Cloudflare R2 storage — ShareZPresso's own dedicated bucket (default
// `sharezpresso`), with an API token scoped to that bucket only, so its usage
// and bill show up separately in the Cloudflare dashboard.
//
// The bucket is PRIVATE. Nothing links to it directly: every view goes through
// our own /raw, /d, /ci and /pa routes, which fetch the object with a
// short-lived signed URL (presignGet). Stored URLs look like
//   r2://<bucket>/<key>
// in the same columns that hold GHL CDN URLs (files.ghl_url, chat_items.ghl_url,
// pages.avatar_url), so old GHL files and new R2 files live side by side.
//
// Upload + delete hand curl a URL we presigned ourselves, the same
// curl-from-disk pattern as lib/ghl.js: it streams the temp file, so a 500 MB
// video never sits in Node's memory.
//
// Env:
//   R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET

const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');

function cfg() {
  return {
    accountId: process.env.R2_ACCOUNT_ID || '',
    accessKeyId: process.env.R2_ACCESS_KEY_ID || '',
    secret: process.env.R2_SECRET_ACCESS_KEY || '',
    bucket: process.env.R2_BUCKET || '',
  };
}

function isConfigured() {
  const c = cfg();
  return Boolean(c.accountId && c.accessKeyId && c.secret && c.bucket);
}

function host(c) { return `${c.accountId}.r2.cloudflarestorage.com`; }

// Keys only ever contain [A-Za-z0-9._/-], so no URL-encoding questions can
// arise between curl's signer, our presigner and R2.
function safeSegment(s) {
  return String(s || 'file').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120) || 'file';
}

function isR2Url(url) { return typeof url === 'string' && url.startsWith('r2://'); }

function parseR2Url(url) {
  const m = /^r2:\/\/([^/]+)\/(.+)$/.exec(url || '');
  return m ? { bucket: m[1], key: m[2] } : null;
}


/** Upload a file from disk. Returns its stored url: r2://<bucket>/<key>. */
function upload(filePath, displayName, mime) {
  const c = cfg();
  if (!isConfigured()) throw new Error('[R2] not configured');
  if (!fs.existsSync(filePath)) throw new Error(`[R2] file not found: ${filePath}`);
  const d = new Date();
  const key = [
    'files',
    String(d.getUTCFullYear()),
    String(d.getUTCMonth() + 1).padStart(2, '0'),
    crypto.randomBytes(12).toString('hex'),
    safeSegment(displayName),
  ].join('/');
  const args = [
    '-s', '-S', '--fail-with-body',
    '-T', filePath,
    '-H', `Content-Type: ${mime || 'application/octet-stream'}`,
    presign('PUT', `r2://${c.bucket}/${key}`, 3600),
  ];
  try {
    execFileSync('curl', args, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  } catch (err) {
    const body = (err.stdout || '') + (err.stderr || '');
    throw new Error(`[R2] upload failed: ${body.slice(0, 300)}`);
  }
  return `r2://${c.bucket}/${key}`;
}

/** Best-effort delete. Returns true when R2 confirmed it. */
function tryDelete(url) {
  const p = parseR2Url(url);
  const c = cfg();
  if (!p || !isConfigured()) return false;
  try {
    execFileSync('curl', ['-s', '-S', '--fail-with-body', '-X', 'DELETE',
      presign('DELETE', url, 300)], { encoding: 'utf8' });
    return true;
  } catch (err) {
    const body = (err.stdout || '') + (err.stderr || '');
    console.warn(`[R2] tryDelete failed for ${p.key}: ${body.slice(0, 200)}`);
    return false;
  }
}

function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }

/** Signed GET url (SigV4 query auth), valid `expires` seconds. */
function presignGet(url, expires = 3600) { return presign('GET', url, expires); }

/**
 * Signed url for any method. Upload/delete use this too and hand the url to
 * plain curl: the server's Debian curl (7.88) has an --aws-sigv4 that R2
 * rejects with InvalidRequest (8 Nov 2026), so we never rely on curl to sign.
 */
function presign(method, url, expires = 3600) {
  const p = parseR2Url(url);
  const c = cfg();
  if (!p) throw new Error('[R2] not an r2:// url');
  const h = host(c);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const date = amzDate.slice(0, 8);
  const scope = `${date}/auto/s3/aws4_request`;
  const path = `/${p.bucket}/${p.key}`;
  const q = [
    ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${c.accessKeyId}/${scope}`],
    ['X-Amz-Date', amzDate],
    ['X-Amz-Expires', String(expires)],
    ['X-Amz-SignedHeaders', 'host'],
  ].map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).sort().join('&');
  const canonical = [method, path, q, `host:${h}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope,
    crypto.createHash('sha256').update(canonical).digest('hex')].join('\n');
  const kSigning = hmac(hmac(hmac(hmac('AWS4' + c.secret, date), 'auto'), 's3'), 'aws4_request');
  const sig = crypto.createHmac('sha256', kSigning).update(toSign).digest('hex');
  return `https://${h}${path}?${q}&X-Amz-Signature=${sig}`;
}

module.exports = { isConfigured, isR2Url, upload, tryDelete, presignGet };

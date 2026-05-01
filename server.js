// share.bizapp.club — multi-user file-share SaaS.
//
// Flow:
//   1. Public signup creates a trial account (status='trial'). Trial users
//      can upload one file per kind (image/video/audio/pdf/text).
//   2. Admin upgrades them to 'regular' for unlimited uploads, or to
//      'deactivated' to cut them off.
//   3. All file uploads still go to the same GHL folder for now — we'll
//      add per-user GHL location+folder config later.

const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { nanoid } = require('nanoid');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { users: udb, files: fdb, passwordResets: prdb, magicLinks: mldb, messages: mdb } = require('./lib/db');
const users = require('./lib/users');
const ghl = require('./lib/ghl');
const transcode = require('./lib/transcode');
const email = require('./lib/email');
const { classify, SIZE_CAPS, fmtBytes } = require('./lib/classify');
const viewers = require('./lib/viewers');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SITE_NAME = process.env.SITE_NAME || 'share.bizapp.club';
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || 'https://share.bizapp.club';
const RECENT_PAGE_SIZE = 10;

// ---------- middleware ----------

app.use(cookieParser(SESSION_SECRET));
app.disable('x-powered-by');
app.set('trust proxy', 1);

// PDF.js viewer assets (served as static files — see Dockerfile)
app.use('/pdfjs', express.static(path.join(__dirname, 'public', 'pdfjs'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.mjs')) res.setHeader('Content-Type', 'text/javascript');
  },
}));

// Cheap request logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`[${req.method}] ${req.originalUrl} → ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

// Load the signed-cookie user on every request. Also clears a stale
// cookie (user deleted / deactivated mid-session) so we don't end up
// serving dashboard chrome to a ghost.
app.use((req, res, next) => {
  const uid = parseInt(req.signedCookies.uid, 10);
  if (Number.isFinite(uid)) {
    const u = udb.getById(uid);
    if (u && u.status !== 'deactivated') {
      req.user = users.sanitize(u);
    } else {
      res.clearCookie('uid');
    }
  }
  next();
});

// Multer: stream to disk, cap at the largest type (video) so the hard cap
// never bites on a legitimate upload. Per-type enforcement runs after.
const upload = multer({
  dest: process.env.UPLOAD_TMP || os.tmpdir(),
  limits: { fileSize: SIZE_CAPS.video },
});

// Guest session: mint a signed guest_id cookie for anyone who isn't
// logged in yet. It's how we correlate "the file they just uploaded"
// with "the email they're about to enter" to the magic link they'll
// click. Random 16 bytes → 22-char base64url, plenty unique for our scale.
app.use((req, res, next) => {
  if (req.user) return next();
  if (!req.signedCookies.gid) {
    const id = crypto.randomBytes(16).toString('base64url');
    res.cookie('gid', id, {
      signed: true, httpOnly: true, sameSite: 'lax', secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    req.guestId = id;
  } else {
    req.guestId = req.signedCookies.gid;
  }
  next();
});

// In-memory per-IP rate limiter for /api/guest-upload. Good enough for
// a single-container deployment — if we ever scale horizontally we'll
// swap this for something shared. Rolling window kept in a Map so old
// entries self-evict on each check.
const GUEST_UPLOAD_LIMIT = 3;
const GUEST_UPLOAD_WINDOW_MS = 60 * 60 * 1000;
const guestUploadBuckets = new Map();
function guestRateLimit(req, res, next) {
  const ip = (req.ip || req.connection.remoteAddress || 'unknown').toString();
  const now = Date.now();
  const arr = (guestUploadBuckets.get(ip) || []).filter(t => now - t < GUEST_UPLOAD_WINDOW_MS);
  if (arr.length >= GUEST_UPLOAD_LIMIT) {
    return res.status(429).json({
      ok: false,
      error: `Too many uploads from this IP. Try again in an hour, or sign up for a free account to keep going.`,
    });
  }
  arr.push(now);
  guestUploadBuckets.set(ip, arr);
  next();
}

function requireUser(req, res, next) {
  if (req.user) return next();
  return res.redirect('/login');
}
function requireAdmin(req, res, next) {
  if (req.user && req.user.is_admin) return next();
  return res.status(403).send(layout({ title: 'Forbidden', body: '<h1>Forbidden</h1><p>Admin only.</p>', user: req.user }));
}

function setAuthCookie(res, userId) {
  res.cookie('uid', String(userId), {
    signed: true, httpOnly: true, sameSite: 'lax', secure: true,
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

// ---------- helpers ----------

const escHtml = viewers.escHtml;

function sanitizeForFilename(s) {
  return String(s || '')
    .replace(/[^\p{L}\p{N}._\- ]+/gu, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[\-_.\s]+|[\-_.\s]+$/g, '')
    .slice(0, 80)
    || 'file';
}

function baseFilename(originalName) {
  if (!originalName) return '';
  return path.parse(originalName).name || '';
}

function fmtGstTimestamp(createdAt) {
  if (!createdAt) return '';
  const raw = String(createdAt).trim();
  const iso = raw.includes('T') ? raw : raw.replace(' ', 'T') + (raw.endsWith('Z') ? '' : 'Z');
  const d = new Date(iso);
  if (isNaN(d)) return '';
  try {
    const date = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Dubai', month: 'short', day: 'numeric', year: 'numeric' }).format(d);
    const time = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Dubai', hour: 'numeric', minute: '2-digit', hour12: true }).format(d);
    return `${date} · ${time} GST`;
  } catch { return ''; }
}

function kindEmoji(kind) {
  return ({ image: '🖼', video: '🎬', audio: '🎙', pdf: '📄', text: '📝', unknown: '📎' })[kind] || '📎';
}

function statusPill(status) {
  const color = { trial: '#f59e0b', regular: '#16a34a', deactivated: '#dc2626' }[status] || '#64748b';
  return `<span class="pill" style="background:${color}1a;color:${color};border:1px solid ${color}55;">${escHtml(status)}</span>`;
}

// ---------- CSS (shared across all pages) ----------
const BASE_CSS = `
  :root { --fg:#111; --muted:#666; --bg:#fafafa; --card:#fff; --brand:#2563eb; --brand-dark:#1d4ed8; --ok:#16a34a; --err:#dc2626; --border:#e5e7eb; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body { font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--fg); min-height: 100vh; }
  .site-header { background: #0f172a; padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .site-header .brand { display: inline-flex; align-items: center; gap: 8px; color: #fff; text-decoration: none; font-weight: 700; font-size: 17px; letter-spacing: -0.01em; }
  .site-header .brand:hover { opacity: 0.85; }
  .site-header .brand-mark { font-size: 20px; line-height: 1; }
  .site-header .navlinks { display: inline-flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .site-header .navlinks a, .site-header .navlinks form button { color: #cbd5e1; text-decoration: none; font-size: 14px; padding: 6px 10px; border-radius: 8px; border: 0; background: transparent; cursor: pointer; font-weight: 500; }
  .site-header .navlinks a:hover, .site-header .navlinks form button:hover { background: rgba(255,255,255,0.08); color: #fff; }
  .site-header .who { color: #94a3b8; font-size: 13px; padding: 6px 8px; }
  main { max-width: 720px; margin: 0 auto; padding: 32px 20px 64px; }
  main.wide { max-width: 960px; }
  h1 { font-size: 28px; margin: 0 0 8px; }
  h2 { font-size: 20px; margin: 24px 0 8px; }
  p { margin: 0 0 16px; }
  .muted { color: var(--muted); }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .btn { display: inline-block; background: var(--brand); color: #fff; border: 0; border-radius: 10px; padding: 14px 22px; font-size: 16px; font-weight: 600; cursor: pointer; text-decoration: none; min-height: 48px; }
  .btn:hover { background: var(--brand-dark); }
  .btn:active { transform: translateY(1px); }
  .btn:disabled { opacity: 0.6; cursor: default; }
  .btn-block { display: block; width: 100%; text-align: center; }
  .btn-secondary { background: #fff; color: var(--fg); border: 1px solid var(--border); }
  .btn-secondary:hover { background: #f3f4f6; }
  .btn-danger { background: #fff; color: var(--err); border: 1px solid #fecaca; }
  .btn-danger:hover { background: #fef2f2; }
  .btn-sm { padding: 8px 14px; font-size: 14px; min-height: 36px; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; }
  .row .btn { flex: 1 1 auto; padding: 10px 14px; font-size: 14px; min-height: 44px; text-align: center; }
  .stack > * + * { margin-top: 12px; }
  .pill { display: inline-block; padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; }
  .chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; background: #f1f5f9; border-radius: 99px; font-size: 13px; color: var(--fg); }
  .chip.used { background: #dcfce7; color: #166534; }
  /* Filter bar for the recent list */
  .filter-bar { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .filter-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
  .chip-btn { padding: 6px 12px; border-radius: 99px; border: 1px solid var(--border); background: #fff; font-size: 13px; font-weight: 500; cursor: pointer; color: var(--fg); white-space: nowrap; transition: background-color .1s, border-color .1s, color .1s; }
  .chip-btn:hover { background: #f3f4f6; }
  .chip-btn.is-active { background: var(--brand); color: #fff; border-color: var(--brand); }
  .filter-inputs { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  .filter-inputs input[type="text"] { flex: 1 1 200px; min-width: 140px; padding: 8px 12px; font-size: 14px; }
  .filter-inputs input[type="date"] { padding: 8px 10px; font-size: 13px; border: 1px solid var(--border); border-radius: 8px; background: #fff; color: var(--fg); }
  .filter-inputs .date-label { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 500; color: var(--muted); margin: 0; }
  .filter-inputs .date-label input[type="date"] { min-width: 140px; }
  .filter-inputs .btn-sm { min-height: 36px; }
  .recent-empty { text-align: center; padding: 40px 20px; color: var(--muted); font-size: 14px; }
  .dropzone { position: relative; border: 2px dashed #cbd5e1; border-radius: 12px; background: #fff; transition: border-color .15s, background-color .15s; cursor: pointer; }
  .dropzone:hover { border-color: var(--brand); background: #f8fafc; }
  .dropzone.is-dragover { border-color: var(--brand); background: #eff6ff; }
  .dropzone input[type="file"] { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
  .dropzone-inner { padding: 32px 20px; text-align: center; pointer-events: none; }
  .dropzone-icon { font-size: 44px; line-height: 1; margin-bottom: 8px; }
  .dropzone-text strong { display: block; font-size: 16px; color: var(--fg); }
  .dropzone-text .sub { display: block; font-size: 14px; color: var(--muted); margin-top: 4px; }
  .dropzone-filename { display: none; margin-top: 12px; font-weight: 600; color: var(--brand); word-break: break-all; font-size: 14px; }
  .dropzone.has-file .dropzone-filename { display: block; }
  .dropzone.has-file .dropzone-icon { color: var(--ok); }
  input[type="text"], input[type="email"], input[type="password"] { display: block; width: 100%; padding: 12px 14px; font-size: 16px; border: 1px solid var(--border); border-radius: 10px; background: #fff; }
  label { display: block; font-weight: 600; margin-bottom: 6px; }
  .checkbox-row { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #f8fafc; border: 1px solid var(--border); border-radius: 10px; cursor: pointer; }
  .checkbox-row input { width: 18px; height: 18px; margin: 0; }
  .checkbox-row span { flex: 1; font-weight: 500; color: var(--fg); }
  .checkbox-row .hint { display: block; font-weight: 400; font-size: 13px; color: var(--muted); margin-top: 2px; }
  .link-box { padding: 14px; background: #f3f4f6; border-radius: 10px; font-family: ui-monospace, monospace; word-break: break-all; font-size: 14px; border: 1px solid var(--border); }
  .ok { color: var(--ok); } .err { color: var(--err); }
  .footer { margin-top: 40px; color: var(--muted); font-size: 13px; text-align: center; }
  /* Table for admin dashboard */
  table.users-table { width: 100%; border-collapse: collapse; font-size: 14px; }
  table.users-table th, table.users-table td { padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
  table.users-table th { font-weight: 600; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
  table.users-table tr:last-child td { border-bottom: 0; }
  table.users-table select { padding: 6px 8px; border: 1px solid var(--border); border-radius: 8px; font-size: 13px; background: #fff; }
  table.users-table .user-name { font-weight: 600; }
  table.users-table .user-email { color: var(--muted); font-size: 13px; }
  /* Upload progress — animated rainbow */
  .progress { display: none; margin-top: 16px; }
  .progress.is-active { display: block; animation: progress-fade-in .25s ease-out; }
  @keyframes progress-fade-in { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
  .progress-pct { font-size: 42px; font-weight: 700; line-height: 1; letter-spacing: -0.02em; text-align: center; margin-bottom: 12px;
    background: linear-gradient(90deg, #2563eb, #9333ea, #ec4899, #f97316);
    background-size: 300% 100%;
    -webkit-background-clip: text; background-clip: text;
    -webkit-text-fill-color: transparent; color: transparent;
    animation: progress-gradient-shift 3s linear infinite;
  }
  @keyframes progress-gradient-shift { 0% { background-position: 0% 50%; } 100% { background-position: 100% 50%; } }
  .progress-bar { position: relative; height: 16px; background: #e5e7eb; border-radius: 99px; overflow: hidden; box-shadow: inset 0 1px 3px rgba(0,0,0,0.08); }
  .progress-fill { position: relative; height: 100%; width: 0%; border-radius: 99px;
    background: linear-gradient(90deg, #2563eb, #9333ea, #ec4899, #f97316);
    background-size: 200% 100%;
    animation: progress-gradient-slide 2s linear infinite;
    transition: width .25s cubic-bezier(.4,0,.2,1);
    box-shadow: 0 0 12px rgba(147, 51, 234, 0.45);
  }
  @keyframes progress-gradient-slide { 0% { background-position: 0% 0%; } 100% { background-position: 200% 0%; } }
  .progress-fill::after { content: ''; position: absolute; inset: 0; border-radius: 99px;
    background-image: linear-gradient(45deg, rgba(255,255,255,.22) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.22) 50%, rgba(255,255,255,.22) 75%, transparent 75%, transparent);
    background-size: 24px 24px;
    animation: progress-stripes-move 1s linear infinite;
  }
  @keyframes progress-stripes-move { 0% { background-position: 0 0; } 100% { background-position: 24px 0; } }
  .progress-meta { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; color: var(--muted); margin-top: 10px; flex-wrap: wrap; }
  .progress-meta strong { color: var(--fg); font-weight: 600; }
  .progress.is-done .progress-fill { animation: none; background: var(--ok); box-shadow: 0 0 12px rgba(22, 163, 74, 0.45); }
  .progress.is-done .progress-fill::after { animation: none; opacity: 0; }
  .progress.is-done .progress-pct { animation: none; background: none; -webkit-text-fill-color: var(--ok); color: var(--ok); }
  /* Viewer specifics */
  .full-image { display: block; width: 100%; height: auto; border-radius: 8px; cursor: zoom-in; }
  .full-media { width: 100%; border-radius: 8px; background: #000; }
  .full-audio { width: 100%; }
  .image-card, .pdf-card { padding: 12px; }
  .pdf-frame { width: 100%; height: 80vh; border: 0; border-radius: 8px; background: #525659; }
  .text-card .raw-text { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font: 13px/1.5 ui-monospace, "SF Mono", Menlo, monospace; max-height: 70vh; overflow-y: auto; }
  .markdown-body { padding: 4px 4px 12px; line-height: 1.65; }
  .markdown-body h1, .markdown-body h2, .markdown-body h3 { margin-top: 1.4em; margin-bottom: .5em; line-height: 1.3; }
  .markdown-body h1 { font-size: 24px; } .markdown-body h2 { font-size: 20px; } .markdown-body h3 { font-size: 17px; }
  .markdown-body p { margin: 0 0 .9em; }
  .markdown-body code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font: 13px/1.4 ui-monospace, "SF Mono", Menlo, monospace; }
  .markdown-body pre { background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 8px; overflow-x: auto; }
  .markdown-body pre code { background: transparent; color: inherit; padding: 0; }
  .markdown-body blockquote { border-left: 4px solid var(--border); padding: .2em 1em; color: var(--muted); margin: 1em 0; }
  .markdown-body ul, .markdown-body ol { padding-left: 1.4em; margin: 0 0 1em; }
  .markdown-body table { border-collapse: collapse; margin: 1em 0; width: 100%; }
  .markdown-body th, .markdown-body td { border: 1px solid var(--border); padding: 8px 12px; text-align: left; }
  .markdown-body img { max-width: 100%; height: auto; }
  .markdown-body a { color: var(--brand); }
`;

// ---------- layout ----------

function renderNav(user) {
  if (!user) {
    return `
      <div class="navlinks">
        <a href="/login">Log in</a>
        <a href="/signup">Sign up</a>
      </div>
    `;
  }
  const adminLink = user.is_admin ? '<a href="/admin">Admin</a>' : '';
  return `
    <div class="navlinks">
      <span class="who">${escHtml(user.name || user.email)}</span>
      <a href="/upload">Upload</a>
      <a href="/messages">Messages</a>
      <a href="/account">Account</a>
      ${adminLink}
      <form method="POST" action="/logout" style="display:inline;"><button type="submit">Log out</button></form>
    </div>
  `;
}

function layout({ title, body, user, ogTitle, ogDescription, ogImageUrl, noindex = true, wide = false }) {
  const og = [
    `<meta property="og:site_name" content="${escHtml(SITE_NAME)}">`,
    `<meta property="og:title" content="${escHtml(ogTitle || title)}">`,
    ogDescription ? `<meta property="og:description" content="${escHtml(ogDescription)}">` : '',
    ogImageUrl ? `<meta property="og:image" content="${escHtml(ogImageUrl)}">` : '',
    `<meta name="twitter:card" content="${ogImageUrl ? 'summary_large_image' : 'summary'}">`,
    `<meta name="twitter:title" content="${escHtml(ogTitle || title)}">`,
    ogDescription ? `<meta name="twitter:description" content="${escHtml(ogDescription)}">` : '',
  ].filter(Boolean).join('\n  ');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escHtml(title)}</title>
  ${noindex ? '<meta name="robots" content="noindex,nofollow">' : ''}
  ${og}
  <style>${BASE_CSS}</style>
</head>
<body>
  <header class="site-header">
    <a href="/" class="brand" aria-label="${escHtml(SITE_NAME)} — home">
      <span class="brand-mark">📤</span>
      <span class="brand-name">${escHtml(SITE_NAME)}</span>
    </a>
    ${renderNav(user)}
  </header>
  <main${wide ? ' class="wide"' : ''}>
    ${body}
  </main>
</body>
</html>`;
}

// ---------- recent list rendering (per user, used on /upload) ----------

function renderRecentCard(r) {
  const shareLink = `${PUBLIC_ORIGIN}/f/${r.slug}`;
  const title = r.title || r.original_filename || 'File';
  const dlLabel = r.download_allowed ? 'Downloads ON' : 'Downloads OFF';
  const dlClass = r.download_allowed ? 'ok' : 'muted';
  return `
    <div class="card stack recent-item" data-slug="${escHtml(r.slug)}" data-id="${r.id}" data-download="${r.download_allowed ? 1 : 0}">
      <div>
        <div style="font-weight: 600; font-size: 16px; word-break: break-word;" class="recent-title">
          ${kindEmoji(r.kind)} ${escHtml(title)}
        </div>
        <div class="muted" style="font-size: 13px; margin-top: 2px;">
          ${escHtml(r.kind)} · ${fmtBytes(r.size_bytes)} · <span class="${dlClass} dl-state">${dlLabel}</span>
        </div>
        <div class="muted" style="font-size: 12px; margin-top: 2px;">
          ${escHtml(fmtGstTimestamp(r.created_at))}
        </div>
      </div>
      <div class="link-box recent-link">${escHtml(shareLink)}</div>
      <button type="button" class="btn btn-block copy-btn" data-url="${escHtml(shareLink)}">Copy link</button>
      <div class="row">
        <a class="btn btn-secondary" href="/f/${escHtml(r.slug)}" target="_blank" rel="noopener">Open</a>
        <button type="button" class="btn btn-secondary rename-btn" data-slug="${escHtml(r.slug)}">Rename</button>
        <button type="button" class="btn btn-secondary toggle-dl-btn" data-slug="${escHtml(r.slug)}">Toggle download</button>
        <button type="button" class="btn btn-danger delete-btn" data-slug="${escHtml(r.slug)}" data-title="${escHtml(title)}">Delete</button>
      </div>
    </div>
  `;
}

// ---------- routes: auth ----------

app.get('/', (req, res) => {
  if (req.user) return res.redirect('/upload');
  // Progressive signup: logged-out visitors see a drag-drop first. They
  // upload without creating an account, then provide an email to get a
  // magic link that activates the share link AND creates their account.
  return res.send(renderGuestLandingPage());
});

app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/upload');
  res.send(renderAuthPage({
    activeTab: 'login',
    loginErr: req.query.err ? 'Wrong email or password.' : '',
    signupErr: '',
  }));
});

app.post('/login', express.urlencoded({ extended: false }), (req, res) => {
  const u = users.login({ email: req.body.email, password: req.body.password });
  if (!u) return res.redirect('/login?err=1');
  setAuthCookie(res, u.id);
  return res.redirect('/upload');
});

app.post('/logout', (req, res) => {
  res.clearCookie('uid');
  res.redirect('/login');
});

app.get('/signup', (req, res) => {
  if (req.user) return res.redirect('/upload');
  const err = req.query.err ? decodeURIComponent(req.query.err) : '';
  res.send(renderAuthPage({
    activeTab: 'signup',
    loginErr: '',
    signupErr: err,
  }));
});

// ---------- public message viewer ----------
//
// Standalone, no app chrome. Title big, copy button enormous and
// reachable on mobile (60px+ tall, sticky on long messages so the
// user never has to scroll-then-tap). Body in a clean reading card
// preserving whitespace and emojis exactly.

function renderMessageViewer(m, viewer) {
  const title = m.title || 'Shared message';
  const bodyJson = JSON.stringify(m.body);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escHtml(title)} — ${escHtml(SITE_NAME)}</title>
  <meta name="robots" content="noindex,nofollow">
  <meta property="og:title" content="${escHtml(title)}">
  <meta property="og:description" content="Tap to copy — ready to paste in DMs.">
  <style>${MSG_VIEWER_CSS}</style>
</head>
<body class="mv-body">
  <header class="mv-header">
    <a href="/" class="mv-brand">
      <span class="mv-brand-mark">📤</span>
      <span>${escHtml(SITE_NAME)}</span>
    </a>
  </header>

  <main class="mv-main">
    <h1 class="mv-title">${escHtml(title)}</h1>

    <button type="button" class="mv-copy" id="mvCopy" data-body='${escHtml(bodyJson)}'>
      <span class="mv-copy-icon">📋</span>
      <span class="mv-copy-label">Tap to copy message</span>
    </button>

    <article class="mv-body-card" id="mvBody">${linkifyHtml(m.body)}</article>

    <p class="mv-hint">Then paste in Instagram, WhatsApp, Facebook DMs — anywhere.</p>
  </main>

  <!-- Sticky copy bar on mobile, only after the user scrolls past the top button -->
  <div class="mv-sticky" id="mvSticky" aria-hidden="true">
    <button type="button" class="mv-copy mv-copy--sticky" id="mvCopySticky" data-body='${escHtml(bodyJson)}'>
      <span class="mv-copy-icon">📋</span>
      <span class="mv-copy-label">Copy message</span>
    </button>
  </div>

  <script>
    // Body is server-side rendered with linkifyHtml — already in the
    // DOM. The raw value lives only in this constant for the copy
    // button so what hits the clipboard stays as plain text URLs
    // (not the <a> markup).
    const raw = JSON.parse(${JSON.stringify(bodyJson)});

    async function doCopy(btn) {
      try {
        await navigator.clipboard.writeText(raw);
        btn.classList.add('is-copied');
        const label = btn.querySelector('.mv-copy-label');
        const icon  = btn.querySelector('.mv-copy-icon');
        const pl = label.textContent, pi = icon.textContent;
        label.textContent = 'Copied — paste anywhere now';
        icon.textContent = '✓';
        if (navigator.vibrate) { try { navigator.vibrate(15); } catch {} }
        setTimeout(() => {
          btn.classList.remove('is-copied');
          label.textContent = pl; icon.textContent = pi;
        }, 2200);
      } catch (e) {
        alert('Copy failed — long-press the message text to copy manually.');
      }
    }
    document.getElementById('mvCopy').addEventListener('click', e => doCopy(e.currentTarget));
    document.getElementById('mvCopySticky').addEventListener('click', e => doCopy(e.currentTarget));

    // Reveal the sticky copy bar only after the top one scrolls out of view
    const topBtn = document.getElementById('mvCopy');
    const sticky = document.getElementById('mvSticky');
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver(entries => {
        for (const e of entries) {
          sticky.classList.toggle('is-visible', !e.isIntersecting);
        }
      }, { rootMargin: '-80px 0px 0px 0px' });
      io.observe(topBtn);
    }
  </script>
</body>
</html>`;
}

const MSG_VIEWER_CSS = `
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  .mv-body {
    font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    color: #0f172a;
    background: linear-gradient(180deg, #fafbff 0%, #f3f5fb 100%);
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    padding-bottom: 96px;     /* room for sticky bar */
  }
  .mv-header { background: #0f172a; padding: 12px 20px; }
  .mv-brand { display: inline-flex; align-items: center; gap: 8px; color: #fff; text-decoration: none; font-weight: 700; font-size: 17px; letter-spacing: -0.01em; }
  .mv-brand-mark { font-size: 20px; line-height: 1; }

  .mv-main { max-width: 640px; margin: 0 auto; padding: 28px 20px 24px; }

  .mv-title {
    margin: 0 0 18px;
    font-size: 26px; font-weight: 700; letter-spacing: -0.02em;
    word-break: break-word;
  }

  /* Hero copy button. 64px tall on desktop, 60px on mobile, full-width
     always. Gradient + soft glow + arrow that nudges on hover. */
  .mv-copy {
    display: flex; align-items: center; justify-content: center; gap: 12px;
    width: 100%; min-height: 64px;
    padding: 16px 22px; margin: 0 0 18px;
    border: 0; border-radius: 14px; cursor: pointer;
    font: inherit; font-size: 18px; font-weight: 700; color: #fff;
    background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%);
    box-shadow: 0 1px 2px rgba(29,78,216,0.22), 0 12px 28px -10px rgba(29,78,216,0.6);
    transition: transform .08s, filter .15s, box-shadow .15s, background .2s;
    -webkit-tap-highlight-color: rgba(255,255,255,0.2);
  }
  .mv-copy:hover { filter: brightness(1.05); }
  .mv-copy:active { transform: scale(0.985); }
  .mv-copy.is-copied {
    background: linear-gradient(180deg, #16a34a 0%, #15803d 100%);
    box-shadow: 0 1px 2px rgba(22,163,74,0.25), 0 12px 28px -10px rgba(22,163,74,0.65);
  }
  .mv-copy-icon { font-size: 26px; line-height: 1; }

  .mv-body-card {
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 14px;
    padding: 20px 22px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04);
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 16px; line-height: 1.6;
    color: #0f172a;
    /* Native font rendering — emojis show as the user's own emoji set */
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", Roboto, sans-serif;
  }
  .mv-body-card a {
    color: #2563eb; text-decoration: underline;
    text-decoration-thickness: 1px;
    text-underline-offset: 2px;
    word-break: break-all;
  }
  .mv-body-card a:hover { color: #1d4ed8; text-decoration-thickness: 2px; }

  .mv-hint { margin: 14px 0 0; text-align: center; font-size: 13.5px; color: #64748b; }

  /* Mobile sticky bar — only shows after the top button scrolls off */
  .mv-sticky {
    position: fixed; left: 0; right: 0; bottom: 0;
    padding: 10px 16px calc(10px + env(safe-area-inset-bottom));
    background: rgba(255,255,255,0.92);
    backdrop-filter: blur(10px);
    border-top: 1px solid #e5e7eb;
    transform: translateY(100%);
    transition: transform .2s ease-out;
    z-index: 50;
  }
  .mv-sticky.is-visible { transform: translateY(0); }
  .mv-copy--sticky { min-height: 56px; padding: 12px 18px; margin: 0; max-width: 640px; margin: 0 auto; font-size: 16px; }

  @media (min-width: 720px) {
    /* On desktop the top button is always reachable; suppress sticky */
    .mv-sticky { display: none; }
    .mv-body { padding-bottom: 24px; }
  }
`;

// ---------- guest landing page ----------
//
// The money page. Visitors land → drop a file → we upload it in the
// background and ask for an email → they click the magic link → account
// + share link in one go. Keeps the same split-screen aesthetic as the
// auth pages so the brand stays consistent.

function renderGuestLandingPage() {
  const caps = `Images ${fmtBytes(SIZE_CAPS.image)} · Video ${fmtBytes(SIZE_CAPS.video)} · Audio ${fmtBytes(SIZE_CAPS.audio)} · PDFs ${fmtBytes(SIZE_CAPS.pdf)} · Text ${fmtBytes(SIZE_CAPS.text)}`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Share any file — ${escHtml(SITE_NAME)}</title>
  <meta name="robots" content="noindex,nofollow">
  <style>${AUTH_CSS}${LANDING_CSS}</style>
</head>
<body class="auth-body">
  <div class="auth-layout">
    <aside class="auth-brand">
      <div class="auth-brand-inner">
        <a href="/" class="auth-logo">
          <span class="auth-logo-mark">📤</span>
          <span>${escHtml(SITE_NAME)}</span>
        </a>
        <span class="auth-eyebrow">
          <span class="auth-eyebrow-dot"></span>
          FREE — no signup to upload
        </span>
        <h1 class="auth-hero">Drop a file.<br>Share a link.</h1>
        <p class="auth-subtitle">
          No account needed to upload. Just drop any file and we'll send
          your share link to your inbox — one click to activate and
          you're done. <strong style="color:#fff;">Images, video, audio, PDF, markdown, code.</strong>
        </p>
        <ul class="auth-features">
          <li><span class="auth-feat-icon">⚡</span> <div><strong>30-second uploads</strong><span>Drop the file, add your email, click the link — that's it.</span></div></li>
          <li><span class="auth-feat-icon">📥</span> <div><strong>Built-in viewers</strong><span>Your recipients preview in-browser — no downloads needed.</span></div></li>
          <li><span class="auth-feat-icon">🔒</span> <div><strong>Secure by default</strong><span>Per-file download toggle, optional password links, short URLs.</span></div></li>
        </ul>
        <div class="auth-footer-note">Already have an account? <a style="color:#86efac;" href="/login">Sign in →</a></div>
      </div>
    </aside>

    <main class="auth-main">
      <div class="auth-card" style="max-width:520px;">
        <div id="stage-drop">
          <span class="free-pill">
            <span class="free-pill-dot"></span>
            100% FREE · No signup to upload
          </span>
          <h2 class="auth-panel-title">Share any file — free</h2>
          <p class="auth-panel-sub">Drop a file below. We'll email your share link in seconds.</p>

          <form id="guestForm" class="auth-form" novalidate>
            <div class="guest-dropzone" id="dropzone">
              <input id="guest-file" name="file" type="file" required>
              <div class="guest-dropzone-inner">
                <div class="guest-dropzone-icon" id="dropzoneIcon">📤</div>
                <div class="guest-dropzone-text">
                  <strong>Drop your file here</strong>
                  <span class="sub">or click to browse — any type, no account needed</span>
                </div>
                <div class="guest-dropzone-filename" id="dropzoneFilename"></div>
              </div>
            </div>
            <p class="guest-caps">${escHtml(caps)}</p>

            <label class="guest-checkbox" for="guest-allow-download">
              <input id="guest-allow-download" name="allow_download" type="checkbox" checked>
              <span class="guest-checkbox-label">
                Allow recipients to download
                <span class="guest-checkbox-hint">Turn off for preview-only share.</span>
              </span>
            </label>

            <button type="submit" class="auth-submit auth-submit--cta" id="guest-submit">
              Upload &amp; get my FREE link <span class="auth-submit-arrow">→</span>
            </button>
            <div class="progress" id="guest-progress" aria-live="polite" style="display:none;">
              <div class="progress-pct" id="guest-progress-pct">0%</div>
              <div class="progress-bar"><div class="progress-fill" id="guest-progress-fill"></div></div>
              <div class="progress-meta">
                <span><strong id="guest-progress-bytes">0 B / 0 B</strong></span>
                <span id="guest-progress-speed"></span>
                <span id="guest-progress-eta"></span>
              </div>
            </div>
            <p class="auth-error" id="guest-err" style="display:none;"></p>
          </form>
        </div>

        <div id="stage-email" style="display:none;">
          <h2 class="auth-panel-title">Where should we send your link?</h2>
          <p class="auth-panel-sub">Your file is uploaded. Enter your email and we'll send a one-click link to activate and view your share URL.</p>
          <div class="summary-card" id="summary-card"></div>
          <form id="emailForm" class="auth-form" novalidate>
            <div class="auth-field">
              <label for="guest-email">Email</label>
              <input id="guest-email" name="email" type="email" required autocomplete="email" placeholder="you@example.com" autofocus>
            </div>
            <button type="submit" class="auth-submit auth-submit--cta" id="guest-email-submit">
              Email me the share link <span class="auth-submit-arrow">→</span>
            </button>
            <ul class="auth-trust">
              <li><span class="auth-trust-check">✓</span> No credit card</li>
              <li><span class="auth-trust-check">✓</span> Link expires in 15 minutes</li>
              <li><span class="auth-trust-check">✓</span> One-click activation</li>
            </ul>
            <p class="auth-error" id="email-err" style="display:none;"></p>
          </form>
        </div>

        <div id="stage-sent" style="display:none; text-align:center; padding: 8px 0;">
          <div style="font-size:48px; margin-bottom: 8px;">📬</div>
          <h2 class="auth-panel-title" style="text-align:center;">Check your inbox</h2>
          <p class="auth-panel-sub" style="text-align:center;">
            We sent a link to <strong id="sent-email-display"></strong>.
            Click it to activate your share link and create your free account.
          </p>
          <p class="muted" style="font-size:13px; margin-top:16px;">
            Didn't see it? Check spam. Or <a href="#" id="resend-link" style="color:#2563eb; text-decoration:underline;">send it again</a>.
          </p>
        </div>
      </div>
    </main>
  </div>

  <script>
    const SIZE_CAPS = ${JSON.stringify(SIZE_CAPS)};
    function classifyClient(name, mime) {
      const ext = (name.split('.').pop() || '').toLowerCase();
      const m = (mime || '').toLowerCase();
      if (m.startsWith('image/')) return { kind: 'image', cap: SIZE_CAPS.image };
      if (m.startsWith('video/')) return { kind: 'video', cap: SIZE_CAPS.video };
      if (m.startsWith('audio/')) return { kind: 'audio', cap: SIZE_CAPS.audio };
      if (m === 'application/pdf' || ext === 'pdf') return { kind: 'pdf', cap: SIZE_CAPS.pdf };
      return { kind: 'text', cap: SIZE_CAPS.text };
    }
    function fmtBytes(b) { if (!b) return '0 B'; const u=['B','KB','MB','GB']; let i=0,n=b; while(n>=1024&&i<u.length-1){n/=1024;i++;} return (n<10&&i>0?n.toFixed(1):Math.round(n))+' '+u[i]; }
    function fmtEta(s){ if(!Number.isFinite(s)||s<=0)return''; if(s<60)return Math.round(s)+'s left'; if(s<3600)return Math.round(s/60)+'m left'; return (s/3600).toFixed(1)+'h left'; }

    const stageDrop = document.getElementById('stage-drop');
    const stageEmail = document.getElementById('stage-email');
    const stageSent = document.getElementById('stage-sent');
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('guest-file');
    const filenameEl = document.getElementById('dropzoneFilename');
    const iconEl = document.getElementById('dropzoneIcon');
    const btn = document.getElementById('guest-submit');
    const err = document.getElementById('guest-err');
    const progress = document.getElementById('guest-progress');
    const progressFill = document.getElementById('guest-progress-fill');
    const progressPct = document.getElementById('guest-progress-pct');
    const progressBytes = document.getElementById('guest-progress-bytes');
    const progressSpeed = document.getElementById('guest-progress-speed');
    const progressEta = document.getElementById('guest-progress-eta');

    function showFilename() {
      const f = fileInput.files && fileInput.files[0];
      if (f) { filenameEl.textContent = f.name + ' (' + fmtBytes(f.size) + ')'; dropzone.classList.add('has-file'); iconEl.textContent = '✅'; }
      else { filenameEl.textContent = ''; dropzone.classList.remove('has-file'); iconEl.textContent = '📤'; }
    }
    ['dragenter','dragover'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('is-dragover'); }));
    ['dragleave','drop'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('is-dragover'); }));
    dropzone.addEventListener('drop', (e) => { if (e.dataTransfer?.files?.length) { try { fileInput.files = e.dataTransfer.files; } catch {} showFilename(); } });
    fileInput.addEventListener('change', showFilename);

    document.getElementById('guestForm').addEventListener('submit', (ev) => {
      ev.preventDefault();
      err.style.display = 'none';
      const f = fileInput.files && fileInput.files[0];
      if (!f) return;
      const c = classifyClient(f.name, f.type);
      if (f.size > c.cap) {
        err.textContent = f.name + ' is ' + fmtBytes(f.size) + ' but the limit for ' + c.kind + ' files is ' + fmtBytes(c.cap) + '.';
        err.style.display = 'block';
        return;
      }

      const fd = new FormData();
      fd.append('file', f);
      fd.append('allow_download', document.getElementById('guest-allow-download').checked ? 'on' : '');

      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/guest-upload');
      const startedAt = performance.now();
      let lastTime = startedAt, lastLoaded = 0, smoothedBps = 0;
      const ALPHA = 0.25;
      xhr.upload.addEventListener('progress', (e) => {
        if (!e.lengthComputable) return;
        const pct = Math.round((e.loaded / e.total) * 100);
        progressFill.style.width = pct + '%';
        progressPct.textContent = pct + '%';
        progressBytes.textContent = fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total);
        const now = performance.now();
        const dt = (now - lastTime) / 1000;
        if (dt > 0.1) {
          const sampleBps = (e.loaded - lastLoaded) / dt;
          smoothedBps = smoothedBps === 0 ? sampleBps : (ALPHA*sampleBps + (1-ALPHA)*smoothedBps);
          lastTime = now; lastLoaded = e.loaded;
        }
        progressSpeed.textContent = smoothedBps > 0 ? fmtBytes(smoothedBps) + '/s' : '';
        const remaining = (e.total - e.loaded) / Math.max(smoothedBps, 1);
        progressEta.textContent = fmtEta(remaining);
      });
      xhr.addEventListener('load', () => {
        let data = null; try { data = JSON.parse(xhr.responseText); } catch(_) {}
        if (xhr.status >= 200 && xhr.status < 300 && data && data.ok) {
          progressFill.style.width = '100%';
          progressPct.textContent = '100%';
          progressEta.textContent = 'Done!';
          progress.classList.add('is-done');
          setTimeout(() => showEmailStage(data), 350);
        } else {
          btn.disabled = false; btn.textContent = 'Upload and get my link →';
          progress.style.display = 'none';
          progress.classList.remove('is-done');
          err.textContent = (data && data.error) || ('Upload failed: ' + (xhr.status || 'network error'));
          err.style.display = 'block';
        }
      });
      xhr.addEventListener('error', () => {
        btn.disabled = false; btn.textContent = 'Upload and get my link →';
        progress.style.display = 'none';
        err.textContent = 'Upload failed: network error'; err.style.display = 'block';
      });
      btn.disabled = true; btn.textContent = 'Uploading…';
      progress.style.display = 'block';
      progress.classList.add('is-active');
      xhr.send(fd);
    });

    function showEmailStage(data) {
      stageDrop.style.display = 'none';
      stageEmail.style.display = '';
      const card = document.getElementById('summary-card');
      card.className = 'summary-card';
      card.innerHTML =
        '<span class="summary-card-icon">' + data.kindEmoji + '</span>' +
        '<div class="summary-card-text">' +
          '<div class="summary-card-title">' + data.title + '</div>' +
          '<div class="summary-card-meta">' + data.kind + ' · ' + fmtBytes(data.size) + ' · uploaded, ready to activate</div>' +
        '</div>';
    }

    document.getElementById('emailForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const emailErr = document.getElementById('email-err');
      emailErr.style.display = 'none';
      const emailInput = document.getElementById('guest-email');
      const emailBtn = document.getElementById('guest-email-submit');
      const emailAddr = emailInput.value.trim();
      emailBtn.disabled = true; emailBtn.textContent = 'Sending…';
      try {
        const res = await fetch('/api/guest-send-magic', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ email: emailAddr }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Could not send.');
        document.getElementById('sent-email-display').textContent = data.email;
        stageEmail.style.display = 'none';
        stageSent.style.display = '';
      } catch (e) {
        emailErr.textContent = e.message;
        emailErr.style.display = 'block';
        emailBtn.disabled = false; emailBtn.textContent = 'Email me the share link →';
      }
    });

    document.getElementById('resend-link').addEventListener('click', async (e) => {
      e.preventDefault();
      const targetEmail = document.getElementById('sent-email-display').textContent;
      try {
        await fetch('/api/guest-send-magic', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: targetEmail }),
        });
        e.target.textContent = 'Sent again! Check your inbox.';
      } catch { e.target.textContent = 'Resend failed — refresh and try again.'; }
    });
  </script>
</body>
</html>`;
}

// Guest landing page — dropzone + FREE marketing polish. These styles
// are scoped to the landing page only so the authed /upload page keeps
// its existing look. AUTH_CSS doesn't include dropzone styles because
// /login and /signup don't have uploads — we add them here.
const LANDING_CSS = `
  /* Prominent "100% FREE" pill above the upload card title */
  .free-pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 14px;
    background: linear-gradient(90deg, #16a34a 0%, #22c55e 100%);
    color: #fff;
    border-radius: 99px;
    font-size: 12.5px; font-weight: 700; letter-spacing: 0.06em;
    text-transform: uppercase;
    box-shadow: 0 2px 8px -2px rgba(22,163,74,0.45);
    margin-bottom: 14px;
  }
  .free-pill-dot {
    width: 7px; height: 7px; background: #fff; border-radius: 50%;
    box-shadow: 0 0 0 3px rgba(255,255,255,0.35);
    animation: freePulse 1.8s ease-in-out infinite;
  }
  @keyframes freePulse {
    0%, 100% { transform: scale(1); opacity: 1; }
    50%      { transform: scale(1.3); opacity: 0.8; }
  }

  /* Dropzone — the star of the landing page. Dashed border goes green
     to match the free-tier language. Hover and drag-over states pop
     warmly so users feel invited to drop. */
  .guest-dropzone {
    position: relative;
    border: 2px dashed #cbd5e1;
    border-radius: 14px;
    background: #fff;
    transition: border-color .2s, background-color .2s, transform .1s;
    cursor: pointer;
    overflow: hidden;
    margin-bottom: 16px;
  }
  .guest-dropzone:hover { border-color: #16a34a; background: #f0fdf4; }
  .guest-dropzone.is-dragover { border-color: #16a34a; background: #dcfce7; transform: scale(1.01); }
  .guest-dropzone input[type="file"] {
    position: absolute; inset: 0; width: 100%; height: 100%;
    opacity: 0; cursor: pointer;
  }
  .guest-dropzone-inner {
    padding: 44px 24px 40px; text-align: center; pointer-events: none;
  }
  .guest-dropzone-icon {
    font-size: 52px; line-height: 1; margin-bottom: 12px;
    display: inline-block; transition: transform .2s;
  }
  .guest-dropzone:hover .guest-dropzone-icon { transform: translateY(-2px); }
  .guest-dropzone.has-file .guest-dropzone-icon { color: #16a34a; }
  .guest-dropzone-text strong {
    display: block;
    font-size: 18px; font-weight: 600; color: #0f172a;
    letter-spacing: -0.01em; margin-bottom: 4px;
  }
  .guest-dropzone-text .sub {
    display: block;
    font-size: 14px; color: #64748b;
  }
  .guest-dropzone-filename {
    display: none; margin-top: 14px; padding: 8px 14px;
    background: #dcfce7; color: #166534;
    border-radius: 99px; font-weight: 600; font-size: 14px;
    word-break: break-all;
  }
  .guest-dropzone.has-file .guest-dropzone-filename { display: inline-block; }

  .guest-caps {
    font-size: 12px; color: #94a3b8;
    text-align: center; margin: 0 0 14px;
    letter-spacing: 0.02em;
  }

  /* Download-toggle row — subtle so it doesn't compete with the dropzone */
  .guest-checkbox {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 14px;
    background: #f8fafc; border: 1px solid #e5e7eb;
    border-radius: 10px; cursor: pointer;
    margin-bottom: 8px;
  }
  .guest-checkbox input { width: 18px; height: 18px; margin: 0; flex: 0 0 auto; }
  .guest-checkbox-label { flex: 1; font-weight: 500; color: #0f172a; font-size: 14px; }
  .guest-checkbox-hint { display: block; font-weight: 400; font-size: 13px; color: #64748b; margin-top: 2px; }

  /* ---------- Animated rainbow progress bar ----------
     Same shape as the /upload page but scaled up a touch since it's
     the climactic moment on the landing flow — the user's first
     interaction with the product, so worth the drama. */
  .progress { display: none; margin-top: 16px; }
  .progress.is-active { display: block; animation: progFade .25s ease-out; }
  @keyframes progFade { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

  .progress-pct {
    font-size: 44px; font-weight: 700; line-height: 1;
    letter-spacing: -0.02em; text-align: center; margin-bottom: 12px;
    background: linear-gradient(90deg, #2563eb, #9333ea, #ec4899, #f97316);
    background-size: 300% 100%;
    -webkit-background-clip: text; background-clip: text;
    -webkit-text-fill-color: transparent; color: transparent;
    animation: progHue 3s linear infinite;
  }
  @keyframes progHue { 0% { background-position: 0% 50%; } 100% { background-position: 100% 50%; } }

  .progress-bar {
    position: relative; height: 18px;
    background: #e5e7eb; border-radius: 99px; overflow: hidden;
    box-shadow: inset 0 1px 3px rgba(0,0,0,0.08);
  }
  .progress-fill {
    position: relative; height: 100%; width: 0%; border-radius: 99px;
    background: linear-gradient(90deg, #2563eb, #9333ea, #ec4899, #f97316);
    background-size: 200% 100%;
    animation: progSlide 2s linear infinite;
    transition: width .25s cubic-bezier(.4,0,.2,1);
    box-shadow: 0 0 14px rgba(147, 51, 234, 0.5);
  }
  @keyframes progSlide { 0% { background-position: 0% 0%; } 100% { background-position: 200% 0%; } }
  /* Diagonal stripes overlay — keeps the bar feeling alive even when
     the percentage isn't moving (e.g. during a server-side pause). */
  .progress-fill::after {
    content: ''; position: absolute; inset: 0; border-radius: 99px;
    background-image: linear-gradient(45deg,
      rgba(255,255,255,.25) 25%, transparent 25%,
      transparent 50%, rgba(255,255,255,.25) 50%,
      rgba(255,255,255,.25) 75%, transparent 75%, transparent);
    background-size: 28px 28px;
    animation: progStripes 1s linear infinite;
  }
  @keyframes progStripes { 0% { background-position: 0 0; } 100% { background-position: 28px 0; } }

  .progress-meta {
    display: flex; justify-content: space-between; gap: 12px;
    font-size: 13px; color: #64748b; margin-top: 10px; flex-wrap: wrap;
  }
  .progress-meta strong { color: #0f172a; font-weight: 600; }

  /* "Done!" state — green fill, gradient text turns solid green, stripes stop */
  .progress.is-done .progress-fill {
    animation: none;
    background: linear-gradient(90deg, #16a34a, #22c55e);
    box-shadow: 0 0 14px rgba(22, 163, 74, 0.5);
  }
  .progress.is-done .progress-fill::after { animation: none; opacity: 0; }
  .progress.is-done .progress-pct {
    animation: none;
    background: none;
    -webkit-text-fill-color: #16a34a; color: #16a34a;
  }

  /* Summary card shown on the email stage */
  .summary-card {
    padding: 14px 16px;
    background: #f0fdf4; border: 1px solid #bbf7d0;
    border-radius: 10px;
    font-size: 14px; color: #166534;
    margin-bottom: 16px;
    display: flex; align-items: center; gap: 10px;
  }
  .summary-card-icon { font-size: 22px; }
  .summary-card-text { flex: 1; }
  .summary-card-title { font-weight: 600; margin-bottom: 2px; color: #14532d; }
  .summary-card-meta { font-size: 12.5px; color: #166534; opacity: 0.8; }
`;

// ---------- password reset ----------
//
// Flow:
//   GET  /forgot           — email field
//   POST /forgot           — generate token, email link, ALWAYS show generic
//                            "check your email" success to avoid leaking
//                            which emails are registered
//   GET  /reset/:token     — validate token, show new-password form
//   POST /reset/:token     — set new password, clear token
//
// The token stored in DB is sha256(raw). The link carries the raw token.

function hashToken(raw) {
  return crypto.createHash('sha256').update(String(raw)).digest('hex');
}

app.get('/forgot', (req, res) => {
  const sent = req.query.sent === '1';
  res.send(renderStandaloneAuthPage({
    title: sent ? 'Check your inbox' : 'Forgot your password?',
    subtitle: sent
      ? `If an account exists for that email, we just sent a reset link. It expires in 24 hours.`
      : `Enter your email and we'll send a link to set a new password. The link works once and expires in 24 hours.`,
    body: sent ? `
      <div class="auth-form">
        <p class="auth-panel-sub" style="margin:0;">Didn't get anything after a minute? Check your spam folder, or request a fresh link.</p>
      </div>
      <p class="auth-switch"><a href="/forgot">Send another link</a> · <a href="/login">Back to sign in</a></p>
    ` : `
      <form method="POST" action="/forgot" class="auth-form" novalidate>
        <div class="auth-field">
          <label for="forgot-email">Email</label>
          <input id="forgot-email" name="email" type="email" required autocomplete="email" autofocus placeholder="you@example.com">
        </div>
        <button type="submit" class="auth-submit">Email me a reset link <span class="auth-submit-arrow">→</span></button>
      </form>
      <p class="auth-switch">Remembered it? <a href="/login">Back to sign in</a></p>
    `,
  }));
});

app.post('/forgot', express.urlencoded({ extended: false }), async (req, res) => {
  const emailAddr = (req.body.email || '').toLowerCase().trim();
  // Always redirect to the generic "sent" page so an attacker can't tell
  // whether the email is registered (account enumeration protection).
  const done = () => res.redirect('/forgot?sent=1');

  const row = udb.getByEmail(emailAddr);
  if (!row) return done();
  if (row.status === 'deactivated') return done();

  try {
    // Invalidate any previously-issued outstanding tokens so only the
    // newest link works.
    prdb.invalidateForUser(row.id);
    prdb.sweep(); // Lazy cleanup — no cron needed at this scale.

    const rawToken = crypto.randomBytes(32).toString('base64url');
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
      .replace('T', ' ').replace(/\..+$/, ''); // "YYYY-MM-DD HH:MM:SS" to match SQLite datetime()
    prdb.create({ userId: row.id, tokenHash, expiresAt });

    const resetUrl = `${PUBLIC_ORIGIN}/reset/${rawToken}`;

    if (!email.isConfigured()) {
      // Graceful degradation: without SMTP wired up, at least log the URL
      // so an admin can deliver it out-of-band during initial rollout.
      console.log(`[forgot] email not configured — reset url for ${emailAddr}: ${resetUrl}`);
    } else {
      try {
        await email.sendPasswordResetEmail({
          toEmail: row.email,
          toName: row.name,
          resetUrl,
          siteName: SITE_NAME,
        });
        console.log(`[forgot] sent reset email to ${row.email}`);
      } catch (err) {
        console.error(`[forgot] send failed for ${row.email}:`, err.message);
        // Still return generic success so enumeration protection holds.
      }
    }
  } catch (err) {
    console.error('[forgot] error:', err);
  }
  return done();
});

app.get('/reset/:token', (req, res) => {
  const tokenHash = hashToken(req.params.token);
  const row = prdb.getByHash(tokenHash);
  const expired = !row || row.used_at || new Date(row.expires_at.replace(' ', 'T') + 'Z') < new Date();
  if (expired) {
    return res.send(renderStandaloneAuthPage({
      title: 'Link expired or used',
      subtitle: `Reset links work once and expire after 24 hours. Request a new one to continue.`,
      body: `
        <p class="auth-switch"><a href="/forgot">Request a new link</a> · <a href="/login">Back to sign in</a></p>
      `,
    }));
  }
  const err = req.query.err ? decodeURIComponent(req.query.err) : '';
  res.send(renderStandaloneAuthPage({
    title: 'Set a new password',
    subtitle: `Pick something you'll remember. Minimum 8 characters.`,
    body: `
      <form method="POST" action="/reset/${escHtml(req.params.token)}" class="auth-form" novalidate>
        <div class="auth-field">
          <label for="reset-password">New password</label>
          <input id="reset-password" name="password" type="password" required minlength="8" autocomplete="new-password" autofocus placeholder="At least 8 characters">
        </div>
        <div class="auth-field">
          <label for="reset-confirm">Confirm new password</label>
          <input id="reset-confirm" name="confirm" type="password" required minlength="8" autocomplete="new-password" placeholder="Re-type password">
        </div>
        <button type="submit" class="auth-submit">Update password <span class="auth-submit-arrow">→</span></button>
        ${err ? `<div class="auth-error">${escHtml(err)}</div>` : ''}
      </form>
    `,
  }));
});

app.post('/reset/:token', express.urlencoded({ extended: false }), (req, res) => {
  const raw = req.params.token;
  const tokenHash = hashToken(raw);
  try {
    const row = prdb.getByHash(tokenHash);
    if (!row) throw new Error('Link is invalid.');
    if (row.used_at) throw new Error('Link already used.');
    if (new Date(row.expires_at.replace(' ', 'T') + 'Z') < new Date()) throw new Error('Link has expired.');

    const { password, confirm } = req.body || {};
    if (!password || password.length < 8) throw new Error('Password must be at least 8 characters.');
    if (password !== confirm) throw new Error('Passwords do not match.');

    udb.setPasswordHash(row.user_id, users.hashPassword(password));
    prdb.markUsed(tokenHash);
    // Invalidate any other outstanding tokens for this user too — belt
    // and suspenders if multiple reset links were in flight.
    prdb.invalidateForUser(row.user_id);
    // Sign them in immediately so they don't have to type the fresh
    // password they just set. Cleaner UX than bouncing back to /login.
    setAuthCookie(res, row.user_id);
    console.log(`[reset] user=${row.user_id} password updated via email token`);
    return res.redirect('/upload');
  } catch (err) {
    return res.redirect('/reset/' + encodeURIComponent(raw) + '?err=' + encodeURIComponent(err.message));
  }
});

// Small helper for pages that reuse the split-screen aesthetic but show
// only a single panel (/forgot, /reset/:token, future /verify, etc.) —
// no tab switcher since there's nothing to switch to.
function renderStandaloneAuthPage({ title, subtitle, body }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escHtml(title)} — ${escHtml(SITE_NAME)}</title>
  <meta name="robots" content="noindex,nofollow">
  <style>${AUTH_CSS}</style>
</head>
<body class="auth-body">
  <div class="auth-layout">
    <aside class="auth-brand">
      <div class="auth-brand-inner">
        <a href="/" class="auth-logo">
          <span class="auth-logo-mark">📤</span>
          <span>${escHtml(SITE_NAME)}</span>
        </a>
        <h1 class="auth-hero">Share any file.<br>Skip the hassle.</h1>
        <p class="auth-subtitle">
          Drop an image, video, audio clip, PDF, or text file — get a share link with a
          built-in viewer. Your recipients see it in their browser, no app needed.
        </p>
      </div>
    </aside>
    <main class="auth-main">
      <div class="auth-card">
        <section class="auth-panel">
          <h2 class="auth-panel-title">${escHtml(title)}</h2>
          <p class="auth-panel-sub">${escHtml(subtitle)}</p>
          ${body}
        </section>
      </div>
    </main>
  </div>
</body>
</html>`;
}

// ---------- auth page renderer ----------
//
// Full-bleed split layout — gradient brand panel on the left, white auth
// card with Sign-in / Sign-up tabs on the right. Both forms ship in the
// same page so the tab switch is instant; the server decides which tab
// is visible on first paint based on the URL path (/login vs /signup).

function renderAuthPage({ activeTab, loginErr, signupErr }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${activeTab === 'signup' ? 'Sign up' : 'Sign in'} — ${escHtml(SITE_NAME)}</title>
  <meta name="robots" content="noindex,nofollow">
  <style>${AUTH_CSS}</style>
</head>
<body class="auth-body">
  <div class="auth-layout">
    <aside class="auth-brand">
      <div class="auth-brand-inner">
        <a href="/" class="auth-logo" aria-label="${escHtml(SITE_NAME)} — home">
          <span class="auth-logo-mark">📤</span>
          <span>${escHtml(SITE_NAME)}</span>
        </a>
        <span class="auth-eyebrow">
          <span class="auth-eyebrow-dot"></span>
          FREE to start — no credit card
        </span>
        <h1 class="auth-hero">Share any file.<br>Skip the hassle.</h1>
        <p class="auth-subtitle">
          Drop an image, video, audio clip, PDF, or text file — get a share link with a
          built-in viewer. Your recipients see it in their browser, no app needed.
          <strong style="color:#fff;">Start free in 30 seconds.</strong>
        </p>
        <ul class="auth-features">
          <li><span class="auth-feat-icon">🎬</span> <div><strong>Stream & seek</strong><span>Video and audio play right in the browser with full controls.</span></div></li>
          <li><span class="auth-feat-icon">📄</span> <div><strong>PDF viewer built in</strong><span>Page nav, zoom, search, and thumbnails — no download needed.</span></div></li>
          <li><span class="auth-feat-icon">📝</span> <div><strong>Markdown & code</strong><span>Markdown renders nicely. Code files show as formatted text.</span></div></li>
          <li><span class="auth-feat-icon">🔒</span> <div><strong>You control downloads</strong><span>Per-file toggle decides whether recipients can save a copy.</span></div></li>
        </ul>
        <div class="auth-footer-note">
          Your files, your folder — connect your own GoHighLevel storage anytime.
        </div>
      </div>
    </aside>

    <main class="auth-main">
      <div class="auth-card">
        <div class="auth-tabs" role="tablist" aria-label="Authentication">
          <button type="button" class="auth-tab${activeTab === 'login' ? ' is-active' : ''}"
                  role="tab" aria-selected="${activeTab === 'login'}" data-tab="login"
                  aria-controls="panel-login" id="tab-login">Sign in</button>
          <button type="button" class="auth-tab${activeTab === 'signup' ? ' is-active' : ''}"
                  role="tab" aria-selected="${activeTab === 'signup'}" data-tab="signup"
                  aria-controls="panel-signup" id="tab-signup">Start Free <span class="auth-tab-badge">FREE</span></button>
        </div>

        <section id="panel-login" class="auth-panel${activeTab === 'login' ? '' : ' is-hidden'}" role="tabpanel" aria-labelledby="tab-login">
          <h2 class="auth-panel-title">Welcome back</h2>
          <p class="auth-panel-sub">Sign in to manage your shared files.</p>
          <form method="POST" action="/login" class="auth-form" novalidate>
            <div class="auth-field">
              <label for="login-email">Email</label>
              <input id="login-email" name="email" type="email" required autocomplete="email" placeholder="you@example.com">
            </div>
            <div class="auth-field">
              <label for="login-password" class="auth-label-row">
                <span>Password</span>
                <a href="/forgot" class="auth-forgot">Forgot?</a>
              </label>
              <input id="login-password" name="password" type="password" required autocomplete="current-password" placeholder="••••••••">
            </div>
            <button type="submit" class="auth-submit">Sign in <span class="auth-submit-arrow">→</span></button>
            ${loginErr ? `<div class="auth-error">${escHtml(loginErr)}</div>` : ''}
          </form>
          <p class="auth-switch">New here? <a href="/signup" data-tab-link="signup">Create an account</a></p>
        </section>

        <section id="panel-signup" class="auth-panel${activeTab === 'signup' ? '' : ' is-hidden'}" role="tabpanel" aria-labelledby="tab-signup">
          <h2 class="auth-panel-title">Start sharing — free</h2>
          <p class="auth-panel-sub">No credit card. 5 uploads to try everything. Upgrade only when you're ready.</p>
          <form method="POST" action="/signup" class="auth-form" novalidate>
            <div class="auth-field">
              <label for="signup-name">Your name</label>
              <input id="signup-name" name="name" type="text" required autocomplete="name" placeholder="Alex Kim">
            </div>
            <div class="auth-field">
              <label for="signup-email">Email</label>
              <input id="signup-email" name="email" type="email" required autocomplete="email" placeholder="you@example.com">
            </div>
            <div class="auth-field">
              <label for="signup-password">Password</label>
              <input id="signup-password" name="password" type="password" required minlength="8" autocomplete="new-password" placeholder="At least 8 characters">
            </div>
            <div class="auth-field">
              <label for="signup-confirm">Confirm password</label>
              <input id="signup-confirm" name="confirm" type="password" required minlength="8" autocomplete="new-password" placeholder="Re-type password">
            </div>
            <button type="submit" class="auth-submit auth-submit--cta">Start Sharing FREE <span class="auth-submit-arrow">→</span></button>
            <ul class="auth-trust">
              <li><span class="auth-trust-check">✓</span> No credit card</li>
              <li><span class="auth-trust-check">✓</span> 5 free uploads</li>
              <li><span class="auth-trust-check">✓</span> 30-second setup</li>
            </ul>
            ${signupErr ? `<div class="auth-error">${escHtml(signupErr)}</div>` : ''}
          </form>
          <p class="auth-switch">Already have an account? <a href="/login" data-tab-link="login">Sign in</a></p>
        </section>
      </div>
    </main>
  </div>

  <script>
    (function () {
      const tabs = document.querySelectorAll('.auth-tab');
      const panels = {
        login:  document.getElementById('panel-login'),
        signup: document.getElementById('panel-signup'),
      };
      function activate(which) {
        tabs.forEach(t => {
          const isActive = t.dataset.tab === which;
          t.classList.toggle('is-active', isActive);
          t.setAttribute('aria-selected', String(isActive));
        });
        Object.entries(panels).forEach(([k, el]) => {
          if (!el) return;
          el.classList.toggle('is-hidden', k !== which);
        });
        // Update the URL (and page title) without a reload so bookmarks + the
        // back button behave naturally.
        try {
          history.replaceState(null, '', which === 'signup' ? '/signup' : '/login');
          document.title = (which === 'signup' ? 'Sign up' : 'Sign in') + ' — ' + ${JSON.stringify(SITE_NAME)};
        } catch (_) {}
        // Focus the first empty field for smoother UX.
        const firstInput = panels[which].querySelector('input:not([type="hidden"])');
        if (firstInput) setTimeout(() => firstInput.focus(), 50);
      }
      tabs.forEach(t => t.addEventListener('click', () => activate(t.dataset.tab)));
      document.querySelectorAll('[data-tab-link]').forEach(a => {
        a.addEventListener('click', (e) => { e.preventDefault(); activate(a.dataset.tabLink); });
      });
    })();
  </script>
</body>
</html>`;
}

const AUTH_CSS = `
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  .auth-body { font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; color: #0f172a; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; background: #fff; }

  .auth-layout { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr); min-height: 100vh; }
  @media (max-width: 960px) { .auth-layout { grid-template-columns: 1fr; } }

  /* ---------- LEFT: brand + marketing ---------- */
  .auth-brand {
    position: relative; overflow: hidden;
    background:
      radial-gradient(1200px 600px at -10% -20%, rgba(99,102,241,0.35) 0%, transparent 60%),
      radial-gradient(900px 500px at 110% 120%, rgba(236,72,153,0.30) 0%, transparent 60%),
      linear-gradient(135deg, #0b1220 0%, #0f172a 50%, #1a2540 100%);
    color: #fff;
    padding: 56px 48px;
    display: flex; align-items: center; justify-content: center;
  }
  .auth-brand::before {
    content: ""; position: absolute; inset: 0;
    background-image:
      linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px);
    background-size: 48px 48px;
    -webkit-mask-image: radial-gradient(ellipse at center, rgba(0,0,0,0.6), transparent 70%);
            mask-image: radial-gradient(ellipse at center, rgba(0,0,0,0.6), transparent 70%);
    pointer-events: none;
  }
  .auth-brand-inner { position: relative; z-index: 1; max-width: 500px; width: 100%; }
  .auth-logo { display: inline-flex; align-items: center; gap: 10px; color: #fff; text-decoration: none; font-weight: 700; font-size: 17px; letter-spacing: -0.01em; margin-bottom: 40px; opacity: 0.95; }
  .auth-logo:hover { opacity: 1; }
  .auth-logo-mark { font-size: 22px; line-height: 1; }

  /* Green "FREE to start" eyebrow pill — pops against the dark brand panel. */
  .auth-eyebrow {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 14px;
    background: rgba(34, 197, 94, 0.14);
    border: 1px solid rgba(34, 197, 94, 0.38);
    border-radius: 99px;
    font-size: 12.5px; font-weight: 600; letter-spacing: 0.04em;
    color: #86efac; text-transform: uppercase;
    margin-bottom: 18px;
  }
  .auth-eyebrow-dot {
    width: 8px; height: 8px; background: #22c55e; border-radius: 50%;
    box-shadow: 0 0 0 3px rgba(34,197,94,0.3);
    animation: eyebrowPulse 2s ease-in-out infinite;
  }
  @keyframes eyebrowPulse {
    0%, 100% { box-shadow: 0 0 0 3px rgba(34,197,94,0.3); }
    50%      { box-shadow: 0 0 0 6px rgba(34,197,94,0.12); }
  }

  .auth-hero {
    font-size: clamp(30px, 4vw, 44px);
    line-height: 1.08; letter-spacing: -0.03em; font-weight: 700;
    margin: 0 0 18px;
    background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%);
    -webkit-background-clip: text; background-clip: text;
    -webkit-text-fill-color: transparent; color: transparent;
  }
  .auth-subtitle { font-size: 16.5px; line-height: 1.55; color: rgba(226,232,240,0.82); margin: 0 0 36px; max-width: 44ch; }

  .auth-features { list-style: none; padding: 0; margin: 0 0 36px; display: flex; flex-direction: column; gap: 14px; }
  .auth-features li { display: flex; align-items: flex-start; gap: 14px; padding: 14px 16px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; backdrop-filter: blur(6px); }
  .auth-feat-icon { font-size: 20px; line-height: 1.2; flex: 0 0 auto; width: 36px; height: 36px; display: inline-flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.06); border-radius: 10px; border: 1px solid rgba(255,255,255,0.08); }
  .auth-features li > div { display: flex; flex-direction: column; gap: 2px; }
  .auth-features li strong { font-size: 14px; font-weight: 600; color: #fff; }
  .auth-features li span { font-size: 13px; color: rgba(226,232,240,0.7); line-height: 1.4; }

  .auth-footer-note { font-size: 13px; color: rgba(226,232,240,0.55); padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.08); }

  @media (max-width: 960px) {
    .auth-brand { padding: 40px 24px; }
    .auth-logo { margin-bottom: 32px; }
    .auth-features { gap: 10px; margin-bottom: 24px; }
  }

  /* ---------- RIGHT: auth card ---------- */
  .auth-main { display: flex; align-items: center; justify-content: center; padding: 56px 24px; background: linear-gradient(180deg, #fafbff 0%, #f3f5fb 100%); }
  .auth-card {
    width: 100%; max-width: 460px;
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 20px;
    padding: 36px 32px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04), 0 20px 50px -20px rgba(15,23,42,0.14);
  }
  @media (max-width: 480px) { .auth-card { padding: 28px 22px; border-radius: 16px; } }

  .auth-tabs { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; padding: 4px; background: #f1f5f9; border-radius: 12px; margin-bottom: 28px; }
  .auth-tab {
    padding: 10px 14px; border: 0; background: transparent;
    font: inherit; font-size: 14px; font-weight: 600; color: #64748b;
    cursor: pointer; border-radius: 9px; transition: background-color .18s, color .18s, box-shadow .18s;
  }
  .auth-tab:hover { color: #0f172a; }
  .auth-tab.is-active { background: #fff; color: #0f172a; box-shadow: 0 1px 2px rgba(15,23,42,0.08), 0 1px 3px rgba(15,23,42,0.04); }
  .auth-tab:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; }

  /* Tiny green "FREE" pill inside the Start Free tab. Visible on both the
     active and inactive state — even on /login it reminds visitors signup
     is free. */
  .auth-tab-badge {
    display: inline-block; margin-left: 6px; padding: 2px 6px;
    background: #16a34a; color: #fff;
    font-size: 9.5px; font-weight: 700; letter-spacing: 0.06em;
    border-radius: 4px; vertical-align: middle;
    box-shadow: 0 1px 2px rgba(22,163,74,0.3);
  }

  .auth-panel { animation: authFade .25s ease-out; }
  .auth-panel.is-hidden { display: none; }
  @keyframes authFade { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

  .auth-panel-title { margin: 0 0 4px; font-size: 24px; font-weight: 700; letter-spacing: -0.02em; color: #0f172a; }
  .auth-panel-sub { margin: 0 0 24px; font-size: 14px; color: #64748b; line-height: 1.45; }

  .auth-form { display: flex; flex-direction: column; gap: 16px; }
  .auth-field { display: flex; flex-direction: column; gap: 6px; }
  .auth-field label { font-size: 13px; font-weight: 600; color: #334155; }
  .auth-label-row { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
  .auth-forgot { font-weight: 500; font-size: 12.5px; color: #64748b; text-decoration: none; }
  .auth-forgot:hover { color: #2563eb; text-decoration: underline; }
  .auth-field input {
    padding: 11px 13px; font: inherit; font-size: 15px;
    border: 1px solid #e5e7eb; border-radius: 10px; background: #fff; color: #0f172a;
    transition: border-color .15s, box-shadow .15s, background-color .15s;
  }
  .auth-field input::placeholder { color: #94a3b8; }
  .auth-field input:hover { border-color: #cbd5e1; }
  .auth-field input:focus { outline: 0; border-color: #2563eb; box-shadow: 0 0 0 4px rgba(37,99,235,0.12); }

  .auth-submit {
    margin-top: 8px;
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 12px 16px; min-height: 48px;
    border: 0; border-radius: 10px; cursor: pointer;
    font: inherit; font-size: 15px; font-weight: 600; color: #fff;
    background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%);
    box-shadow: 0 1px 2px rgba(29,78,216,0.2), 0 6px 18px -6px rgba(29,78,216,0.5);
    transition: transform .1s, box-shadow .15s, filter .15s;
  }
  .auth-submit:hover { filter: brightness(1.05); box-shadow: 0 2px 4px rgba(29,78,216,0.22), 0 10px 24px -6px rgba(29,78,216,0.55); }
  .auth-submit:active { transform: translateY(1px); }
  .auth-submit-arrow { transition: transform .15s; }
  .auth-submit:hover .auth-submit-arrow { transform: translateX(2px); }

  /* Emphasis variant for the signup CTA — green gradient so it reads as
     "start free" instead of generic "submit". */
  .auth-submit--cta {
    background: linear-gradient(180deg, #22c55e 0%, #16a34a 100%);
    box-shadow: 0 1px 2px rgba(22,163,74,0.22), 0 8px 20px -6px rgba(22,163,74,0.55);
    font-size: 16px; min-height: 52px; letter-spacing: 0.01em;
  }
  .auth-submit--cta:hover { box-shadow: 0 2px 4px rgba(22,163,74,0.24), 0 12px 26px -6px rgba(22,163,74,0.6); }

  /* Trust bullets under the Start Free CTA. */
  .auth-trust {
    list-style: none; padding: 0; margin: 12px 0 0;
    display: flex; gap: 14px; flex-wrap: wrap; justify-content: center;
    font-size: 12.5px; color: #64748b;
  }
  .auth-trust li { display: inline-flex; align-items: center; gap: 5px; }
  .auth-trust-check { color: #16a34a; font-weight: 700; }

  .auth-error { margin-top: 4px; padding: 10px 12px; background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; border-radius: 10px; font-size: 13.5px; }

  .auth-switch { margin: 20px 0 0; text-align: center; font-size: 14px; color: #64748b; }
  .auth-switch a { color: #2563eb; font-weight: 600; text-decoration: none; }
  .auth-switch a:hover { text-decoration: underline; }
`;

app.post('/signup', express.urlencoded({ extended: false }), (req, res) => {
  try {
    const { name, email, password, confirm } = req.body || {};
    if (password !== confirm) throw new Error('Passwords do not match.');
    const u = users.signup({ name, email, password });
    setAuthCookie(res, u.id);
    return res.redirect('/upload');
  } catch (err) {
    return res.redirect('/signup?err=' + encodeURIComponent(err.message));
  }
});

// ---------- account (change-password) ----------

app.get('/account', requireUser, (req, res) => {
  const pwMsg = req.query.pw === 'ok' ? 'Password updated.' : '';
  const pwErr = req.query.pw_err ? decodeURIComponent(req.query.pw_err) : '';
  const ghlMsg = req.query.ghl === 'ok'  ? 'Your GHL storage is connected.'
              : req.query.ghl === 'cleared' ? 'Switched back to shared storage.' : '';
  const ghlErr = req.query.ghl_err ? decodeURIComponent(req.query.ghl_err) : '';

  // Reload so we see any columns the seed migration just added.
  const row = udb.getById(req.user.id);
  const cfg = users.effectiveGhlConfig(row);
  const canCustomize = req.user.status === 'regular' || req.user.is_admin;

  const ghlSection = canCustomize ? `
    <h2>Your GHL storage</h2>
    <div class="card stack">
      <p class="muted" style="margin: 0;">
        By default your uploads go to the shared folder. Connect your own GoHighLevel sub-account and folder
        and your future uploads will land there instead. Already-uploaded files stay where they are.
      </p>
      <div>
        <strong>Current target:</strong>
        ${cfg.source === 'user'
          ? `<span class="pill" style="background:#16a34a1a;color:#16a34a;border:1px solid #16a34a55;">your folder</span>
             <span class="muted" style="font-size:13px;">${escHtml(cfg.folderName)} in location ${escHtml(cfg.locationId)}</span>`
          : `<span class="pill" style="background:#64748b1a;color:#64748b;border:1px solid #64748b55;">shared folder</span>`}
      </div>
    </div>
    <form class="card stack" method="POST" action="/account/ghl-settings">
      <div>
        <label for="pit">PIT token</label>
        <input id="pit" name="pit" type="password" placeholder="${row.ghl_api_key ? '•••••• (saved — retype to change)' : 'pit-xxxxxxxx-xxxx-...'}" autocomplete="off">
        <p class="muted" style="font-size: 12px; margin: 4px 0 0;">
          Create one in GHL: Settings → Private Integrations → + Create. Needs the <em>medias.write</em> and <em>medias.readonly</em> scopes.
        </p>
      </div>
      <div>
        <label for="location">Location ID</label>
        <input id="location" name="location" type="text" value="${escHtml(row.ghl_location_id || '')}" placeholder="the sub-account location id">
      </div>
      <div>
        <label for="folder">Folder name (must already exist in GHL)</label>
        <input id="folder" name="folder" type="text" value="${escHtml(row.ghl_folder_name || '')}" placeholder="e.g. ${escHtml(SITE_NAME)}">
        <p class="muted" style="font-size: 12px; margin: 4px 0 0;">
          Create the folder in the GHL media library first, then paste the exact name here. We'll look it up and save its id.
        </p>
      </div>
      <div class="row">
        <button type="submit" class="btn">Save &amp; test</button>
        ${cfg.source === 'user' ? `<button type="submit" class="btn btn-secondary" formaction="/account/ghl-settings/clear" formnovalidate>Use shared folder instead</button>` : ''}
      </div>
      ${ghlMsg ? `<p class="ok">${escHtml(ghlMsg)}</p>` : ''}
      ${ghlErr ? `<p class="err">${escHtml(ghlErr)}</p>` : ''}
    </form>
  ` : `
    <h2>Your GHL storage</h2>
    <div class="card">
      <p class="muted" style="margin: 0;">
        Trial accounts use the shared storage. Ask the admin to upgrade your account to <strong>regular</strong>
        and you'll be able to connect your own GoHighLevel sub-account and folder here.
      </p>
    </div>
  `;

  res.send(layout({
    title: 'Account — ' + SITE_NAME,
    user: req.user,
    body: `
      <h1>Your account</h1>
      <div class="card stack">
        <div><strong>Name:</strong> ${escHtml(req.user.name)}</div>
        <div><strong>Email:</strong> ${escHtml(req.user.email)}</div>
        <div><strong>Status:</strong> ${statusPill(req.user.status)}${req.user.is_admin ? ' ' + statusPill('admin') : ''}</div>
      </div>

      <h2>Change password</h2>
      <form class="card stack" method="POST" action="/account/change-password">
        <div>
          <label for="current">Current password</label>
          <input id="current" name="current" type="password" required autocomplete="current-password">
        </div>
        <div>
          <label for="next">New password (min 8 chars)</label>
          <input id="next" name="next" type="password" required minlength="8" autocomplete="new-password">
        </div>
        <div>
          <label for="confirm">Confirm new password</label>
          <input id="confirm" name="confirm" type="password" required minlength="8" autocomplete="new-password">
        </div>
        <button type="submit" class="btn btn-block">Update password</button>
        ${pwMsg ? `<p class="ok">${escHtml(pwMsg)}</p>` : ''}
        ${pwErr ? `<p class="err">${escHtml(pwErr)}</p>` : ''}
      </form>

      ${ghlSection}
    `,
  }));
});

app.post('/account/change-password', requireUser, express.urlencoded({ extended: false }), (req, res) => {
  try {
    const { current, next, confirm } = req.body || {};
    if (!current || !next || !confirm) throw new Error('All fields are required.');
    if (next !== confirm) throw new Error('New passwords do not match.');

    // Load the full row (we need the hash, which sanitize strips).
    const row = udb.getById(req.user.id);
    if (!row || !users.verifyPassword(current, row.password_hash)) {
      throw new Error('Current password is wrong.');
    }
    udb.setPasswordHash(req.user.id, users.hashPassword(next));
    return res.redirect('/account?pw=ok');
  } catch (err) {
    return res.redirect('/account?pw_err=' + encodeURIComponent(err.message));
  }
});

// Save GHL storage settings. We validate live: the PIT must authenticate
// against the given location, and the folder name must resolve to an id
// via the folders-list endpoint. If any check fails, nothing is saved.
app.post('/account/ghl-settings', requireUser, express.urlencoded({ extended: false }), (req, res) => {
  if (!(req.user.status === 'regular' || req.user.is_admin)) {
    return res.redirect('/account?ghl_err=' + encodeURIComponent('Upgrade to a regular account to customize storage.'));
  }
  try {
    const row = udb.getById(req.user.id);
    const newPit      = (req.body.pit      || '').trim();
    const locationId  = (req.body.location || '').trim();
    const folderName  = (req.body.folder   || '').trim();
    if (!locationId) throw new Error('Location ID is required.');
    if (!folderName) throw new Error('Folder name is required.');

    // PIT is optional on re-save — leaving it blank means "keep the one we already have"
    const apiKey = newPit || row.ghl_api_key || '';
    if (!apiKey) throw new Error('PIT token is required on first save.');

    // Validate with a live list-folders call; also resolves folder id
    const folder = ghl.findFolderByName({ apiKey, locationId, folderName });
    if (!folder) throw new Error(`No folder named "${folderName}" in that location. Create it in GHL first.`);

    udb.setGhlConfig(req.user.id, {
      apiKey, locationId, folderId: folder._id, folderName: folder.name,
    });
    console.log(`[ghl-cfg] user=${req.user.id} set custom target location=${locationId} folder=${folder._id}`);
    return res.redirect('/account?ghl=ok');
  } catch (err) {
    console.warn(`[ghl-cfg] user=${req.user.id} save failed: ${err.message}`);
    return res.redirect('/account?ghl_err=' + encodeURIComponent(err.message));
  }
});

app.post('/account/ghl-settings/clear', requireUser, (req, res) => {
  if (!(req.user.status === 'regular' || req.user.is_admin)) {
    return res.redirect('/account');
  }
  udb.setGhlConfig(req.user.id, { apiKey: null, locationId: null, folderId: null, folderName: null });
  console.log(`[ghl-cfg] user=${req.user.id} reverted to shared`);
  return res.redirect('/account?ghl=cleared');
});

// ---------- messages (DM/snippet library) ----------
//
// User saves formatted messages once, taps a big copy button to
// drop the exact text into Instagram / WhatsApp / Facebook DMs.
// Public viewer at /m/<slug> exposes the same copy button so a
// teammate can be sent the URL and copy the message themselves.

const MSG_PAGE_SIZE = 20;

function fmtMsgDate(s) { return fmtGstTimestamp(s); }
function bodyPreview(body, max = 220) {
  const t = (body || '').toString();
  if (t.length <= max) return t;
  return t.slice(0, max).trimEnd() + '…';
}

/**
 * HTML-escape `text` and turn any http(s):// URL into an <a> opening
 * in a new tab. Trailing punctuation (.,;:!?)]}) is kept OUTSIDE the
 * link so a sentence-ending period or paren doesn't break the URL.
 *
 * Used for *display only*. The copy button reads from a separate
 * data-body attribute that stores the original raw text, so what
 * lands on the user's clipboard is still the plain URL they typed —
 * not the HTML markup.
 */
function linkifyHtml(text) {
  const URL_RE = /(https?:\/\/[^\s<>"]+?)([.,;:!?)\]}]*)(?=\s|$)/g;
  let out = '';
  let last = 0;
  let m;
  while ((m = URL_RE.exec(text)) !== null) {
    out += escHtml(text.slice(last, m.index));
    const escUrl = escHtml(m[1]);
    out += `<a href="${escUrl}" target="_blank" rel="noopener noreferrer">${escUrl}</a>`;
    out += escHtml(m[2]);
    last = m.index + m[0].length;
  }
  out += escHtml(text.slice(last));
  return out;
}

function renderMessageCard(m, publicOrigin) {
  const url = `${publicOrigin}/m/${m.slug}`;
  const title = m.title || '(untitled message)';
  const preview = bodyPreview(m.body, 240);
  // JSON-encode the body so the data attribute survives quotes,
  // newlines, emojis, everything. Decoded back via JSON.parse.
  const bodyJson = JSON.stringify(m.body);
  return `
    <div class="msg-card" data-id="${m.id}" data-slug="${escHtml(m.slug)}">
      <div class="msg-card-head">
        <div class="msg-card-head-text">
          <h3 class="msg-card-title">${escHtml(title)}</h3>
          <span class="msg-card-date">${escHtml(fmtMsgDate(m.updated_at || m.created_at))}</span>
        </div>
        <div class="msg-reorder" role="group" aria-label="Reorder">
          <button type="button" class="msg-reorder-btn msg-up-btn"   aria-label="Move up"   title="Move up">↑</button>
          <button type="button" class="msg-reorder-btn msg-down-btn" aria-label="Move down" title="Move down">↓</button>
        </div>
      </div>
      <pre class="msg-card-preview">${linkifyHtml(preview)}</pre>
      <button type="button" class="btn-copy-big" data-body='${escHtml(bodyJson)}'>
        <span class="btn-copy-icon">📋</span>
        <span class="btn-copy-label">Copy message</span>
      </button>
      <div class="msg-card-actions">
        <a class="btn btn-secondary btn-sm" href="/m/${escHtml(m.slug)}" target="_blank" rel="noopener">Open</a>
        <a class="btn btn-secondary btn-sm" href="/messages/${escHtml(m.slug)}/edit">Edit</a>
        <button type="button" class="btn btn-secondary btn-sm copy-link-btn" data-url="${escHtml(url)}">Copy link</button>
        <button type="button" class="btn btn-danger btn-sm msg-delete-btn">Delete</button>
      </div>
    </div>
  `;
}

app.get('/messages', requireUser, (req, res) => {
  const q = (req.query.q || '').toString().trim().slice(0, 100);
  const firstPage = mdb.listRecentByUser(req.user.id, { limit: MSG_PAGE_SIZE, q });
  const nextCursor = firstPage.length === MSG_PAGE_SIZE
    ? firstPage[firstPage.length - 1].id : null;
  const hasAny = firstPage.length > 0 || q;

  const justSavedSlug = req.query.saved ? req.query.saved.toString().slice(0, 32) : '';

  res.send(layout({
    title: 'Messages — ' + SITE_NAME,
    user: req.user,
    body: `
      <style>${MESSAGES_CSS}</style>
      <div class="msg-page-head">
        <h1>Messages</h1>
        <a href="/messages/new" class="btn">+ New message</a>
      </div>
      <p class="muted">Save your DMs once. Tap copy, paste anywhere — Instagram, WhatsApp, Facebook, anything.</p>

      ${justSavedSlug ? `
        <div class="card" style="border-left: 4px solid var(--ok); background:#f0fdf4;">
          <strong style="color:#166534;">Saved.</strong>
          <span class="muted" style="font-size:14px;">It's at the top of your list.</span>
        </div>
      ` : ''}

      <form method="GET" action="/messages" class="msg-search">
        <input type="text" name="q" value="${escHtml(q)}" placeholder="Search title or body…" autocomplete="off">
        ${q ? `<a href="/messages" class="btn btn-secondary btn-sm">Clear</a>` : ''}
      </form>

      <div id="msg-list">
        ${firstPage.length === 0
          ? `<div class="recent-empty">${q
              ? 'No messages match that search.'
              : 'No saved messages yet. Click <a href="/messages/new">+ New message</a> to start.'}</div>`
          : firstPage.map(m => renderMessageCard(m, PUBLIC_ORIGIN)).join('')}
      </div>
      ${nextCursor != null ? `<div id="msg-sentinel" data-cursor="${nextCursor}" class="muted" style="text-align: center; padding: 16px;">Loading more…</div>` : ''}

      <script>${MSG_LIST_JS}</script>
    `,
  }));
});

app.get('/messages/new', requireUser, (req, res) => {
  res.send(layout({
    title: 'New message — ' + SITE_NAME,
    user: req.user,
    body: `
      <style>${MESSAGES_CSS}</style>
      <h1>New message</h1>
      <p class="muted">Type the exact message you'll paste. Multi-paragraph + emojis preserved.</p>
      <form method="POST" action="/api/messages" class="card stack" id="msgForm">
        <div>
          <label for="title">Title (so you can find it later)</label>
          <input id="title" name="title" type="text" required autofocus maxlength="200" placeholder="e.g. New lead intro DM">
        </div>
        <div>
          <label for="body">Message</label>
          <textarea id="body" name="body" required rows="14" placeholder="Write your message exactly as you'd paste it…"></textarea>
          <p class="muted" style="font-size:12px; margin:6px 0 0;">Line breaks, emojis, everything is preserved.</p>
        </div>
        <button type="submit" class="btn btn-block">Save message</button>
        <p class="err" id="formErr" style="display:none;"></p>
        <p class="muted" style="text-align:center; font-size:14px; margin:0;"><a href="/messages">← Back to messages</a></p>
      </form>
      <script>
        document.getElementById('msgForm').addEventListener('submit', async (ev) => {
          ev.preventDefault();
          const errEl = document.getElementById('formErr');
          errEl.style.display = 'none';
          const fd = new FormData(ev.target);
          const body = { title: fd.get('title'), body: fd.get('body') };
          try {
            const res = await fetch('/api/messages', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(body), credentials: 'same-origin',
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Save failed');
            location.href = '/messages?saved=' + encodeURIComponent(data.slug);
          } catch (e) {
            errEl.textContent = e.message; errEl.style.display = 'block';
          }
        });
      </script>
    `,
  }));
});

app.get('/messages/:slug/edit', requireUser, (req, res) => {
  const m = mdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!m) {
    return res.status(404).send(layout({ title: 'Not found', user: req.user, body: '<h1>Not found</h1><p>This message does not exist or is not yours.</p>' }));
  }
  res.send(layout({
    title: 'Edit message — ' + SITE_NAME,
    user: req.user,
    body: `
      <style>${MESSAGES_CSS}</style>
      <h1>Edit message</h1>
      <form method="POST" action="/api/messages/${escHtml(m.slug)}" class="card stack" id="msgForm">
        <div>
          <label for="title">Title</label>
          <input id="title" name="title" type="text" required autofocus maxlength="200" value="${escHtml(m.title)}">
        </div>
        <div>
          <label for="body">Message</label>
          <textarea id="body" name="body" required rows="14">${escHtml(m.body)}</textarea>
        </div>
        <button type="submit" class="btn btn-block">Save changes</button>
        <p class="err" id="formErr" style="display:none;"></p>
        <p class="muted" style="text-align:center; font-size:14px; margin:0;"><a href="/messages">← Back to messages</a></p>
      </form>
      <script>
        document.getElementById('msgForm').addEventListener('submit', async (ev) => {
          ev.preventDefault();
          const errEl = document.getElementById('formErr');
          errEl.style.display = 'none';
          const fd = new FormData(ev.target);
          const body = { title: fd.get('title'), body: fd.get('body') };
          try {
            const res = await fetch('/api/messages/${escHtml(m.slug)}', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(body), credentials: 'same-origin',
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Save failed');
            location.href = '/messages?saved=' + encodeURIComponent('${escHtml(m.slug)}');
          } catch (e) {
            errEl.textContent = e.message; errEl.style.display = 'block';
          }
        });
      </script>
    `,
  }));
});

app.post('/api/messages', requireUser, express.json({ limit: '2mb' }), (req, res) => {
  try {
    const title = ((req.body && req.body.title) || '').toString().trim();
    const body = ((req.body && req.body.body) || '').toString();
    if (!title) throw new Error('Title is required.');
    if (!body.trim()) throw new Error('Message body is required.');
    if (body.length > 200000) throw new Error('Message is too long (max 200,000 characters).');
    const slug = nanoid(8);
    mdb.insert({ slug, userId: req.user.id, title, body });
    console.log(`[msg] user=${req.user.id} created slug=${slug} (${body.length} chars)`);
    res.json({ ok: true, slug });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/messages/:slug', requireUser, express.json({ limit: '2mb' }), (req, res) => {
  try {
    const m = mdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!m) return res.status(404).json({ ok: false, error: 'not found' });
    const title = ((req.body && req.body.title) || '').toString().trim();
    const body = ((req.body && req.body.body) || '').toString();
    if (!title) throw new Error('Title is required.');
    if (!body.trim()) throw new Error('Message body is required.');
    if (body.length > 200000) throw new Error('Message is too long (max 200,000 characters).');
    mdb.update(m.id, req.user.id, { title, body });
    res.json({ ok: true, slug: m.slug });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/messages/:slug/delete', requireUser, (req, res) => {
  const m = mdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!m) return res.status(404).json({ ok: false, error: 'not found' });
  mdb.deleteByIdForUser(m.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/messages/:slug/move', requireUser, express.json(), (req, res) => {
  const dir = (req.body && req.body.direction) === 'down' ? 'down' : 'up';
  const result = mdb.move(req.params.slug, req.user.id, dir);
  if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
  res.json({ ok: true });
});

// Public message viewer — no auth, big copy CTA
app.get('/m/:slug', (req, res) => {
  const m = mdb.getBySlug(req.params.slug);
  if (!m) {
    return res.status(404).send(layout({ title: 'Not found', user: req.user, body: '<h1>Not found</h1><p>This message link does not exist or was removed.</p>' }));
  }
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.send(renderMessageViewer(m, req.user));
});

const MESSAGES_CSS = `
  .msg-page-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 6px; }
  .msg-page-head h1 { margin: 0; }
  .msg-search { display: flex; gap: 8px; margin: 16px 0; }
  .msg-search input[type="text"] { flex: 1; padding: 12px 14px; font-size: 15px; border: 1px solid var(--border); border-radius: 10px; background: #fff; }
  .msg-search input[type="text"]:focus { outline: 0; border-color: var(--brand); box-shadow: 0 0 0 4px rgba(37,99,235,0.12); }

  .msg-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; margin-bottom: 14px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .msg-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 8px; flex-wrap: nowrap; }
  .msg-card-head-text { flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
  .msg-card-title { margin: 0; font-size: 17px; font-weight: 700; color: var(--fg); letter-spacing: -0.01em; word-break: break-word; }
  .msg-card-date { font-size: 12px; color: var(--muted); white-space: nowrap; }

  /* Up/down reorder buttons. Stacked vertically, 36×36 each so they're
     comfortably tappable on mobile. Subtle by default — they're a
     control, not a CTA — but visibly an interactive element. */
  .msg-reorder { display: flex; flex-direction: column; gap: 4px; flex: 0 0 auto; }
  .msg-reorder-btn {
    width: 36px; height: 36px; padding: 0;
    display: inline-flex; align-items: center; justify-content: center;
    background: #fff; border: 1px solid var(--border); border-radius: 8px;
    font: 600 16px/1 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #475569; cursor: pointer;
    transition: background-color .12s, border-color .12s, transform .08s;
  }
  .msg-reorder-btn:hover { background: #f3f4f6; border-color: #cbd5e1; color: #0f172a; }
  .msg-reorder-btn:active { transform: scale(0.92); }
  .msg-reorder-btn:disabled { opacity: 0.35; cursor: not-allowed; transform: none; }
  .msg-card.is-moving { background-color: #f0fdf4; transition: background-color .35s; }
  .msg-card-preview {
    margin: 0 0 14px;
    padding: 10px 12px;
    background: #f8fafc;
    border: 1px solid var(--border);
    border-radius: 8px;
    font: 13.5px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #334155;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 90px;          /* ~ 4 lines */
    overflow: hidden;
    position: relative;
    -webkit-mask-image: linear-gradient(180deg, #000 70%, transparent);
            mask-image: linear-gradient(180deg, #000 70%, transparent);
  }
  .msg-card-preview a { color: #2563eb; text-decoration: underline; word-break: break-all; }
  .msg-card-preview a:hover { color: #1d4ed8; }

  /* Big copy button — primary action on every message card. Min 56px
     tall so it's tappable on mobile. Gradient ramp matches the upload
     CTA so the visual language is consistent across the product. */
  .btn-copy-big {
    display: flex; align-items: center; justify-content: center; gap: 10px;
    width: 100%; min-height: 56px;
    padding: 14px 20px;
    border: 0; border-radius: 12px; cursor: pointer;
    font: inherit; font-size: 16px; font-weight: 700; color: #fff;
    background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%);
    box-shadow: 0 1px 2px rgba(29,78,216,0.22), 0 8px 22px -8px rgba(29,78,216,0.55);
    transition: transform .08s, filter .15s, box-shadow .15s;
    margin-bottom: 12px;
    -webkit-tap-highlight-color: rgba(255,255,255,0.2);
  }
  .btn-copy-big:hover { filter: brightness(1.05); }
  .btn-copy-big:active { transform: scale(0.985); }
  .btn-copy-big.is-copied {
    background: linear-gradient(180deg, #16a34a 0%, #15803d 100%);
    box-shadow: 0 1px 2px rgba(22,163,74,0.22), 0 8px 22px -8px rgba(22,163,74,0.55);
  }
  .btn-copy-icon { font-size: 22px; line-height: 1; }
  .btn-copy-label { letter-spacing: 0.01em; }

  .msg-card-actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .msg-card-actions .btn-sm { flex: 1 1 auto; }

  .recent-empty { text-align: center; padding: 40px 20px; color: var(--muted); font-size: 15px; }

  textarea {
    display: block; width: 100%;
    padding: 12px 14px; font: inherit; font-size: 15px; line-height: 1.5;
    border: 1px solid var(--border); border-radius: 10px; background: #fff; color: var(--fg);
    transition: border-color .15s, box-shadow .15s; resize: vertical;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  textarea:hover { border-color: #cbd5e1; }
  textarea:focus { outline: 0; border-color: var(--brand); box-shadow: 0 0 0 4px rgba(37,99,235,0.12); }
`;

const MSG_LIST_JS = `
  (function () {
    const list = document.getElementById('msg-list');
    if (!list) return;

    list.addEventListener('click', async (e) => {
      const btn = e.target.closest('button, a');
      if (!btn) return;
      const card = btn.closest('.msg-card');

      // Big primary copy
      if (btn.classList.contains('btn-copy-big')) {
        try {
          const body = JSON.parse(btn.dataset.body);
          await navigator.clipboard.writeText(body);
          btn.classList.add('is-copied');
          const label = btn.querySelector('.btn-copy-label');
          const icon = btn.querySelector('.btn-copy-icon');
          const prevLabel = label.textContent; const prevIcon = icon.textContent;
          label.textContent = 'Copied — paste anywhere'; icon.textContent = '✓';
          setTimeout(() => {
            btn.classList.remove('is-copied');
            label.textContent = prevLabel; icon.textContent = prevIcon;
          }, 2000);
        } catch (err) {
          alert('Copy failed — long-press the message to copy manually.');
        }
        return;
      }

      // Copy link
      if (btn.classList.contains('copy-link-btn')) {
        try {
          await navigator.clipboard.writeText(btn.dataset.url);
          const prev = btn.textContent;
          btn.textContent = 'Link copied!';
          setTimeout(() => { btn.textContent = prev; }, 1500);
        } catch { btn.textContent = 'Copy failed'; }
        return;
      }

      // Move up / down — swap with the adjacent card in the DOM,
      // then fire-and-forget the API call. We do the DOM swap first
      // so the UI feels instant; on API failure we revert.
      if (btn.classList.contains('msg-reorder-btn')) {
        const dir = btn.classList.contains('msg-up-btn') ? 'up' : 'down';
        const sibling = dir === 'up'
          ? card.previousElementSibling
          : card.nextElementSibling;
        if (!sibling || !sibling.classList || !sibling.classList.contains('msg-card')) {
          return; // already at edge — silently no-op
        }
        // Optimistic DOM swap
        if (dir === 'up') card.parentNode.insertBefore(card, sibling);
        else              card.parentNode.insertBefore(sibling, card);
        card.classList.add('is-moving');
        setTimeout(() => card.classList.remove('is-moving'), 600);
        try {
          const res = await fetch('/api/messages/' + card.dataset.slug + '/move', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ direction: dir }), credentials: 'same-origin',
          });
          if (!res.ok) {
            // Revert on failure
            if (dir === 'up') card.parentNode.insertBefore(sibling, card);
            else              card.parentNode.insertBefore(card, sibling);
            const data = await res.json().catch(() => ({}));
            alert(data.error || 'Move failed.');
          }
        } catch (e) {
          if (dir === 'up') card.parentNode.insertBefore(sibling, card);
          else              card.parentNode.insertBefore(card, sibling);
          alert('Move failed (network).');
        }
        return;
      }

      // Delete
      if (btn.classList.contains('msg-delete-btn')) {
        const title = card.querySelector('.msg-card-title').textContent.trim();
        if (!confirm('Delete "' + title + '"?\\n\\nThis can\\'t be undone.')) return;
        btn.disabled = true; btn.textContent = 'Deleting…';
        try {
          const res = await fetch('/api/messages/' + card.dataset.slug + '/delete', {
            method: 'POST', credentials: 'same-origin',
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          card.remove();
        } catch { btn.disabled = false; btn.textContent = 'Delete'; alert('Delete failed.'); }
        return;
      }
    });
  })();
`;

// ---------- upload page ----------

function renderTrialChips(usage) {
  return usage.kinds.map(k => {
    const used = usage.used[k];
    return `<span class="chip${used ? ' used' : ''}">${kindEmoji(k)} ${escHtml(k)} ${used ? '✓ used' : 'available'}</span>`;
  }).join(' ');
}

app.get('/upload', requireUser, (req, res) => {
  if (req.user.status === 'deactivated') {
    return res.send(layout({
      title: 'Account deactivated',
      user: req.user,
      body: `<h1 class="err">Account deactivated</h1><p>Contact the admin to reactivate.</p>`,
    }));
  }

  const isTrial = req.user.status === 'trial';
  const usage = isTrial ? users.trialUsage(req.user.id) : null;

  // Show a welcome banner when the user just clicked a magic link and
  // landed here with freshly-claimed files. If any pending files hit
  // the trial cap and got rejected, explain that too — otherwise the
  // user wonders where the other files went.
  const claimed = Math.max(0, parseInt(req.query.claimed, 10) || 0);
  const rejected = Math.max(0, parseInt(req.query.rejected, 10) || 0);
  let claimedBanner = '';
  if (claimed > 0 && rejected === 0) {
    claimedBanner = `
      <div class="card" style="border-left:4px solid var(--ok); background:#f0fdf4;">
        <h2 style="margin:0 0 4px; color:#166534; font-size:18px;">🎉 Welcome! Your link ${claimed === 1 ? 'is' : claimed + ' links are'} ready.</h2>
        <p class="muted" style="margin:0; font-size:14px;">Scroll to your recent shares below — copy the link to send it.</p>
      </div>
    `;
  } else if (claimed > 0 && rejected > 0) {
    claimedBanner = `
      <div class="card" style="border-left:4px solid #f59e0b; background:#fffbeb;">
        <h2 style="margin:0 0 4px; color:#92400e; font-size:18px;">Welcome — ${claimed} file${claimed === 1 ? '' : 's'} activated.</h2>
        <p class="muted" style="margin:0; font-size:14px;">
          ${rejected} upload${rejected === 1 ? ' was' : 's were'} not activated because your trial allows one file of each kind. Ask the admin to upgrade your account for unlimited uploads.
        </p>
      </div>
    `;
  } else if (claimed === 0 && rejected > 0) {
    claimedBanner = `
      <div class="card" style="border-left:4px solid var(--err); background:#fef2f2;">
        <h2 style="margin:0 0 4px; color:#991b1b; font-size:18px;">Upload not activated — trial limit reached.</h2>
        <p class="muted" style="margin:0; font-size:14px;">
          Your trial allows one file of each kind, and you've already used that slot. Ask the admin to upgrade your account to regular to unlock unlimited uploads.
        </p>
      </div>
    `;
  }

  const firstPage = fdb.listRecentByUser(req.user.id, { limit: RECENT_PAGE_SIZE });
  const nextCursor = firstPage.length === RECENT_PAGE_SIZE
    ? firstPage[firstPage.length - 1].id : null;

  // Always render the recent-list scaffolding — heading, filter bar, list
  // container, sentinel. That way the RECENT_LIST_JS IIFE always binds its
  // 'recent:refresh' listener, and a first-upload populates the list live
  // without needing a reload. The list + filter bar stay hidden visually
  // until there's at least one file to show (toggled client-side by the
  // refresh handler).
  const hasAnyFiles = firstPage.length > 0;

  const recentHtml = `
    <h2 id="recent-heading"${hasAnyFiles ? '' : ' style="display:none;"'}>Your recent shares</h2>
    <div class="filter-bar" id="filter-bar"${hasAnyFiles ? '' : ' style="display:none;"'}>
      <div class="filter-chips">
        <button class="chip-btn is-active" type="button" data-kind="all">All</button>
        <button class="chip-btn" type="button" data-kind="image">🖼 Images</button>
        <button class="chip-btn" type="button" data-kind="video">🎬 Video</button>
        <button class="chip-btn" type="button" data-kind="audio">🎙 Audio</button>
        <button class="chip-btn" type="button" data-kind="pdf">📄 PDFs</button>
        <button class="chip-btn" type="button" data-kind="text">📝 Text</button>
      </div>
      <div class="filter-inputs">
        <input type="text" id="filter-q" placeholder="Search by name…" autocomplete="off">
        <label class="date-label">From <input type="date" id="filter-from"></label>
        <label class="date-label">To <input type="date" id="filter-to"></label>
        <button type="button" class="btn btn-secondary btn-sm" id="filter-reset">Clear</button>
      </div>
    </div>
    <div id="recent-list">${firstPage.map(renderRecentCard).join('')}</div>
    <div id="recent-sentinel"
         data-cursor="${nextCursor != null ? nextCursor : ''}"
         class="muted"
         style="text-align: center; padding: 16px;${nextCursor == null ? 'display:none;' : ''}">
      Loading more…
    </div>
    <script>${RECENT_LIST_JS}</script>
  `;

  const caps = { Images: fmtBytes(SIZE_CAPS.image), Audio: fmtBytes(SIZE_CAPS.audio), Video: fmtBytes(SIZE_CAPS.video), PDFs: fmtBytes(SIZE_CAPS.pdf), Text: fmtBytes(SIZE_CAPS.text) };
  const capsHint = Object.entries(caps).map(([k, v]) => `${k} up to ${v}`).join(' · ');

  const trialBanner = isTrial ? `
    <div class="card" style="border-left: 4px solid #f59e0b;">
      <strong>Trial account</strong> — one file per kind until the admin upgrades you.
      <div style="margin-top: 8px;">${renderTrialChips(usage)}</div>
    </div>
  ` : '';

  // The client-side classifier mirrors the server logic for fast feedback.
  // We also embed which kinds are already used so trial users don't waste
  // a 4 GB upload just to see a server-side rejection.
  const trialUsedJson = isTrial ? JSON.stringify(usage.used) : 'null';

  res.send(layout({
    title: 'Upload — ' + SITE_NAME,
    user: req.user,
    body: `
      <h1>Share a file</h1>
      <p class="muted">Drop any file. Get a link with a built-in viewer.</p>
      ${claimedBanner}
      ${trialBanner}
      <form class="card stack" id="uploadForm">
        <div>
          <label for="title">Title (optional)</label>
          <input id="title" name="title" type="text" placeholder="Defaults to filename">
        </div>
        <div>
          <label for="file">File</label>
          <div class="dropzone" id="dropzone">
            <input id="file" name="file" type="file" required>
            <div class="dropzone-inner">
              <div class="dropzone-icon" id="dropzoneIcon">📤</div>
              <div class="dropzone-text">
                <strong>Drop a file here</strong>
                <span class="sub">or tap to choose · images, video, audio, PDF, text/code</span>
              </div>
              <div class="dropzone-filename" id="dropzoneFilename"></div>
            </div>
          </div>
          <p class="muted" style="font-size: 12px; margin: 6px 0 0;">${escHtml(capsHint)}</p>
        </div>
        <label class="checkbox-row" for="allow_download">
          <input id="allow_download" name="allow_download" type="checkbox" checked>
          <span>Allow viewers to download
            <span class="hint">When off, the share page only previews — no download button.</span>
          </span>
        </label>
        <button type="submit" class="btn btn-block" id="submitBtn">Upload and make link</button>
        <div class="progress" id="progress" aria-live="polite">
          <div class="progress-pct" id="progressPct">0%</div>
          <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
          <div class="progress-meta">
            <span><strong id="progressBytes">0 B / 0 B</strong></span>
            <span id="progressSpeed"></span>
            <span id="progressEta"></span>
          </div>
        </div>
        <p class="err" id="errMsg" style="display:none;"></p>
      </form>
      ${recentHtml}
      <script>
        const SIZE_CAPS = ${JSON.stringify(SIZE_CAPS)};
        const TRIAL_USED = ${trialUsedJson};

        function classifyClient(name, mime) {
          const ext = (name.split('.').pop() || '').toLowerCase();
          const m = (mime || '').toLowerCase();
          if (m.startsWith('image/')) return { kind: 'image', cap: SIZE_CAPS.image };
          if (m.startsWith('video/')) return { kind: 'video', cap: SIZE_CAPS.video };
          if (m.startsWith('audio/')) return { kind: 'audio', cap: SIZE_CAPS.audio };
          if (m === 'application/pdf' || ext === 'pdf') return { kind: 'pdf', cap: SIZE_CAPS.pdf };
          return { kind: 'text', cap: SIZE_CAPS.text };
        }
        function fmtBytes(b) { if (!b) return '0 B'; const u=['B','KB','MB','GB']; let i=0,n=b; while(n>=1024&&i<u.length-1){n/=1024;i++;} return (n<10&&i>0?n.toFixed(1):Math.round(n))+' '+u[i]; }
        function fmtEta(s){ if(!Number.isFinite(s)||s<=0)return''; if(s<60)return Math.round(s)+'s left'; if(s<3600)return Math.round(s/60)+'m left'; return (s/3600).toFixed(1)+'h left'; }

        // ---- Dropzone wiring ----
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('file');
        const filenameEl = document.getElementById('dropzoneFilename');
        const iconEl = document.getElementById('dropzoneIcon');
        function showFilename() {
          const f = fileInput.files && fileInput.files[0];
          if (f) { filenameEl.textContent = f.name + ' (' + fmtBytes(f.size) + ')'; dropzone.classList.add('has-file'); iconEl.textContent = '✅'; }
          else { filenameEl.textContent = ''; dropzone.classList.remove('has-file'); iconEl.textContent = '📤'; }
        }
        ['dragenter','dragover'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('is-dragover'); }));
        ['dragleave','drop'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('is-dragover'); }));
        dropzone.addEventListener('drop', (e) => { if (e.dataTransfer?.files?.length) { try { fileInput.files = e.dataTransfer.files; } catch {} showFilename(); } });
        fileInput.addEventListener('change', showFilename);

        // ---- Submit via XHR for real-time progress ----
        const form = document.getElementById('uploadForm');
        const btn = document.getElementById('submitBtn');
        const progress = document.getElementById('progress');
        const progressFill = document.getElementById('progressFill');
        const progressPct = document.getElementById('progressPct');
        const progressBytes = document.getElementById('progressBytes');
        const progressSpeed = document.getElementById('progressSpeed');
        const progressEta = document.getElementById('progressEta');
        const errMsg = document.getElementById('errMsg');

        form.addEventListener('submit', (ev) => {
          ev.preventDefault();
          errMsg.style.display = 'none';
          const f = fileInput.files && fileInput.files[0];
          if (!f) return;

          const c = classifyClient(f.name, f.type);
          if (f.size > c.cap) {
            errMsg.textContent = f.name + ' is ' + fmtBytes(f.size) + ' but the limit for ' + c.kind + ' files is ' + fmtBytes(c.cap) + '.';
            errMsg.style.display = 'block';
            return;
          }
          // Trial-user-kind check, mirrored from the server
          if (TRIAL_USED && TRIAL_USED[c.kind]) {
            errMsg.textContent = 'Your trial allows one ' + c.kind + ' file. Ask the admin to upgrade your account to upload more.';
            errMsg.style.display = 'block';
            return;
          }

          const fd = new FormData(form);
          const xhr = new XMLHttpRequest();
          xhr.open('POST', '/api/upload');
          // NOTE: do NOT set responseType = 'document'. Accessing responseText
          // on a document response throws InvalidStateError, which used to
          // crash mid-render after document.open() had already blanked the
          // page. We now parse JSON and render the success state in place.

          const startedAt = performance.now();
          let lastTime = startedAt, lastLoaded = 0, smoothedBps = 0;
          const ALPHA = 0.25;
          xhr.upload.addEventListener('progress', (e) => {
            if (!e.lengthComputable) return;
            const pct = Math.round((e.loaded / e.total) * 100);
            progressFill.style.width = pct + '%';
            progressPct.textContent = pct + '%';
            progressBytes.textContent = fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total);
            const now = performance.now();
            const dt = (now - lastTime) / 1000;
            if (dt > 0.1) {
              const sampleBps = (e.loaded - lastLoaded) / dt;
              smoothedBps = smoothedBps === 0 ? sampleBps : (ALPHA*sampleBps + (1-ALPHA)*smoothedBps);
              lastTime = now; lastLoaded = e.loaded;
            }
            progressSpeed.textContent = smoothedBps > 0 ? fmtBytes(smoothedBps) + '/s' : '';
            const remaining = (e.total - e.loaded) / Math.max(smoothedBps, 1);
            progressEta.textContent = fmtEta(remaining);
          });
          xhr.addEventListener('load', () => {
            let data = null;
            try { data = JSON.parse(xhr.responseText); } catch (_) {}

            if (xhr.status >= 200 && xhr.status < 300 && data && data.ok) {
              // Animate progress to 100% so the user sees completion.
              progressFill.style.width = '100%';
              progressPct.textContent = '100%';
              progressEta.textContent = 'Done!';
              progress.classList.add('is-done');
              setTimeout(() => {
                showUploadSuccess(data);
                resetUploadForm();
                // Ask the recent list (if present) to refresh so the new
                // file shows up at the top without a page reload.
                document.dispatchEvent(new CustomEvent('recent:refresh'));
              }, 350);
            } else {
              btn.disabled = false; btn.textContent = 'Upload and make link';
              progress.classList.remove('is-active');
              errMsg.textContent = (data && data.error) || ('Upload failed: ' + (xhr.status || 'network error'));
              errMsg.style.display = 'block';
            }
          });
          xhr.addEventListener('error', () => {
            btn.disabled = false; btn.textContent = 'Upload and make link';
            progress.classList.remove('is-active');
            errMsg.textContent = 'Upload failed: network error'; errMsg.style.display = 'block';
          });
          btn.disabled = true; btn.textContent = 'Uploading…';
          progress.classList.add('is-active');
          xhr.send(fd);
        });

        // ---- In-place success UI ----
        // A single success card per session is reused — if the user uploads
        // several files in a row, the card updates instead of stacking.
        function escText(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
        function showUploadSuccess(d) {
          let card = document.getElementById('upload-success');
          if (!card) {
            card = document.createElement('div');
            card.id = 'upload-success';
            card.className = 'card stack';
            card.style.borderLeft = '4px solid var(--ok)';
            form.parentNode.insertBefore(card, form);
          }
          const storage = d.storageSource === 'user'
            ? 'your folder <strong>' + escText(d.folderName) + '</strong>'
            : 'the shared folder';
          card.innerHTML =
            '<h2 class="ok" style="margin:0 0 4px;">✅ Link ready</h2>' +
            '<p class="muted" style="margin:0;">' + escText(d.title) + '</p>' +
            '<div class="link-box" style="word-break:break-all;">' + escText(d.shareLink) + '</div>' +
            '<div class="row">' +
              '<button type="button" class="btn" data-role="copy">Copy link</button>' +
              '<a class="btn btn-secondary" href="' + escText(d.shareLink) + '" target="_blank" rel="noopener">Open to test</a>' +
              '<button type="button" class="btn btn-secondary" data-role="dismiss">Dismiss</button>' +
            '</div>' +
            '<p class="muted" style="font-size:13px; margin:0;">' +
              escText(d.kindEmoji) + ' ' + escText(d.kind) + ' · ' + fmtBytes(d.size) +
              ' · ' + (d.allowDownload ? 'Downloads allowed' : 'Preview only') +
              ' · Stored in ' + storage +
            '</p>';
          card.querySelector('[data-role="copy"]').addEventListener('click', async (e) => {
            const b = e.currentTarget;
            try { await navigator.clipboard.writeText(d.shareLink); const prev = b.textContent; b.textContent = 'Copied!'; setTimeout(() => b.textContent = prev, 1500); }
            catch { b.textContent = 'Copy failed — long-press the link'; }
          });
          card.querySelector('[data-role="dismiss"]').addEventListener('click', () => card.remove());
          // Keep the success card in view without snapping the page around
          card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        function resetUploadForm() {
          btn.disabled = false;
          btn.textContent = 'Upload and make link';
          progress.classList.remove('is-active');
          progress.classList.remove('is-done');
          progressFill.style.width = '0%';
          progressPct.textContent = '0%';
          progressBytes.textContent = '0 B / 0 B';
          progressSpeed.textContent = '';
          progressEta.textContent = '';
          // Clear the file input + dropzone state but keep the Title and
          // "allow download" choice — users often share similar files in
          // batches and shouldn't have to re-check the box each time.
          fileInput.value = '';
          showFilename();
          errMsg.style.display = 'none';
        }
      </script>
    `,
  }));
});

// JS for the /upload recent-list block. Handles the filter bar (kind chips,
// name search, date range), infinite scroll, and the per-card actions
// (copy/rename/toggle-download/delete). Both the filter refresh and the
// infinite-scroll fetch read from the same `filters` object, so paginating
// a filtered list carries the filters across page requests.
const RECENT_LIST_JS = `
  (function () {
    const list = document.getElementById('recent-list');
    const sentinel = document.getElementById('recent-sentinel');
    const chips = Array.from(document.querySelectorAll('.filter-chips .chip-btn'));
    const qInput = document.getElementById('filter-q');
    const fromInput = document.getElementById('filter-from');
    const toInput = document.getElementById('filter-to');
    const resetBtn = document.getElementById('filter-reset');
    if (!list) return;

    const PAGE_SIZE = ${RECENT_PAGE_SIZE};
    const filters = { kind: 'all', q: '', from: '', to: '' };
    let loading = false;
    let debounceTimer = null;
    let io = null;

    function buildQs(extra) {
      const p = new URLSearchParams();
      if (filters.kind && filters.kind !== 'all') p.set('kind', filters.kind);
      if (filters.q)    p.set('q', filters.q);
      if (filters.from) p.set('from', filters.from);
      if (filters.to)   p.set('to', filters.to);
      p.set('limit', String(PAGE_SIZE));
      if (extra && extra.before) p.set('before', extra.before);
      return p.toString();
    }

    function setSentinelActive(nextCursor) {
      if (!sentinel) return;
      if (nextCursor == null) {
        sentinel.style.display = 'none';
      } else {
        sentinel.style.display = '';
        sentinel.dataset.cursor = nextCursor;
        sentinel.textContent = 'Loading more…';
        if (!io) attachObserver();
      }
    }

    async function refreshFirstPage() {
      if (loading) return;
      loading = true;
      list.innerHTML = '<div class="recent-empty">Loading…</div>';
      try {
        const res = await fetch('/api/recent?' + buildQs(), { credentials: 'same-origin' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const hasFilters = filters.kind !== 'all' || filters.q || filters.from || filters.to;
        if (data.html) {
          list.innerHTML = data.html;
          // First upload ever: server rendered the heading + filter bar
          // hidden, show them now that the user has at least one file.
          const heading = document.getElementById('recent-heading');
          const bar = document.getElementById('filter-bar');
          if (heading) heading.style.display = '';
          if (bar) bar.style.display = '';
        } else {
          list.innerHTML = '<div class="recent-empty">'
            + (hasFilters ? 'No files match those filters.' : 'You haven\\'t shared anything yet.')
            + '</div>';
        }
        setSentinelActive(data.nextCursor);
      } catch (err) {
        list.innerHTML = '<p class="err">Could not load. Please try again.</p>';
      } finally {
        loading = false;
      }
    }

    async function fetchNextPage() {
      if (loading || !sentinel || sentinel.style.display === 'none') return;
      if (!sentinel.dataset.cursor) return;
      loading = true;
      try {
        const res = await fetch('/api/recent?' + buildQs({ before: sentinel.dataset.cursor }), { credentials: 'same-origin' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        if (data.html) list.insertAdjacentHTML('beforeend', data.html);
        if (data.nextCursor == null) {
          sentinel.style.display = 'none';
        } else {
          sentinel.dataset.cursor = data.nextCursor;
        }
      } catch {
        sentinel.textContent = 'Could not load more — scroll to retry.';
      } finally {
        loading = false;
      }
    }

    function attachObserver() {
      if (!('IntersectionObserver' in window)) return;
      io = new IntersectionObserver((entries) => {
        for (const ent of entries) if (ent.isIntersecting) fetchNextPage();
      }, { rootMargin: '200px 0px' });
      io.observe(sentinel);
    }
    if (sentinel && sentinel.dataset.cursor) attachObserver();

    // --- Reload when the upload form tells us a new file just landed ---
    // Keeps active filters intact; refreshFirstPage re-reads them from the
    // filters object each call, so a filtered list stays filtered.
    document.addEventListener('recent:refresh', () => { refreshFirstPage(); });

    // --- Filter bar wiring ---
    chips.forEach(c => c.addEventListener('click', () => {
      chips.forEach(x => x.classList.remove('is-active'));
      c.classList.add('is-active');
      filters.kind = c.dataset.kind;
      refreshFirstPage();
    }));
    if (qInput) qInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        filters.q = qInput.value.trim();
        refreshFirstPage();
      }, 300);
    });
    if (fromInput) fromInput.addEventListener('change', () => {
      filters.from = fromInput.value || '';
      refreshFirstPage();
    });
    if (toInput) toInput.addEventListener('change', () => {
      filters.to = toInput.value || '';
      refreshFirstPage();
    });
    if (resetBtn) resetBtn.addEventListener('click', () => {
      chips.forEach(x => x.classList.remove('is-active'));
      const allChip = chips.find(c => c.dataset.kind === 'all');
      if (allChip) allChip.classList.add('is-active');
      if (qInput) qInput.value = '';
      if (fromInput) fromInput.value = '';
      if (toInput) toInput.value = '';
      filters.kind = 'all'; filters.q = ''; filters.from = ''; filters.to = '';
      refreshFirstPage();
    });

    // --- Per-card actions (copy / rename / toggle-download / delete) ---
    list.addEventListener('click', async (e) => {
      const btn = e.target.closest('button, a');
      if (!btn) return;

      if (btn.classList.contains('copy-btn')) {
        const url = btn.dataset.url;
        try { await navigator.clipboard.writeText(url); const prev = btn.textContent; btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = prev, 1500); }
        catch { btn.textContent = 'Copy failed — long-press the link'; }
        return;
      }
      if (btn.classList.contains('rename-btn')) {
        const item = btn.closest('.recent-item');
        const current = item.querySelector('.recent-title').textContent.trim().replace(/^[^\\s]+\\s+/, '');
        const next = prompt('New title', current);
        if (next == null) return;
        const title = next.trim();
        if (!title) { alert('Title cannot be empty.'); return; }
        const res = await fetch('/api/rename/' + btn.dataset.slug, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title }), credentials: 'same-origin' });
        if (res.ok) {
          const titleEl = item.querySelector('.recent-title');
          const emoji = titleEl.textContent.trim().split(' ')[0];
          titleEl.textContent = emoji + ' ' + title;
          const delBtn = item.querySelector('.delete-btn');
          if (delBtn) delBtn.dataset.title = title;
        } else alert('Rename failed.');
        return;
      }
      if (btn.classList.contains('toggle-dl-btn')) {
        const item = btn.closest('.recent-item');
        const current = item.dataset.download === '1';
        btn.disabled = true;
        const res = await fetch('/api/toggle-download/' + btn.dataset.slug, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ allowed: !current }), credentials: 'same-origin' });
        btn.disabled = false;
        if (res.ok) {
          const data = await res.json();
          item.dataset.download = data.allowed ? '1' : '0';
          const stateEl = item.querySelector('.dl-state');
          stateEl.textContent = data.allowed ? 'Downloads ON' : 'Downloads OFF';
          stateEl.className = 'dl-state ' + (data.allowed ? 'ok' : 'muted');
        } else alert('Toggle failed.');
        return;
      }
      if (btn.classList.contains('delete-btn')) {
        const title = btn.dataset.title || 'this file';
        if (!confirm('Delete "' + title + '"?\\n\\nThe share link will stop working and the file will be removed from storage. This cannot be undone.')) return;
        btn.disabled = true; btn.textContent = 'Deleting…';
        const res = await fetch('/api/delete/' + btn.dataset.slug, { method: 'POST', credentials: 'same-origin' });
        if (res.ok) btn.closest('.recent-item').remove();
        else { btn.disabled = false; btn.textContent = 'Delete'; alert('Delete failed.'); }
        return;
      }
    });
  })();
`;

// ---------- upload endpoint ----------

app.post('/api/upload', requireUser, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ ok: false, error: 'No file uploaded.' });

  try {
    console.log(`[upload] user=${req.user.id} ${file.originalname} mime=${file.mimetype} size=${file.size}`);

    const cls = classify(file.originalname, file.mimetype);
    if (cls.kind === 'unknown') throw new Error(cls.reason || 'Unsupported file type');
    if (file.size > cls.maxBytes) {
      throw new Error(`${file.originalname} is ${fmtBytes(file.size)} but the limit for ${cls.kind} files is ${fmtBytes(cls.maxBytes)}.`);
    }

    // Status and trial-cap gate (server-side enforcement)
    const fresh = udb.getById(req.user.id);
    if (!fresh) throw new Error('Account not found.');
    const gate = users.checkUploadAllowed(fresh, cls.kind);
    if (!gate.ok) throw new Error(gate.reason);

    const userTitle = (req.body.title || '').toString().trim();
    const fallbackTitle = baseFilename(file.originalname) || 'File';
    const title = (userTitle || fallbackTitle).slice(0, 200);
    const allowDownload = req.body.allow_download === 'on' || req.body.allow_download === 'true' || req.body.allow_download === '1';

    const slug = nanoid(8);
    const uniq = nanoid(4);
    const safeBase = sanitizeForFilename(title);
    const ghlDisplayName = `${safeBase}-${uniq}.${cls.ghlExt}`;

    // Transcode audio to mp3 when the source format isn't GHL-accepted
    // (iPhone .m4a, WebM .weba, .aac, .aiff, ...). Keeps the original
    // filename but flips the extension to .mp3 so downloads play.
    let uploadPath = file.path;
    let uploadSize = file.size;
    let effectiveOriginalName = file.originalname;
    let transcodedTmp = null;
    if (cls.needsTranscode && cls.kind === 'audio') {
      console.log(`[upload] transcoding ${file.originalname} → mp3...`);
      transcodedTmp = transcode.transcodeToMp3(file.path);
      uploadPath = transcodedTmp;
      uploadSize = fs.statSync(transcodedTmp).size;
      effectiveOriginalName = file.originalname.replace(/\.[^.]+$/, '') + '.mp3';
      console.log(`[upload] transcoded ${fmtBytes(file.size)} → ${fmtBytes(uploadSize)}`);
      if (uploadSize > cls.maxBytes) {
        try { fs.unlinkSync(transcodedTmp); } catch {}
        throw new Error(
          `This recording is too long for one upload — after converting to MP3 it's ` +
          `${fmtBytes(uploadSize)} and the storage limit is ${fmtBytes(cls.maxBytes)}. ` +
          `Trim it to under about 50 minutes and try again.`
        );
      }
    }

    // Pick the user's GHL config if they set one; otherwise fall back to
    // shared env. Trial users are gated above so they only ever hit
    // shared here, which matches the "regular users only" rule.
    const ghlCfg = users.effectiveGhlConfig(fresh);
    const ghlUrl = ghl.uploadToGhl(uploadPath, ghlDisplayName, cls.ghlMime, ghlCfg);
    console.log(`[upload] user=${req.user.id} target=${ghlCfg.source}`);

    fdb.insert({
      slug, title, original_filename: effectiveOriginalName,
      kind: cls.kind, mime_type: cls.mime, size_bytes: uploadSize,
      download_allowed: allowDownload, ghl_url: ghlUrl,
      user_id: req.user.id,
    });

    if (transcodedTmp) { try { fs.unlinkSync(transcodedTmp); } catch {} }

    const shareLink = `${PUBLIC_ORIGIN}/f/${slug}`;
    console.log(`[upload] done user=${req.user.id}: ${shareLink}`);

    // JSON response so the client can render the success state in place
    // without a page navigation. Previous HTML-response + document.write
    // flow could leave the page blank if the response parse failed.
    res.json({
      ok: true,
      slug,
      shareLink,
      title,
      kind: cls.kind,
      kindEmoji: kindEmoji(cls.kind),
      size: file.size,
      allowDownload,
      storageSource: ghlCfg.source,
      folderName: ghlCfg.folderName,
    });
  } catch (err) {
    console.error('[upload] failed:', err.message);
    res.status(400).json({ ok: false, error: err.message || 'Unknown error' });
  } finally {
    try { fs.unlinkSync(file.path); } catch {}
  }
});

function uploadErrorPage(msg, user) {
  return layout({
    title: 'Upload failed — ' + SITE_NAME,
    user,
    body: `
      <h1 class="err">Upload failed</h1>
      <p>${escHtml(msg)}</p>
      <a href="/upload" class="btn btn-block">Try again</a>
    `,
  });
}

// ---------- progressive signup: guest upload → email → magic link ----------
//
// 1. POST /api/guest-upload   guest drops a file; we store it with
//                             activated=0 and guest_id = signed cookie
// 2. POST /api/guest-send-magic   guest gives email; we attach to pending
//                             rows, create a 15-min magic-link token, send
// 3. GET  /magic/:token       verify → find-or-create user → claim pending
//                             files → sign in → redirect to /upload

app.post('/api/guest-upload', guestRateLimit, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (req.user) return res.status(400).json({ ok: false, error: 'You\'re already signed in — use the regular upload.' });
  if (!file) return res.status(400).json({ ok: false, error: 'No file uploaded.' });

  try {
    const cls = classify(file.originalname, file.mimetype);
    if (cls.kind === 'unknown') throw new Error(cls.reason || 'Unsupported file type');
    if (file.size > cls.maxBytes) {
      throw new Error(`${file.originalname} is ${fmtBytes(file.size)} but the limit for ${cls.kind} files is ${fmtBytes(cls.maxBytes)}.`);
    }

    // Best-effort cleanup of expired pending rows before we add another.
    await sweepExpiredPending();

    const userTitle = (req.body.title || '').toString().trim();
    const title = (userTitle || baseFilename(file.originalname) || 'File').slice(0, 200);
    const allowDownload = req.body.allow_download === 'on' || req.body.allow_download === 'true' || req.body.allow_download === '1';

    const slug = nanoid(8);
    const uniq = nanoid(4);
    const safeBase = sanitizeForFilename(title);
    const ghlDisplayName = `${safeBase}-${uniq}.${cls.ghlExt}`;

    // Same audio transcode pipeline as the authed upload — iPhone
    // voice memos drop as .m4a which GHL refuses outright.
    let uploadPath = file.path;
    let uploadSize = file.size;
    let effectiveOriginalName = file.originalname;
    let transcodedTmp = null;
    if (cls.needsTranscode && cls.kind === 'audio') {
      console.log(`[guest-upload] transcoding ${file.originalname} → mp3...`);
      transcodedTmp = transcode.transcodeToMp3(file.path);
      uploadPath = transcodedTmp;
      uploadSize = fs.statSync(transcodedTmp).size;
      effectiveOriginalName = file.originalname.replace(/\.[^.]+$/, '') + '.mp3';
      console.log(`[guest-upload] transcoded ${fmtBytes(file.size)} → ${fmtBytes(uploadSize)}`);
      if (uploadSize > cls.maxBytes) {
        try { fs.unlinkSync(transcodedTmp); } catch {}
        throw new Error(
          `This recording is too long — after converting to MP3 it's ` +
          `${fmtBytes(uploadSize)} and the storage limit is ${fmtBytes(cls.maxBytes)}. ` +
          `Trim it to under about 50 minutes and try again.`
        );
      }
    }

    // Guest uploads always go to shared storage — they don't have a
    // per-user GHL config yet. Once they activate and become a regular
    // user they can point new uploads at their own folder.
    const ghlUrl = ghl.uploadToGhl(uploadPath, ghlDisplayName, cls.ghlMime);

    fdb.insert({
      slug, title, original_filename: effectiveOriginalName,
      kind: cls.kind, mime_type: cls.mime, size_bytes: uploadSize,
      download_allowed: allowDownload, ghl_url: ghlUrl,
      user_id: null,
      activated: 0,
      guest_id: req.guestId,
    });

    if (transcodedTmp) { try { fs.unlinkSync(transcodedTmp); } catch {} }

    console.log(`[guest-upload] guest=${req.guestId} slug=${slug} size=${uploadSize}`);

    res.json({
      ok: true,
      slug,
      title,
      kind: cls.kind,
      kindEmoji: kindEmoji(cls.kind),
      size: uploadSize,
      allowDownload,
    });
  } catch (err) {
    console.error('[guest-upload] failed:', err.message);
    res.status(400).json({ ok: false, error: err.message });
  } finally {
    try { fs.unlinkSync(file.path); } catch {}
  }
});

app.post('/api/guest-send-magic', express.json(), async (req, res) => {
  if (req.user) return res.status(400).json({ ok: false, error: 'You\'re already signed in.' });
  const emailAddr = ((req.body && req.body.email) || '').toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailAddr)) {
    return res.status(400).json({ ok: false, error: 'Please enter a valid email.' });
  }

  const pending = fdb.listPendingByGuest(req.guestId);
  if (pending.length === 0) {
    return res.status(400).json({ ok: false, error: 'No pending uploads found. Try uploading again.' });
  }

  // Track the email on the pending rows for admin visibility, then issue
  // a short-lived magic link. 15 minutes keeps the attack window small
  // without being annoying for legit users.
  fdb.setPendingEmailForGuest(req.guestId, emailAddr);

  const rawToken = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString()
    .replace('T', ' ').replace(/\..+$/, '');
  mldb.sweep();
  mldb.create({ tokenHash, email: emailAddr, guestId: req.guestId, expiresAt });

  const magicUrl = `${PUBLIC_ORIGIN}/magic/${rawToken}`;

  if (!email.isConfigured()) {
    console.log(`[guest-magic] email not configured — link for ${emailAddr}: ${magicUrl}`);
  } else {
    try {
      await email.sendMagicLinkEmail({
        toEmail: emailAddr,
        magicUrl,
        siteName: SITE_NAME,
        fileCount: pending.length,
      });
      console.log(`[guest-magic] sent to ${emailAddr} for ${pending.length} pending file(s)`);
    } catch (err) {
      console.error('[guest-magic] send failed:', err.message);
      // Still return success so the UI moves forward. Admin can resend
      // via the admin dashboard later if needed.
    }
  }

  res.json({ ok: true, email: emailAddr, count: pending.length });
});

app.get('/magic/:token', async (req, res) => {
  const tokenHash = hashToken(req.params.token);
  const row = mldb.getByHash(tokenHash);
  const expired = !row || row.used_at
    || new Date(row.expires_at.replace(' ', 'T') + 'Z') < new Date();
  if (expired) {
    return res.send(renderStandaloneAuthPage({
      title: 'Link expired or used',
      subtitle: `Magic links work once and expire after 15 minutes. Upload again to get a fresh link.`,
      body: `<p class="auth-switch"><a href="/">Upload a file</a> · <a href="/login">Sign in instead</a></p>`,
    }));
  }

  try {
    // Find-or-create the user. If they're new, we create with a random
    // unguessable password_hash so the email+password login path rejects
    // cleanly until they set a password on /account.
    let u = udb.getByEmail(row.email);
    if (!u) {
      const throwawayPlain = crypto.randomBytes(24).toString('base64url');
      const userId = udb.insert({
        email: row.email,
        name: row.email.split('@')[0],
        password_hash: users.hashPassword(throwawayPlain),
        status: 'trial',
        is_admin: 0,
      });
      u = udb.getById(userId);
      console.log(`[magic] created passwordless user ${u.email} (id=${u.id})`);
    } else if (u.status === 'deactivated') {
      return res.send(renderStandaloneAuthPage({
        title: 'Account deactivated',
        subtitle: 'Contact the admin to reactivate your account.',
        body: `<p class="auth-switch"><a href="/">Back to home</a></p>`,
      }));
    }

    // Gather every pending file that belongs to this guest (by cookie
    // OR by the email we stashed on the row). Trial users hit the cap
    // below; regular/admin users get everything activated.
    const pending = fdb.listPendingMatching(row.guest_id, row.email);

    const toActivate = [];
    const toReject = [];

    if (u.status === 'trial') {
      // Trial cap is 1 per kind. Count what they already have live +
      // decide per pending row whether to accept. Oldest-first order
      // matches the ORDER BY id ASC in listPendingMatching so the
      // earliest upload wins if multiple of the same kind are pending.
      const remainingByKind = {};
      for (const k of ['image', 'video', 'audio', 'pdf', 'text']) {
        remainingByKind[k] = Math.max(0, 1 - fdb.countByUserAndKind(u.id, k));
      }
      for (const p of pending) {
        if ((remainingByKind[p.kind] || 0) > 0) {
          toActivate.push(p);
          remainingByKind[p.kind]--;
        } else {
          toReject.push(p);
        }
      }
    } else {
      // Regular + admin users have no cap.
      toActivate.push(...pending);
    }

    const claimed = fdb.activateByIds(toActivate.map(p => p.id), u.id);
    // Drop rejected rows + best-effort GHL cleanup so we don't leave
    // orphan bytes on the CDN. It's safe to silently drop these — the
    // user already knows they're on trial; the banner on /upload
    // explains exactly what happened.
    if (toReject.length) {
      fdb.deleteByIds(toReject.map(p => p.id));
      for (const r of toReject) { try { ghl.tryDeleteFromGhl(r.ghl_url); } catch {} }
    }
    mldb.markUsed(tokenHash);

    setAuthCookie(res, u.id);
    res.clearCookie('gid');
    console.log(`[magic] user=${u.id} status=${u.status} email=${row.email} pending=${pending.length} claimed=${claimed} rejected=${toReject.length}`);

    return res.redirect(`/upload?claimed=${claimed}&rejected=${toReject.length}`);
  } catch (err) {
    console.error('[magic] error:', err);
    return res.send(renderStandaloneAuthPage({
      title: 'Something went wrong',
      subtitle: err.message,
      body: `<p class="auth-switch"><a href="/">Try again</a></p>`,
    }));
  }
});

// Drop expired pending rows (DB + best-effort GHL delete).
async function sweepExpiredPending() {
  try {
    const expired = fdb.listAndDeleteExpiredPending();
    if (expired.length) {
      console.log(`[sweep] removed ${expired.length} expired pending file(s)`);
      for (const r of expired) { try { ghl.tryDeleteFromGhl(r.ghl_url); } catch {} }
    }
  } catch (e) { console.warn('[sweep] failed:', e.message); }
}

// ---------- raw / download proxies (public) ----------

app.get('/raw/:slug', async (req, res) => {
  const rec = fdb.getBySlug(req.params.slug);
  if (!rec) return res.status(404).send('Not found');
  // Don't leak the bytes of a pending-activation file — the share link
  // isn't live yet. Treat it the same as not-found so we don't confirm
  // existence to someone guessing slugs.
  if (!rec.activated) return res.status(404).send('Not found');
  try {
    // Forward the Range header so HTML5 <video> / <audio> can seek and
    // progressively load. Without this, the browser gets a flat 200 with
    // the whole body and many browsers refuse to play the video at all
    // — there's no way to scrub, and Safari in particular won't start
    // playback. GHL's CDN supports range requests natively.
    const headers = {};
    if (req.headers.range) headers.range = req.headers.range;
    const upstream = await fetch(rec.ghl_url, { headers });
    if (!upstream.ok || !upstream.body) return res.status(502).send('Upstream error');

    // Mirror the upstream status (200 for a full body, 206 for a partial
    // range). Whatever we return here, <video> uses the status to decide
    // whether to trust the range it asked for.
    res.status(upstream.status);

    // Always set our MIME (we know the original extension via classify);
    // GHL's octet-stream shouldn't win. Pass through size + range headers.
    res.set('Content-Type', rec.mime_type || 'application/octet-stream');
    for (const h of ['content-length', 'content-range', 'accept-ranges']) {
      const v = upstream.headers.get(h);
      if (v) res.set(h, v);
    }
    // Declare range support even if the upstream didn't echo it back —
    // some <video> implementations look for Accept-Ranges before issuing
    // a follow-up Range request for seeking.
    if (!upstream.headers.get('accept-ranges')) res.set('Accept-Ranges', 'bytes');
    res.set('Cache-Control', 'public, max-age=3600');

    const { Readable } = require('node:stream');
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (err) {
    console.error('[raw]', err);
    res.status(502).send('Stream failed');
  }
});

app.get('/d/:slug', async (req, res) => {
  const rec = fdb.getBySlug(req.params.slug);
  if (!rec) return res.status(404).send('Not found');
  if (!rec.activated) return res.status(404).send('Not found');
  if (!rec.download_allowed) return res.status(403).send('Downloads are disabled for this file.');
  const filename = rec.original_filename || (rec.title || 'file') + '.' + (rec.kind === 'text' ? 'txt' : rec.kind);
  try {
    // Forward Range for resumable downloads on flaky networks and to let
    // GHL serve partial content for huge videos instead of transferring
    // the whole body if the client only asked for a slice.
    const headers = {};
    if (req.headers.range) headers.range = req.headers.range;
    const upstream = await fetch(rec.ghl_url, { headers });
    if (!upstream.ok || !upstream.body) return res.status(502).send('Upstream error');
    res.status(upstream.status);
    res.set('Content-Type', rec.mime_type || 'application/octet-stream');
    res.set('Content-Disposition', `attachment; filename="${filename.replace(/"/g, '')}"`);
    for (const h of ['content-length', 'content-range', 'accept-ranges']) {
      const v = upstream.headers.get(h);
      if (v) res.set(h, v);
    }
    res.set('Cache-Control', 'private, max-age=0');
    const { Readable } = require('node:stream');
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (err) {
    console.error('[download]', err);
    res.status(502).send('Download failed');
  }
});

// ---------- public viewer ----------

app.get('/f/:slug', async (req, res) => {
  const rec = fdb.getBySlug(req.params.slug);
  if (!rec) {
    return res.status(404).send(layout({ title: 'Not found', user: req.user, body: `<h1>Not found</h1><p>This link does not exist or was removed.</p>` }));
  }
  // Progressive-signup uploads start in a pending state until the
  // uploader activates via magic link. Show a polite "not yet" page
  // instead of the actual file to keep the share URL non-reusable by
  // strangers who happen to guess the slug.
  if (!rec.activated) {
    res.set('X-Robots-Tag', 'noindex, nofollow');
    return res.send(layout({
      title: 'Waiting for activation',
      user: req.user,
      body: `
        <div class="card" style="text-align:center; padding: 40px 24px;">
          <div style="font-size:36px; margin-bottom: 8px;">📬</div>
          <h1 style="margin:0 0 8px;">Almost ready</h1>
          <p class="muted" style="max-width:420px; margin:0 auto 16px;">
            The owner of this file is activating the share link from their inbox.
            Check back in a minute.
          </p>
        </div>
      `,
    }));
  }
  res.set('X-Robots-Tag', 'noindex, nofollow');

  const ogTitle = rec.title || rec.original_filename || 'Shared file';
  const ogDescription = `${rec.kind} · ${fmtBytes(rec.size_bytes)}`;
  const ogImageUrl = rec.kind === 'image' ? `${PUBLIC_ORIGIN}/raw/${rec.slug}` : '';

  let body;
  switch (rec.kind) {
    case 'image': body = viewers.renderImage(rec, SITE_NAME); break;
    case 'video': body = viewers.renderVideo(rec, SITE_NAME); break;
    case 'audio': body = viewers.renderAudio(rec, SITE_NAME); break;
    case 'pdf':   body = viewers.renderPdf(rec, SITE_NAME); break;
    case 'text': {
      const SOFT_INLINE_CAP = 5 * 1024 * 1024;
      if (rec.size_bytes > SOFT_INLINE_CAP) {
        body = `
          <h1>${escHtml(rec.title || rec.original_filename || 'Text')}</h1>
          <p class="muted">${escHtml(rec.original_filename || '')} · ${fmtBytes(rec.size_bytes)}</p>
          <div class="card">
            <p>This text file is too large to preview inline (${fmtBytes(rec.size_bytes)} > ${fmtBytes(SOFT_INLINE_CAP)}).</p>
            ${rec.download_allowed ? `<a class="btn btn-block" href="/d/${rec.slug}" download>⬇ Download to read</a>` : '<p class="muted">Downloads are disabled for this file.</p>'}
          </div>
        `;
      } else {
        try {
          const upstream = await fetch(rec.ghl_url);
          const text = await upstream.text();
          body = viewers.renderText(rec, text, SITE_NAME);
        } catch (err) {
          body = `<h1 class="err">Could not load file</h1><p>${escHtml(err.message)}</p>`;
        }
      }
      break;
    }
    default:
      body = `
        <h1>${escHtml(rec.title || 'File')}</h1>
        <p class="muted">${escHtml(rec.original_filename)} · ${fmtBytes(rec.size_bytes)}</p>
        <div class="card"><p>This file type does not have a built-in viewer.</p>
        ${rec.download_allowed ? `<a class="btn btn-block" href="/d/${rec.slug}" download>⬇ Download</a>` : '<p class="muted">Downloads are disabled for this file.</p>'}</div>
      `;
  }

  res.send(layout({ title: ogTitle + ' — ' + SITE_NAME, user: req.user, body, ogTitle, ogDescription, ogImageUrl, noindex: true }));
});

// ---------- owner-scoped APIs ----------

app.get('/api/recent', requireUser, (req, res) => {
  const before = parseInt(req.query.before, 10);
  const limit = Math.max(1, Math.min(50, parseInt(req.query.limit, 10) || RECENT_PAGE_SIZE));

  // Accept optional filters. An empty / "all" kind means no filter on that
  // column. Strings are trimmed and length-capped to keep LIKE reasonable.
  const kind = ['image', 'video', 'audio', 'pdf', 'text'].includes(req.query.kind)
    ? req.query.kind : null;
  const q = (req.query.q || '').toString().trim().slice(0, 100) || null;
  // Basic shape check on dates so a bogus value doesn't bake into the
  // query. SQLite's date() is permissive but we want to fail fast here.
  const dateOk = s => /^\d{4}-\d{2}-\d{2}$/.test(s);
  const from = dateOk(req.query.from) ? req.query.from : null;
  const to   = dateOk(req.query.to)   ? req.query.to   : null;

  const rows = fdb.listRecentFilteredByUser(req.user.id, {
    before: Number.isFinite(before) && before > 0 ? before : undefined,
    limit,
    kind, q, from, to,
  });
  const nextCursor = rows.length === limit ? rows[rows.length - 1].id : null;
  res.json({ html: rows.map(renderRecentCard).join(''), nextCursor });
});

app.post('/api/rename/:slug', requireUser, express.json(), (req, res) => {
  const title = (req.body && req.body.title || '').toString().trim();
  if (!title) return res.status(400).json({ ok: false, error: 'title required' });
  const changed = fdb.updateTitle(req.params.slug, req.user.id, title.slice(0, 200));
  if (!changed) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({ ok: true, title });
});

app.post('/api/toggle-download/:slug', requireUser, express.json(), (req, res) => {
  const allowed = !!(req.body && req.body.allowed);
  const changed = fdb.setDownloadAllowed(req.params.slug, req.user.id, allowed);
  if (!changed) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({ ok: true, allowed });
});

app.post('/api/delete/:slug', requireUser, (req, res) => {
  const ghlUrl = fdb.deleteBySlugForUser(req.params.slug, req.user.id);
  if (!ghlUrl) return res.status(404).json({ ok: false, error: 'not found' });
  // Use the user's config so files in their own folder get deleted with
  // their PIT. Files that predate a user's custom config were uploaded
  // via the shared env — effectiveGhlConfig falls back to env when the
  // user hasn't set one, so best-effort cleanup still goes to the right
  // bucket. The one corner case — user uploads while shared, then later
  // customizes — still works because delete uses the saved ghl_url and
  // the shared PIT always has access (same sub-account today).
  try { ghl.tryDeleteFromGhl(ghlUrl, users.effectiveGhlConfig(udb.getById(req.user.id))); } catch {}
  res.json({ ok: true });
});

// ---------- admin ----------

function renderUserRow(u) {
  const opts = ['trial', 'regular', 'deactivated'].map(s => `<option value="${s}"${u.status === s ? ' selected' : ''}>${s}</option>`).join('');
  const fileCount = fdb.countByUser(u.id);
  const isSelf = u.is_admin;
  const disableDanger = isSelf ? 'disabled title="Cannot delete admin"' : '';
  return `
    <tr data-user-id="${u.id}">
      <td>
        <div class="user-name">${escHtml(u.name || '—')}${u.is_admin ? ' <span class="pill" style="background:#2563eb1a;color:#2563eb;border:1px solid #2563eb55;">admin</span>' : ''}</div>
        <div class="user-email">${escHtml(u.email)}</div>
      </td>
      <td>${statusPill(u.status)}</td>
      <td>${fileCount}</td>
      <td class="muted">${escHtml(fmtGstTimestamp(u.created_at))}</td>
      <td>
        <div class="row" style="gap: 6px;">
          <select class="status-select" ${isSelf ? 'disabled title="Admin cannot change own status"' : ''}>${opts}</select>
          <button class="btn btn-secondary btn-sm reset-btn" type="button">Reset password</button>
          <button class="btn btn-danger btn-sm delete-btn" type="button" ${disableDanger}>Delete</button>
        </div>
      </td>
    </tr>
  `;
}

app.get('/admin', requireUser, requireAdmin, (req, res) => {
  const all = udb.list();
  const counts = udb.countByStatus();
  const rows = all.map(renderUserRow).join('');
  res.send(layout({
    title: 'Admin — ' + SITE_NAME,
    user: req.user,
    wide: true,
    body: `
      <h1>Admin</h1>
      <p class="muted">Manage accounts.</p>
      <div class="card" style="display: flex; gap: 20px; flex-wrap: wrap; font-size: 14px;">
        <div><strong>${all.length}</strong> total</div>
        <div><strong>${counts.trial || 0}</strong> trial</div>
        <div><strong>${counts.regular || 0}</strong> regular</div>
        <div><strong>${counts.deactivated || 0}</strong> deactivated</div>
      </div>

      <details class="card" id="create-user-card">
        <summary style="cursor: pointer; font-weight: 600; list-style: none; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 18px;">➕</span>
          <span>Create a new user</span>
          <span class="muted" style="font-weight: 400; font-size: 13px;">— skip the signup flow, set type directly</span>
        </summary>
        <form id="create-user-form" class="stack" style="margin-top: 16px;">
          <div class="row" style="gap: 12px;">
            <div style="flex: 1 1 260px;">
              <label for="new-name">Name</label>
              <input id="new-name" name="name" type="text" required autocomplete="off">
            </div>
            <div style="flex: 1 1 260px;">
              <label for="new-email">Email</label>
              <input id="new-email" name="email" type="email" required autocomplete="off">
            </div>
          </div>
          <div class="row" style="gap: 12px;">
            <div style="flex: 1 1 260px;">
              <label for="new-password">Password (min 8 chars)</label>
              <input id="new-password" name="password" type="password" required minlength="8" autocomplete="new-password">
            </div>
            <div style="flex: 1 1 260px;">
              <label for="new-type">User type</label>
              <select id="new-type" name="type" style="width:100%; padding:12px 14px; font-size:16px; border:1px solid var(--border); border-radius:10px; background:#fff;">
                <option value="trial">Trial — one file per kind</option>
                <option value="regular" selected>Regular — unlimited uploads</option>
                <option value="admin">Admin — full dashboard access</option>
                <option value="deactivated">Deactivated — cannot log in</option>
              </select>
            </div>
          </div>
          <div class="row">
            <button type="submit" class="btn">Create user</button>
            <button type="reset" class="btn btn-secondary">Clear</button>
          </div>
          <p class="err" id="create-err" style="display:none;"></p>
          <p class="ok" id="create-ok" style="display:none;"></p>
        </form>
      </details>

      <div class="card">
        <table class="users-table">
          <thead><tr><th>User</th><th>Status</th><th>Files</th><th>Joined</th><th>Actions</th></tr></thead>
          <tbody id="users-tbody">${rows}</tbody>
        </table>
      </div>
      <script>
        (function () {
          // --- Create user form ---
          const createForm = document.getElementById('create-user-form');
          const createErr = document.getElementById('create-err');
          const createOk = document.getElementById('create-ok');
          if (createForm) {
            createForm.addEventListener('submit', async (ev) => {
              ev.preventDefault();
              createErr.style.display = 'none';
              createOk.style.display = 'none';
              const payload = {
                name: document.getElementById('new-name').value.trim(),
                email: document.getElementById('new-email').value.trim(),
                password: document.getElementById('new-password').value,
                type: document.getElementById('new-type').value,
              };
              const submitBtn = createForm.querySelector('button[type="submit"]');
              submitBtn.disabled = true;
              try {
                const res = await fetch('/admin/users', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  credentials: 'same-origin',
                  body: JSON.stringify(payload),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
                createOk.textContent = 'Created ' + data.user.email + ' (' + payload.type + ').';
                createOk.style.display = 'block';
                // Reload so the new row appears in the users table and the
                // summary counts update without us re-templating client-side.
                setTimeout(() => location.reload(), 700);
              } catch (err) {
                createErr.textContent = err.message || 'Create failed';
                createErr.style.display = 'block';
                submitBtn.disabled = false;
              }
            });
          }

          const tbody = document.getElementById('users-tbody');
          if (!tbody) return;

          tbody.addEventListener('change', async (e) => {
            if (!e.target.classList.contains('status-select')) return;
            const tr = e.target.closest('tr');
            const id = tr.dataset.userId;
            const status = e.target.value;
            e.target.disabled = true;
            try {
              const res = await fetch('/admin/users/' + id + '/status', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status }), credentials: 'same-origin',
              });
              if (!res.ok) throw new Error('HTTP ' + res.status);
              // Re-fetch the pill — cheapest way to reflect the change.
              location.reload();
            } catch { alert('Status change failed.'); e.target.disabled = false; }
          });

          tbody.addEventListener('click', async (e) => {
            const btn = e.target.closest('button');
            if (!btn) return;
            const tr = btn.closest('tr');
            const id = tr.dataset.userId;

            if (btn.classList.contains('reset-btn')) {
              const pw = prompt('Enter a new password for this user (min 8 characters):');
              if (pw == null) return;
              if (pw.length < 8) { alert('Password must be at least 8 characters.'); return; }
              btn.disabled = true;
              try {
                const res = await fetch('/admin/users/' + id + '/reset-password', {
                  method: 'POST', headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ password: pw }), credentials: 'same-origin',
                });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                alert('Password reset.');
              } catch { alert('Reset failed.'); }
              btn.disabled = false;
              return;
            }

            if (btn.classList.contains('delete-btn')) {
              const who = tr.querySelector('.user-email').textContent.trim();
              if (!confirm('Delete account ' + who + ' and all their files?\\n\\nThis removes the user, their share links, and their files from storage. This cannot be undone.')) return;
              btn.disabled = true;
              try {
                const res = await fetch('/admin/users/' + id + '/delete', { method: 'POST', credentials: 'same-origin' });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                tr.remove();
              } catch { alert('Delete failed.'); btn.disabled = false; }
              return;
            }
          });
        })();
      </script>
    `,
  }));
});

// Admin-created account. Skips the public signup flow and lets admin set
// the status (and admin flag) directly. "type" is a compact UI abstraction —
// admin = status:regular + is_admin:1; everything else = that status + is_admin:0.
app.post('/admin/users', requireUser, requireAdmin, express.json(), (req, res) => {
  try {
    const { name, email, password, type } = req.body || {};
    const allowedTypes = ['trial', 'regular', 'admin', 'deactivated'];
    if (!allowedTypes.includes(type)) {
      return res.status(400).json({ ok: false, error: 'Invalid user type.' });
    }
    const status = type === 'admin' ? 'regular' : type;
    const is_admin = type === 'admin';

    const u = users.signup({ name, email, password, status, is_admin });
    console.log(`[admin-create] ${req.user.email} created ${u.email} (type=${type})`);
    res.status(201).json({ ok: true, user: u });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/admin/users/:id/status', requireUser, requireAdmin, express.json(), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const target = udb.getById(id);
  if (!target) return res.status(404).json({ ok: false, error: 'not found' });
  if (target.is_admin && target.id === req.user.id) return res.status(400).json({ ok: false, error: 'cannot change own admin status' });
  try {
    udb.setStatus(id, req.body && req.body.status);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/admin/users/:id/reset-password', requireUser, requireAdmin, express.json(), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const target = udb.getById(id);
  if (!target) return res.status(404).json({ ok: false, error: 'not found' });
  try {
    const hash = users.hashPassword(req.body && req.body.password);
    udb.setPasswordHash(id, hash);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/admin/users/:id/delete', requireUser, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const target = udb.getById(id);
  if (!target) return res.status(404).json({ ok: false, error: 'not found' });
  if (target.is_admin) return res.status(400).json({ ok: false, error: 'cannot delete admin' });
  // Cascade: delete user's files locally, best-effort remove from GHL.
  // Use the deleted user's own config if they had one so files in their
  // personal folder get torn down with their PIT. The shared-env fallback
  // handles everything they uploaded before customizing.
  const userCfg = users.effectiveGhlConfig(target);
  const urls = fdb.deleteAllByUser(id);
  udb.deleteById(id);
  for (const u of urls) { try { ghl.tryDeleteFromGhl(u, userCfg); } catch {} }
  res.json({ ok: true, deletedFiles: urls.length });
});

// ---------- healthz ----------

app.get('/healthz', (req, res) => res.json({ ok: true, site: SITE_NAME }));

// Admin-only DB peek for debugging the progressive-signup flow.
// Returns the current state of pending (activated=0) files and the
// most recent magic_links so we can match them up.
app.get('/api/admin/debug-pending', requireUser, requireAdmin, (req, res) => {
  const { raw } = require('./lib/db');
  const pending = raw.prepare(`
    SELECT id, slug, guest_id, pending_email, user_id, activated, created_at,
           substr(ghl_url,1,60) AS ghl_url
    FROM files WHERE activated = 0 ORDER BY id DESC LIMIT 20
  `).all();
  const allFiles = raw.prepare(`
    SELECT id, slug, guest_id, pending_email, user_id, activated, created_at
    FROM files ORDER BY id DESC LIMIT 20
  `).all();
  const recentMagic = raw.prepare(`
    SELECT id, email, guest_id, used_at, expires_at, created_at
    FROM magic_links ORDER BY id DESC LIMIT 20
  `).all();
  let bySlug = null;
  if (req.query.slug) {
    bySlug = raw.prepare(`SELECT * FROM files WHERE slug = ?`).get(req.query.slug) || null;
  }
  res.json({ ok: true, pending, allFiles, recentMagic, bySlug, now_utc: new Date().toISOString() });
});

// Admin-only force-activate: claim a pending file by slug to a user.
// Useful when a magic-link click failed silently and we need to rescue
// a file that's already uploaded.
app.post('/api/admin/force-activate/:slug', requireUser, requireAdmin, express.json(), (req, res) => {
  const { raw } = require('./lib/db');
  const toEmail = (req.body && req.body.email || '').toLowerCase().trim();
  if (!toEmail) return res.status(400).json({ ok: false, error: 'email required in body' });
  let u = udb.getByEmail(toEmail);
  if (!u) {
    const id = udb.insert({
      email: toEmail,
      name: toEmail.split('@')[0],
      password_hash: users.hashPassword(crypto.randomBytes(24).toString('base64url')),
      status: 'trial', is_admin: 0,
    });
    u = udb.getById(id);
  }
  const info = raw.prepare(`
    UPDATE files SET user_id = ?, activated = 1, guest_id = NULL, pending_email = NULL
    WHERE slug = ? AND activated = 0
  `).run(u.id, req.params.slug);
  res.json({ ok: true, assignedTo: u.email, userId: u.id, changed: info.changes });
});

// Admin-only server-capacity snapshot. Runs `df` inside the container,
// which sees the host's disk via the /app/data bind mount, so the
// numbers for that path reflect the Hetzner VPS's real free space.
app.get('/api/admin/system', requireUser, requireAdmin, (req, res) => {
  const { execFileSync } = require('node:child_process');
  function run(cmd, args) {
    try { return execFileSync(cmd, args, { encoding: 'utf8', timeout: 5000 }).trim(); }
    catch (e) { return `error: ${e.message.slice(0, 200)}`; }
  }
  res.json({
    ok: true,
    df_h: run('df', ['-h']),
    df_P_total: run('df', ['-P', '-B1', '/app/data']),
    uptime: run('uptime', []),
    free: run('free', ['-h']),
    hostname: run('hostname', []),
    node: process.version,
  });
});

// ---------- boot ----------

console.log(`[boot] starting ${SITE_NAME} on :${PORT}`);
try {
  users.seedAdminFromEnv();
} catch (err) {
  console.error('[admin-seed] failed:', err.message);
}
const check = ghl.healthCheck();
if (check.ok) console.log('[boot] GHL reachable');
else console.warn('[boot] GHL check failed:', check.reason);

app.listen(PORT, () => console.log(`[boot] listening on :${PORT}`));

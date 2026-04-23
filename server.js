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

const { users: udb, files: fdb } = require('./lib/db');
const users = require('./lib/users');
const ghl = require('./lib/ghl');
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
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/upload');
  res.send(layout({
    title: 'Log in — ' + SITE_NAME,
    user: null,
    body: `
      <h1>Log in</h1>
      <form class="card stack" method="POST" action="/login">
        <div>
          <label for="email">Email</label>
          <input id="email" name="email" type="email" required autofocus autocomplete="email">
        </div>
        <div>
          <label for="password">Password</label>
          <input id="password" name="password" type="password" required autocomplete="current-password">
        </div>
        <button type="submit" class="btn btn-block">Log in</button>
        ${req.query.err ? '<p class="err">Wrong email or password.</p>' : ''}
        <p class="muted" style="margin: 0; text-align: center; font-size: 14px;">
          No account? <a href="/signup">Sign up</a>
        </p>
      </form>
    `,
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
  res.send(layout({
    title: 'Sign up — ' + SITE_NAME,
    user: null,
    body: `
      <h1>Create your account</h1>
      <p class="muted">You'll start on a free trial — one file of each kind (image, video, audio, PDF, text) while we get you approved.</p>
      <form class="card stack" method="POST" action="/signup">
        <div>
          <label for="name">Your name</label>
          <input id="name" name="name" type="text" required autofocus autocomplete="name">
        </div>
        <div>
          <label for="email">Email</label>
          <input id="email" name="email" type="email" required autocomplete="email">
        </div>
        <div>
          <label for="password">Password (min 8 chars)</label>
          <input id="password" name="password" type="password" required minlength="8" autocomplete="new-password">
        </div>
        <div>
          <label for="confirm">Confirm password</label>
          <input id="confirm" name="confirm" type="password" required minlength="8" autocomplete="new-password">
        </div>
        <button type="submit" class="btn btn-block">Create account</button>
        ${err ? `<p class="err">${escHtml(err)}</p>` : ''}
        <p class="muted" style="margin: 0; text-align: center; font-size: 14px;">
          Already have an account? <a href="/login">Log in</a>
        </p>
      </form>
    `,
  }));
});

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

  const firstPage = fdb.listRecentByUser(req.user.id, { limit: RECENT_PAGE_SIZE });
  const nextCursor = firstPage.length === RECENT_PAGE_SIZE
    ? firstPage[firstPage.length - 1].id : null;

  const recentHtml = firstPage.length === 0 ? '' : `
    <h2>Your recent shares</h2>
    <div id="recent-list">${firstPage.map(renderRecentCard).join('')}</div>
    ${nextCursor != null ? `<div id="recent-sentinel" data-cursor="${nextCursor}" class="muted" style="text-align: center; padding: 16px;">Loading more…</div>` : ''}
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
          xhr.responseType = 'document';

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
            if (xhr.status >= 200 && xhr.status < 300 && xhr.responseXML) {
              progressFill.style.width = '100%';
              progressPct.textContent = '100%';
              progressEta.textContent = 'Done!';
              progress.classList.add('is-done');
              setTimeout(() => { document.open(); document.write(xhr.responseText); document.close(); }, 350);
            } else {
              btn.disabled = false; btn.textContent = 'Upload and make link';
              progress.classList.remove('is-active');
              // Try to surface the server's text body on error
              let msg = 'Upload failed: ' + (xhr.status || 'network error');
              try { const t = xhr.response?.body?.innerText?.trim(); if (t) msg = t.slice(0, 200); } catch {}
              errMsg.textContent = msg; errMsg.style.display = 'block';
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
      </script>
    `,
  }));
});

// JS for the /upload recent-list block (extracted so it isn't duplicated
// inside template literals). Event delegation covers both the initial cards
// and everything the infinite-scroll fetch appends.
const RECENT_LIST_JS = `
  (function () {
    const list = document.getElementById('recent-list');
    if (!list) return;
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
    const sentinel = document.getElementById('recent-sentinel');
    if (!sentinel || !('IntersectionObserver' in window)) return;
    let loading = false;
    const io = new IntersectionObserver(async (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting || loading) continue;
        loading = true;
        const cursor = sentinel.dataset.cursor;
        try {
          const res = await fetch('/api/recent?before=' + encodeURIComponent(cursor) + '&limit=${RECENT_PAGE_SIZE}', { credentials: 'same-origin' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          const data = await res.json();
          if (data.html) list.insertAdjacentHTML('beforeend', data.html);
          if (data.nextCursor == null) { io.disconnect(); sentinel.remove(); }
          else { sentinel.dataset.cursor = data.nextCursor; loading = false; }
        } catch { sentinel.textContent = 'Could not load more — scroll to retry.'; loading = false; }
      }
    }, { rootMargin: '200px 0px' });
    io.observe(sentinel);
  })();
`;

// ---------- upload endpoint ----------

app.post('/api/upload', requireUser, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send(uploadErrorPage('No file uploaded', req.user));

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

    // Pick the user's GHL config if they set one; otherwise fall back to
    // shared env. Trial users are gated above so they only ever hit
    // shared here, which matches the "regular users only" rule.
    const ghlCfg = users.effectiveGhlConfig(fresh);
    const ghlUrl = ghl.uploadToGhl(file.path, ghlDisplayName, cls.ghlMime, ghlCfg);
    console.log(`[upload] user=${req.user.id} target=${ghlCfg.source}`);

    fdb.insert({
      slug, title, original_filename: file.originalname,
      kind: cls.kind, mime_type: cls.mime, size_bytes: file.size,
      download_allowed: allowDownload, ghl_url: ghlUrl,
      user_id: req.user.id,
    });

    const shareLink = `${PUBLIC_ORIGIN}/f/${slug}`;
    console.log(`[upload] done user=${req.user.id}: ${shareLink}`);

    res.send(layout({
      title: 'Link ready — ' + SITE_NAME,
      user: req.user,
      body: `
        <h1 class="ok">Link ready</h1>
        <p class="muted">Send this link. The viewer is built in — no app needed.</p>
        <div class="card stack">
          <div class="link-box" id="link">${escHtml(shareLink)}</div>
          <button class="btn btn-block" id="copyBtn" type="button">Copy link</button>
          <a class="btn btn-secondary btn-block" href="/f/${slug}" target="_blank" rel="noopener">Open to test</a>
        </div>
        <div class="card">
          <p><strong>${kindEmoji(cls.kind)} ${escHtml(cls.kind)}</strong> · ${fmtBytes(file.size)}</p>
          <p class="muted" style="margin: 0;">${allowDownload ? 'Downloads allowed' : 'Preview only — downloads off'}</p>
          <p class="muted" style="margin: 6px 0 0; font-size: 13px;">
            Stored in ${ghlCfg.source === 'user' ? `your folder <strong>${escHtml(ghlCfg.folderName)}</strong>` : 'the shared folder'}.
          </p>
        </div>
        <a href="/upload" class="btn btn-secondary btn-block">Upload another</a>
        <script>
          const btn = document.getElementById('copyBtn');
          btn.addEventListener('click', async () => {
            try { await navigator.clipboard.writeText(${JSON.stringify(shareLink)}); btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy link', 1500); }
            catch { btn.textContent = 'Copy failed — long-press the link'; }
          });
        </script>
      `,
    }));
  } catch (err) {
    console.error('[upload] failed:', err.message);
    res.status(400).send(uploadErrorPage(err.message || 'Unknown error', req.user));
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

// ---------- raw / download proxies (public) ----------

app.get('/raw/:slug', async (req, res) => {
  const rec = fdb.getBySlug(req.params.slug);
  if (!rec) return res.status(404).send('Not found');
  try {
    const upstream = await fetch(rec.ghl_url);
    if (!upstream.ok || !upstream.body) return res.status(502).send('Upstream error');
    res.set('Content-Type', rec.mime_type || 'application/octet-stream');
    const len = upstream.headers.get('content-length');
    if (len) res.set('Content-Length', len);
    const range = upstream.headers.get('accept-ranges');
    if (range) res.set('Accept-Ranges', range);
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
  if (!rec.download_allowed) return res.status(403).send('Downloads are disabled for this file.');
  const filename = rec.original_filename || (rec.title || 'file') + '.' + (rec.kind === 'text' ? 'txt' : rec.kind);
  try {
    const upstream = await fetch(rec.ghl_url);
    if (!upstream.ok || !upstream.body) return res.status(502).send('Upstream error');
    res.set('Content-Type', rec.mime_type || 'application/octet-stream');
    res.set('Content-Disposition', `attachment; filename="${filename.replace(/"/g, '')}"`);
    const len = upstream.headers.get('content-length');
    if (len) res.set('Content-Length', len);
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
  if (!Number.isFinite(before) || before <= 0) return res.status(400).json({ error: 'before cursor required' });
  const limit = Math.max(1, Math.min(50, parseInt(req.query.limit, 10) || RECENT_PAGE_SIZE));
  const rows = fdb.listRecentByUser(req.user.id, { before, limit });
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

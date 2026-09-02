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

const { users: udb, files: fdb, passwordResets: prdb, magicLinks: mldb, messages: mdb, groups: gdb, feed: feeddb, chats: cdb, apiTokens: atdb, deviceTokens: dtdb, NOTES_MAX_CHARS } = require('./lib/db');
const users = require('./lib/users');
const ghl = require('./lib/ghl');
const transcode = require('./lib/transcode');
const email = require('./lib/email');
const { classify, SIZE_CAPS, fmtBytes } = require('./lib/classify');
const viewers = require('./lib/viewers');
const apns = require('./lib/apns');
const apiV1 = require('./lib/api_v1');

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

// Third-party JS we serve ourselves rather than from a CDN. A blocked or slow
// cdn.jsdelivr.net used to stall the whole page — a deferred <script> that
// never resolves holds DOMContentLoaded hostage — and the chat editor is the
// one screen people open on hotel wifi with a phone full of screenshots.
app.use('/vendor', express.static(path.join(__dirname, 'public', 'vendor'), {
  maxAge: '30d',
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

// `status` is a workspace-organization tag the admin sets — it is NOT a paid
// tier and nothing in the app or on this site can be bought. App Review
// (guideline 2.1(b)) read the old "trial / upgrade" wording as a paid plan and
// rejected the iOS build over it, so the internal value stays `trial` while
// every user-facing surface says "Starter". Keep it that way.
function statusPill(status) {
  const color = { trial: '#f59e0b', regular: '#16a34a', deactivated: '#dc2626' }[status] || '#64748b';
  const label = { trial: 'starter', regular: 'regular', deactivated: 'deactivated' }[status] || status;
  return `<span class="pill" style="background:${color}1a;color:${color};border:1px solid ${color}55;">${escHtml(label)}</span>`;
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
  main { max-width: 720px; margin: 0 auto; padding: 20px 20px 56px; }
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
  /* Notes — the copyable text that rides along with any share */
  .notes-card { padding: 14px 16px 16px; }
  .notes-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 10px; }
  .notes-title { font-weight: 700; font-size: 15px; }
  .notes-body {
    background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 8px; margin: 0;
    white-space: pre-wrap; word-break: break-word; overflow-x: auto;
    font: 13px/1.55 ui-monospace, "SF Mono", Menlo, monospace;
    max-height: 60vh; overflow-y: auto; user-select: text;
  }
  .notes-copy { flex: 0 0 auto; white-space: nowrap; }
  /* The notes editor (upload form + edit modal) */
  textarea.notes-input {
    width: 100%; min-height: 96px; resize: vertical; padding: 12px 14px;
    border: 1px solid var(--border); border-radius: 10px; background: #fff; color: var(--fg);
    font: 14px/1.5 ui-monospace, "SF Mono", Menlo, monospace;
  }
  textarea.notes-input:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px rgba(37,99,235,0.15); }
  .notes-badge { display: inline-block; font-size: 12px; color: var(--muted); }
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
      <a href="/chats">Chats</a>
      <a href="/messages">Messages</a>
      <a href="/account">Account</a>
      ${adminLink}
      <form method="POST" action="/logout" style="display:inline;"><button type="submit">Log out</button></form>
    </div>
  `;
}

function layout({ title, body, user, ogTitle, ogDescription, ogImageUrl, noindex = true, wide = false, mainClass = '' }) {
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
  <style>${BASE_CSS}${DEL_MODAL_CSS}${NOTES_MODAL_CSS}${CHAT_CSS}${REORDER_CSS}</style>
</head>
<body>
  <header class="site-header">
    <a href="/" class="brand" aria-label="${escHtml(SITE_NAME)} — home">
      <span class="brand-mark">📤</span>
      <span class="brand-name">${escHtml(SITE_NAME)}</span>
    </a>
    ${renderNav(user)}
  </header>
  <main${[wide ? 'wide' : '', mainClass].filter(Boolean).length ? ` class="${[wide ? 'wide' : '', mainClass].filter(Boolean).join(' ')}"` : ''}>
    ${body}
  </main>
  ${DEL_MODAL_HTML}
  ${NOTES_MODAL_HTML}
  <script>${DEL_MODAL_JS}</script>
  <script>${NOTES_MODAL_JS}</script>
</body>
</html>`;
}

// ---------- shared permanent-delete modal ----------
//
// Every destructive action in the app calls window.__confirmDelete()
// instead of the browser's native confirm(). The modal forces the
// user to tick a checkbox acknowledging the permanence — there is
// no path to the red Delete button without it. Cancel is the
// default focused control on open so an accidental Enter doesn't
// trigger destruction.

const DEL_MODAL_HTML = `
  <div class="del-modal-backdrop" id="del-modal" hidden role="dialog" aria-modal="true" aria-labelledby="del-modal-title">
    <div class="del-modal-card">
      <h2 class="del-modal-title" id="del-modal-title">Delete permanently?</h2>
      <p class="del-modal-text" id="del-modal-text">This action cannot be undone.</p>
      <label class="del-modal-check">
        <input type="checkbox" id="del-modal-checkbox">
        <span>I understand this is permanent and cannot be reversed.</span>
      </label>
      <div class="del-modal-actions">
        <button type="button" class="del-modal-cancel" id="del-modal-cancel">Cancel</button>
        <button type="button" class="del-modal-ok" id="del-modal-ok" disabled>Delete permanently</button>
      </div>
    </div>
  </div>
`;

const DEL_MODAL_CSS = `
  .del-modal-backdrop {
    position: fixed; inset: 0; z-index: 9999;
    background: rgba(15,23,42,0.55);
    display: flex; align-items: center; justify-content: center;
    padding: 20px;
    backdrop-filter: blur(2px);
    animation: delFade .15s ease-out;
  }
  .del-modal-backdrop[hidden] { display: none; }
  @keyframes delFade { from { opacity: 0; } to { opacity: 1; } }
  .del-modal-card {
    background: #fff; border-radius: 14px; padding: 22px 22px 18px;
    max-width: 420px; width: 100%;
    box-shadow: 0 20px 50px -16px rgba(0,0,0,0.35);
    animation: delPop .18s cubic-bezier(.18,.7,.25,1.2);
  }
  @keyframes delPop {
    from { transform: scale(0.94); opacity: 0; }
    to   { transform: scale(1);    opacity: 1; }
  }
  .del-modal-title {
    margin: 0 0 6px; font-size: 19px; font-weight: 700;
    letter-spacing: -0.02em; color: #991b1b;
  }
  .del-modal-text {
    margin: 0 0 16px; font-size: 14px; line-height: 1.5; color: #475569;
    word-break: break-word;
  }
  .del-modal-check {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 12px 14px; margin: 0 0 16px;
    background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px;
    cursor: pointer;
  }
  .del-modal-check input[type="checkbox"] {
    width: 20px; height: 20px; flex: 0 0 auto; margin: 0;
    accent-color: #dc2626;
  }
  .del-modal-check span { font-size: 14px; line-height: 1.4; color: #7f1d1d; font-weight: 500; }
  .del-modal-actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .del-modal-actions button {
    flex: 1 1 140px; min-height: 48px; padding: 12px 16px;
    border: 0; border-radius: 10px; cursor: pointer;
    font: inherit; font-size: 15px; font-weight: 600;
    transition: filter .15s, transform .08s;
  }
  .del-modal-cancel { background: #fff; color: #0f172a; border: 1px solid #e5e7eb; }
  .del-modal-cancel:hover { background: #f3f4f6; }
  .del-modal-ok {
    background: linear-gradient(180deg, #dc2626 0%, #b91c1c 100%); color: #fff;
    box-shadow: 0 1px 2px rgba(220,38,38,0.22), 0 8px 22px -8px rgba(220,38,38,0.55);
  }
  .del-modal-ok:hover { filter: brightness(1.05); }
  .del-modal-ok:active { transform: translateY(1px); }
  .del-modal-ok:disabled {
    background: #fecaca; color: #fff; box-shadow: none;
    cursor: not-allowed; filter: none; transform: none;
  }
`;

const DEL_MODAL_JS = `
  (function () {
    const modal   = document.getElementById('del-modal');
    const titleEl = document.getElementById('del-modal-title');
    const textEl  = document.getElementById('del-modal-text');
    const check   = document.getElementById('del-modal-checkbox');
    const okBtn   = document.getElementById('del-modal-ok');
    const cancel  = document.getElementById('del-modal-cancel');
    if (!modal) return;

    let onConfirm = null;

    function open(opts) {
      titleEl.textContent = opts.title || 'Delete permanently?';
      textEl.textContent  = opts.message || 'This action cannot be undone.';
      okBtn.textContent   = opts.okText  || 'Delete permanently';
      check.checked = false;
      okBtn.disabled = true;
      modal.hidden = false;
      document.body.style.overflow = 'hidden';
      onConfirm = opts.then || null;
      // Focus Cancel by default so a stray Enter keypress dismisses
      // rather than confirms.
      setTimeout(() => cancel.focus(), 50);
    }
    function close() {
      modal.hidden = true;
      document.body.style.overflow = '';
      onConfirm = null;
    }

    check.addEventListener('change', () => { okBtn.disabled = !check.checked; });
    cancel.addEventListener('click', close);
    okBtn.addEventListener('click', async () => {
      if (!check.checked) return;
      const fn = onConfirm;
      close();
      if (typeof fn === 'function') {
        try { await fn(); } catch (e) { console.error('[del-modal] callback error', e); }
      }
    });
    // Click outside the card = cancel
    modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
    // Escape = cancel
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !modal.hidden) close();
    });

    window.__confirmDelete = open;
  })();
`;

// ---------- shared notes editor modal ----------
//
// Notes are multi-line by nature (a pasted prompt is the whole point), so
// the browser's prompt() — single-line, no newlines — is the wrong tool.
// This is the same modal shape as the delete confirm, with a textarea.
// window.__editNotes({ value, title, then(text) }) opens it; `then` fires
// with the new text only if the user saves.

const NOTES_MODAL_HTML = `
  <div class="notes-modal-backdrop" id="notes-modal" hidden role="dialog" aria-modal="true" aria-labelledby="notes-modal-title">
    <div class="notes-modal-card">
      <h2 class="notes-modal-title" id="notes-modal-title">Notes</h2>
      <p class="notes-modal-text">
        Anyone with the share link sees this under the file, with a Copy button.
        Leave it empty to remove the notes.
      </p>
      <textarea id="notes-modal-input" class="notes-input" rows="10" maxlength="${NOTES_MAX_CHARS}"
                placeholder="Paste a prompt, a caption, the steps you talked through…"></textarea>
      <div class="notes-modal-actions">
        <button type="button" class="notes-modal-cancel" id="notes-modal-cancel">Cancel</button>
        <button type="button" class="notes-modal-ok" id="notes-modal-ok">Save notes</button>
      </div>
    </div>
  </div>
`;

const NOTES_MODAL_CSS = `
  .notes-modal-backdrop {
    position: fixed; inset: 0; z-index: 9999;
    background: rgba(15,23,42,0.55);
    display: flex; align-items: center; justify-content: center;
    padding: 20px; backdrop-filter: blur(2px);
    animation: delFade .15s ease-out;
  }
  .notes-modal-backdrop[hidden] { display: none; }
  .notes-modal-card {
    background: #fff; border-radius: 14px; padding: 22px 22px 18px;
    max-width: 620px; width: 100%;
    box-shadow: 0 20px 50px -16px rgba(0,0,0,0.35);
    animation: delPop .18s cubic-bezier(.18,.7,.25,1.2);
  }
  .notes-modal-title { margin: 0 0 6px; font-size: 19px; font-weight: 700; letter-spacing: -0.02em; }
  .notes-modal-text { margin: 0 0 14px; font-size: 14px; line-height: 1.5; color: #475569; }
  .notes-modal-card .notes-input { min-height: 220px; }
  .notes-modal-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
  .notes-modal-actions button {
    flex: 1 1 140px; min-height: 48px; padding: 12px 16px;
    border: 0; border-radius: 10px; cursor: pointer;
    font: inherit; font-size: 15px; font-weight: 600;
    transition: filter .15s, transform .08s;
  }
  .notes-modal-cancel { background: #fff; color: #0f172a; border: 1px solid #e5e7eb; }
  .notes-modal-cancel:hover { background: #f3f4f6; }
  .notes-modal-ok {
    background: linear-gradient(180deg, var(--brand) 0%, var(--brand-dark) 100%); color: #fff;
    box-shadow: 0 1px 2px rgba(37,99,235,0.22), 0 8px 22px -8px rgba(37,99,235,0.55);
  }
  .notes-modal-ok:hover { filter: brightness(1.05); }
  .notes-modal-ok:active { transform: translateY(1px); }
`;

const NOTES_MODAL_JS = `
  (function () {
    const modal = document.getElementById('notes-modal');
    const titleEl = document.getElementById('notes-modal-title');
    const input = document.getElementById('notes-modal-input');
    const cancel = document.getElementById('notes-modal-cancel');
    const okBtn = document.getElementById('notes-modal-ok');
    if (!modal) return;

    let onSave = null;

    function open(opts) {
      opts = opts || {};
      titleEl.textContent = opts.title || 'Notes';
      input.value = opts.value || '';
      onSave = typeof opts.then === 'function' ? opts.then : null;
      modal.hidden = false;
      document.body.style.overflow = 'hidden';
      input.focus();
      // Caret at the end, so appending to existing notes needs no extra click.
      try { input.setSelectionRange(input.value.length, input.value.length); } catch (e) {}
    }
    function close() {
      modal.hidden = true;
      document.body.style.overflow = '';
      onSave = null;
    }

    cancel.addEventListener('click', close);
    okBtn.addEventListener('click', async () => {
      const fn = onSave;
      const text = input.value;
      close();
      if (fn) { try { await fn(text); } catch (e) { console.error('[notes-modal] callback error', e); } }
    });
    modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !modal.hidden) close();
      // Enter alone must insert a newline — notes are multi-line — so the
      // keyboard save is the standard ⌘/Ctrl+Enter.
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && !modal.hidden) okBtn.click();
    });

    window.__editNotes = open;
  })();
`;

// ============================================================================
// Drag-to-reorder — shared by the file list (/upload) and the chat-scroll
// list (/chats).
//
// Two ways to move a card, because one is never enough on a phone:
//   1. Drag it. On a mouse that's an ordinary press-and-drag anywhere on the
//      card; on a touchscreen it's a ~180ms press first, so a normal flick
//      still scrolls the page instead of picking a card up.
//   2. Tap the ↑ / ↓ buttons in the card's grip bar. Same endpoint, so a
//      shaky finger never has to land a drag at all.
// Buttons and links inside a card are excluded from the drag, so "Copy link"
// still copies.
// ============================================================================

const REORDER_CSS = `
  .reorder-bar {
    display: flex; align-items: center; gap: 6px;
    margin: -20px -20px 14px; padding: 4px 8px 4px 4px;
    background: #f8fafc; border-bottom: 1px solid var(--border);
    border-radius: 12px 12px 0 0;
    cursor: grab; user-select: none; -webkit-user-select: none;
  }
  .reorder-bar:active { cursor: grabbing; }
  .stack > .reorder-bar + * { margin-top: 0; }
  .reorder-grip {
    flex: 0 0 auto; width: 40px; height: 40px;
    display: inline-flex; align-items: center; justify-content: center;
    color: #94a3b8; font-size: 17px; line-height: 1;
  }
  .reorder-hint { flex: 1 1 auto; font-size: 12px; color: var(--muted); min-width: 0;
                  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .reorder-btn {
    flex: 0 0 auto; width: 40px; height: 40px; border-radius: 9px;
    border: 1px solid var(--border); background: #fff; color: #475569;
    font-size: 16px; line-height: 1; cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center;
    transition: background .12s, transform .08s;
  }
  .reorder-btn:hover { background: #f1f5f9; color: #0f172a; }
  .reorder-btn:active { transform: scale(0.92); }
  .reorder-btn:disabled { opacity: 0.3; cursor: not-allowed; transform: none; }

  /* Whole card is the drag surface, so the finger doesn't have to find the
     grip. pan-y keeps vertical scrolling native until the press delay fires. */
  .reorder-item { touch-action: pan-y; }
  .reorder-item.sortable-ghost { opacity: 0.28; }
  .reorder-item.sortable-chosen .reorder-bar { background: #eef2ff; }
  .reorder-item.sortable-drag  { box-shadow: 0 18px 40px -12px rgba(15,23,42,0.45); }

  .reorder-toast {
    position: fixed; left: 50%; bottom: 22px; transform: translate(-50%, 14px);
    background: rgba(15,23,42,0.92); color: #fff; font-size: 14px; font-weight: 600;
    padding: 10px 16px; border-radius: 99px; z-index: 9998;
    opacity: 0; pointer-events: none; transition: opacity .18s, transform .18s;
  }
  .reorder-toast.on { opacity: 1; transform: translate(-50%, 0); }
  .reorder-toast.err { background: #b91c1c; }

  @media (max-width: 480px) {
    .reorder-hint { display: none; }
  }
`;

// The grip bar markup, rendered as the first child of a reorderable card.
function reorderBar(hint) {
  return `
    <div class="reorder-bar">
      <span class="reorder-grip" aria-hidden="true">⠿</span>
      <span class="reorder-hint">${escHtml(hint || 'Drag to reorder')}</span>
      <button type="button" class="reorder-btn reorder-up" aria-label="Move up" title="Move up">↑</button>
      <button type="button" class="reorder-btn reorder-down" aria-label="Move down" title="Move down">↓</button>
    </div>
  `;
}

const REORDER_JS = `
  (function () {
    if (window.__initReorder) return;

    var toastEl = null;
    var toastTimer = null;
    function toast(msg, isErr) {
      if (!toastEl) {
        toastEl = document.createElement('div');
        toastEl.className = 'reorder-toast';
        document.body.appendChild(toastEl);
      }
      toastEl.textContent = msg;
      toastEl.className = 'reorder-toast on' + (isErr ? ' err' : '');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(function () {
        toastEl.className = 'reorder-toast' + (isErr ? ' err' : '');
      }, isErr ? 3200 : 1400);
    }

    function whenSortable(fn, tries) {
      if (typeof Sortable !== 'undefined') return fn();
      if ((tries || 0) > 60) return;
      setTimeout(function () { whenSortable(fn, (tries || 0) + 1); }, 50);
    }

    /**
     * opts: { container, itemSelector, endpoint, hint }
     * Returns { refresh } so a list that re-renders itself (filters,
     * infinite scroll) can re-sync the arrow buttons.
     */
    window.__initReorder = function (opts) {
      var box = typeof opts.container === 'string'
        ? document.querySelector(opts.container) : opts.container;
      if (!box) return { refresh: function () {} };

      var sel = opts.itemSelector;

      function items() {
        return Array.prototype.slice.call(box.querySelectorAll(':scope > ' + sel));
      }

      // Grey out ↑ on the first card and ↓ on the last, so the ends of the
      // list are obvious instead of silently doing nothing.
      function refresh() {
        var rows = items();
        rows.forEach(function (row, i) {
          var up = row.querySelector('.reorder-up');
          var down = row.querySelector('.reorder-down');
          if (up) up.disabled = (i === 0);
          if (down) down.disabled = (i === rows.length - 1);
        });
      }

      var saving = false;
      async function save() {
        var slugs = items().map(function (r) { return r.dataset.slug; })
                           .filter(function (x) { return !!x; });
        if (slugs.length < 2 || saving) return;
        saving = true;
        try {
          var res = await fetch(opts.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ slugs: slugs }),
            credentials: 'same-origin',
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          toast('Order saved');
        } catch (err) {
          toast('Could not save the new order — reload and try again.', true);
          console.error('[reorder]', err);
        } finally {
          saving = false;
        }
      }

      whenSortable(function () {
        if (box.__reorderBound) return;
        box.__reorderBound = true;
        Sortable.create(box, {
          animation: 170,
          draggable: sel,
          // Anything a tap should still activate stays out of the drag.
          filter: 'button, a, input, textarea, select, label, .link-box, .filter-bar',
          preventOnFilter: false,
          // Mouse: drag starts immediately. Finger: hold ~180ms first, and
          // bail out to a normal page scroll if the finger travels before
          // then — otherwise the list becomes impossible to scroll.
          delay: 180,
          delayOnTouchOnly: true,
          touchStartThreshold: 8,
          forceFallback: true,
          fallbackOnBody: true,
          fallbackTolerance: 4,
          ghostClass: 'sortable-ghost',
          chosenClass: 'sortable-chosen',
          dragClass: 'sortable-drag',
          scroll: true,
          scrollSensitivity: 90,
          scrollSpeed: 12,
          bubbleScroll: true,
          onEnd: function (evt) {
            refresh();
            if (evt.oldIndex === evt.newIndex) return;
            save();
          },
        });
      });

      box.addEventListener('click', function (e) {
        var btn = e.target.closest('.reorder-up, .reorder-down');
        if (!btn || btn.disabled) return;
        var row = btn.closest(sel);
        if (!row || row.parentElement !== box) return;
        if (btn.classList.contains('reorder-up')) {
          var prev = row.previousElementSibling;
          while (prev && !prev.matches(sel)) prev = prev.previousElementSibling;
          if (!prev) return;
          box.insertBefore(row, prev);
        } else {
          var next = row.nextElementSibling;
          while (next && !next.matches(sel)) next = next.nextElementSibling;
          if (!next) return;
          box.insertBefore(next, row);
        }
        row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        refresh();
        save();
      });

      refresh();
      return { refresh: refresh };
    };
  })();
`;

// ---------- recent list rendering (per user, used on /upload) ----------

function renderRecentCard(r) {
  const shareLink = `${PUBLIC_ORIGIN}/f/${r.slug}`;
  const title = r.title || r.original_filename || 'File';
  const dlLabel = r.download_allowed ? 'Downloads ON' : 'Downloads OFF';
  const dlClass = r.download_allowed ? 'ok' : 'muted';
  const notes = (r.notes || '').toString();
  // The notes body is carried on the card as a data attribute so the Notes
  // editor opens instantly with the current text — no round-trip, and no
  // second endpoint to keep in sync with the list.
  return `
    <div class="card stack recent-item reorder-item" data-slug="${escHtml(r.slug)}" data-id="${r.id}" data-download="${r.download_allowed ? 1 : 0}" data-notes="${escHtml(notes)}">
      ${reorderBar('Drag to reorder')}
      <div>
        <div style="font-weight: 600; font-size: 16px; word-break: break-word;" class="recent-title">
          ${kindEmoji(r.kind)} ${escHtml(title)}
        </div>
        <div class="muted" style="font-size: 13px; margin-top: 2px;">
          ${escHtml(r.kind)} · ${fmtBytes(r.size_bytes)} · <span class="${dlClass} dl-state">${dlLabel}</span>
        </div>
        <div class="muted" style="font-size: 12px; margin-top: 2px;">
          ${escHtml(fmtGstTimestamp(r.created_at))}
          <span class="notes-badge notes-state"${notes ? '' : ' style="display:none;"'}> · 📝 has notes</span>
        </div>
      </div>
      <div class="link-box recent-link">${escHtml(shareLink)}</div>
      <button type="button" class="btn btn-block copy-btn" data-url="${escHtml(shareLink)}">Copy link</button>
      <div class="row">
        <a class="btn btn-secondary" href="/f/${escHtml(r.slug)}" target="_blank" rel="noopener">Open</a>
        <button type="button" class="btn btn-secondary rename-btn" data-slug="${escHtml(r.slug)}">Rename</button>
        <button type="button" class="btn btn-secondary notes-btn" data-slug="${escHtml(r.slug)}">${notes ? 'Edit notes' : 'Add notes'}</button>
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
          <p class="auth-panel-sub">Free to use. Create an account and start sharing links right away.</p>
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
        Starter accounts use the shared storage. Once the workspace admin sets your account to
        <strong>Regular</strong>, you'll be able to connect your own GoHighLevel sub-account and folder here.
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
    return res.redirect('/account?ghl_err=' + encodeURIComponent('Your account needs to be set to Regular to customize storage. Ask the workspace admin.'));
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

// Group card — teal accent header, 2-column grid of orange/teal alternating
// tiles inside. Each tile has its own compact copy button and a ⋯ menu.
function renderGroupCard(g, children, publicOrigin) {
  const tiles = children.map((m, i) => {
    // Checkerboard pattern: alternate by (col + row), not just by i.
    // i % 2 alone paints whole columns one color; we want adjacent
    // tiles in the same row OR same column to differ, like a chessboard.
    const col = i % 2;
    const row = Math.floor(i / 2);
    const isOrange = (col + row) % 2 === 0;
    const themeClass = isOrange ? 'tile-orange' : 'tile-teal';
    const bodyJson = JSON.stringify(m.body);
    const preview = (m.body || '').toString().split('\n').find(s => s.trim()) || '';
    const ellided = preview.length > 60 ? preview.slice(0, 60).trimEnd() + '…' : preview;
    return `
      <div class="msg-tile ${themeClass}" data-slug="${escHtml(m.slug)}">
        <button type="button" class="tile-drag-handle" aria-label="Drag to reorder" title="Drag to reorder">≡</button>
        <button type="button" class="tile-overflow" aria-label="More" data-slug="${escHtml(m.slug)}">⋯</button>
        <div class="tile-title">${escHtml(m.title || '(untitled)')}</div>
        <div class="tile-preview">${escHtml(ellided)}</div>
        <button type="button" class="tile-copy" data-body='${escHtml(bodyJson)}'>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:middle; margin-right:4px;"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy
        </button>
      </div>
    `;
  }).join('');

  return `
    <div class="grp-card" data-slug="${escHtml(g.slug)}">
      <div class="grp-head">
        <div class="grp-head-text">
          <span class="grp-pill">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
            Group
          </span>
          <h3 class="grp-title">${escHtml(g.title || '(untitled group)')}</h3>
          <span class="grp-meta">${children.length} message${children.length === 1 ? '' : 's'}</span>
        </div>
        <div class="msg-reorder" role="group" aria-label="Reorder group">
          <button type="button" class="msg-reorder-btn grp-up-btn"   aria-label="Move up"   title="Move group up">↑</button>
          <button type="button" class="msg-reorder-btn grp-down-btn" aria-label="Move down" title="Move group down">↓</button>
        </div>
      </div>
      <div class="grp-grid">
        ${tiles || '<div class="grp-empty">No messages in this group yet — use ＋ Add below.</div>'}
        <a href="/messages/new?group=${escHtml(g.slug)}" class="grp-add">＋ Add message to this group</a>
      </div>
      <div class="grp-foot">
        <a href="/groups/${escHtml(g.slug)}/edit" class="btn btn-secondary btn-sm">Rename group</a>
        <button type="button" class="btn btn-danger btn-sm grp-delete-btn">Delete group</button>
      </div>
    </div>
  `;
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
        <button type="button" class="btn btn-secondary btn-sm move-to-group-btn" style="position: relative;">Move to group</button>
        <button type="button" class="btn btn-secondary btn-sm copy-link-btn" data-url="${escHtml(url)}">Copy link</button>
        <button type="button" class="btn btn-danger btn-sm msg-delete-btn">Delete</button>
      </div>
    </div>
  `;
}

app.get('/messages', requireUser, (req, res) => {
  const q = (req.query.q || '').toString().trim().slice(0, 100);

  // Unified feed: groups + standalone messages, merged by sort_order DESC.
  // Search filter applies to standalone messages only for now (group
  // titles + their children matched separately if we extend later).
  const standalone = mdb.listRecentByUser(req.user.id, { limit: 200, q });
  const groupRows = q
    ? [] // hide groups on search for now — clearer UX, easier to reason about
    : gdb.listForUser(req.user.id, { limit: 200 });

  // Build a unified array sorted by sort_order DESC. Each row is
  // either { kind: 'group', ... } or { kind: 'message', ... }.
  const feed = [
    ...groupRows.map(g => ({ kind: 'group', sort_order: g.sort_order, group: g })),
    ...standalone.map(m => ({ kind: 'message', sort_order: m.sort_order, msg: m })),
  ].sort((a, b) => b.sort_order - a.sort_order);

  // Pre-fetch each group's messages
  const groupChildren = new Map();
  for (const g of groupRows) {
    groupChildren.set(g.id, mdb.listInGroup(g.id, req.user.id));
  }

  const justSavedSlug = req.query.saved ? req.query.saved.toString().slice(0, 32) : '';
  const justGrouped = req.query.group_saved ? 'A new group is saved.' : '';

  res.send(layout({
    title: 'Messages — ' + SITE_NAME,
    user: req.user,
    body: `
      <style>${MESSAGES_CSS}</style>
      <div class="msg-page-head">
        <h1>Messages</h1>
        <div class="msg-page-actions">
          <a href="/groups/new" class="btn btn-secondary btn-sm">+ New group</a>
          <a href="/messages/new" class="btn">+ New message</a>
        </div>
      </div>
      <p class="muted">Save your DMs once. Tap copy, paste anywhere — Instagram, WhatsApp, Facebook, anything.</p>

      ${(justSavedSlug || justGrouped) ? `
        <div class="card" id="saved-banner" style="border-left: 4px solid var(--ok); background:#f0fdf4;">
          <strong style="color:#166534;">${justGrouped || 'Saved.'}</strong>
          <span class="muted" style="font-size:14px;">${justGrouped ? '' : "It's at the top of your list."}</span>
        </div>
        <script>
          try {
            const u = new URL(location.href);
            u.searchParams.delete('saved');
            u.searchParams.delete('group_saved');
            history.replaceState(null, '', u.pathname + (u.search || ''));
          } catch (e) {}
        </script>
      ` : ''}

      <form method="GET" action="/messages" class="msg-search">
        <input type="text" name="q" value="${escHtml(q)}" placeholder="Search title or body…" autocomplete="off">
        ${q ? `<a href="/messages" class="btn btn-secondary btn-sm">Clear</a>` : ''}
      </form>

      <div id="msg-list">
        ${feed.length === 0
          ? `<div class="recent-empty">${q
              ? 'No messages match that search.'
              : 'No saved messages yet. Click <a href="/messages/new">+ New message</a> or <a href="/groups/new">+ New group</a> to start.'}</div>`
          : feed.map(item => item.kind === 'group'
              ? renderGroupCard(item.group, groupChildren.get(item.group.id) || [], PUBLIC_ORIGIN)
              : renderMessageCard(item.msg, PUBLIC_ORIGIN)
            ).join('')}
      </div>

      <script>
        // Expose the user's groups (slug + title) so the per-card
        // "Move to group" picker can render without an extra fetch.
        window.__USER_GROUPS = ${JSON.stringify(
          (groupRows || []).map(g => ({ slug: g.slug, title: g.title }))
        )};
      </script>
      <script src="/vendor/sortable.min.js" defer></script>
      <script defer>
        // Wait for SortableJS to be available, then bind to every
        // group grid on the page.
        function initTileDragAndDrop() {
          if (typeof Sortable === 'undefined') {
            // Library hasn't finished loading yet — try again very soon
            return setTimeout(initTileDragAndDrop, 50);
          }
          document.querySelectorAll('.grp-grid').forEach(function (grid) {
            if (grid.__sortableBound) return;
            grid.__sortableBound = true;
            Sortable.create(grid, {
              animation: 160,
              handle: '.tile-drag-handle',
              draggable: '.msg-tile',
              filter: '.grp-add, .grp-empty',
              ghostClass: 'sortable-ghost',
              chosenClass: 'sortable-chosen',
              // delay+touchStartThreshold tuned for finger drag on iOS
              delay: 0,
              touchStartThreshold: 5,
              onEnd: async function (evt) {
                if (evt.oldIndex === evt.newIndex) return;
                var card = grid.closest('.grp-card');
                if (!card) return;
                var groupSlug = card.dataset.slug;
                var slugs = Array.prototype.map.call(
                  grid.querySelectorAll('.msg-tile'),
                  function (t) { return t.dataset.slug; }
                ).filter(function (s) { return !!s; });
                try {
                  var res = await fetch(
                    '/api/groups/' + encodeURIComponent(groupSlug) + '/reorder-tiles',
                    {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ slugs: slugs }),
                      credentials: 'same-origin',
                    }
                  );
                  if (!res.ok) throw new Error('Save failed');
                } catch (err) {
                  alert('Could not save the new order — please reload and try again.');
                  console.error('[reorder-tiles]', err);
                }
              },
            });
          });
        }
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initTileDragAndDrop);
        } else {
          initTileDragAndDrop();
        }
      </script>
      <script>${MSG_LIST_JS}</script>
    `,
  }));
});

app.get('/messages/new', requireUser, (req, res) => {
  // Allow ?group=<slug> to pre-select a target group from the URL
  // (used by the "+ Add message to this group" link inside group cards).
  const preselectSlug = (req.query.group || '').toString().trim();
  const allGroups = gdb.listForUser(req.user.id, { limit: 200 });
  const groupOpts = allGroups.map(g =>
    `<option value="${escHtml(g.slug)}"${g.slug === preselectSlug ? ' selected' : ''}>${escHtml(g.title)}</option>`
  ).join('');

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
        ${allGroups.length > 0 ? `
          <div>
            <label for="group">Group (optional)</label>
            <select id="group" name="group" style="width:100%; padding:12px 14px; font-size:15px; border:1px solid var(--border); border-radius:10px; background:#fff;">
              <option value="">(none — standalone message)</option>
              ${groupOpts}
            </select>
            <p class="muted" style="font-size:12px; margin:6px 0 0;">Saving inside a group shows it as a tile in that group's matrix.</p>
          </div>
        ` : ''}
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
          const body = {
            title: fd.get('title'),
            body: fd.get('body'),
            groupSlug: fd.get('group') || null,
          };
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
  // Look up the user's groups + which one this message is in (if any),
  // so the dropdown can preselect.
  const allGroups = gdb.listForUser(req.user.id, { limit: 200 });
  const currentGroupSlug = (() => {
    if (!m.group_id) return '';
    const g = allGroups.find(x => x.id === m.group_id);
    return g ? g.slug : '';
  })();
  const groupOpts = allGroups.map(g =>
    `<option value="${escHtml(g.slug)}"${g.slug === currentGroupSlug ? ' selected' : ''}>${escHtml(g.title)}</option>`
  ).join('');

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
        ${allGroups.length > 0 ? `
          <div>
            <label for="group">Group</label>
            <select id="group" name="group" style="width:100%; padding:12px 14px; font-size:15px; border:1px solid var(--border); border-radius:10px; background:#fff;">
              <option value="">(none — standalone message)</option>
              ${groupOpts}
            </select>
            <p class="muted" style="font-size:12px; margin:6px 0 0;">Move this message into a group, or back out to standalone.</p>
          </div>
        ` : ''}
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
          const payload = { title: fd.get('title'), body: fd.get('body') };
          const newGroupSlug = (fd.get('group') || '').toString().trim();
          try {
            const res = await fetch('/api/messages/${escHtml(m.slug)}', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload), credentials: 'same-origin',
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Save failed');
            // Optionally re-bucket the message
            const currentGroupSlug = ${JSON.stringify(currentGroupSlug)};
            if (newGroupSlug !== currentGroupSlug) {
              await fetch('/api/messages/${escHtml(m.slug)}/move-to-group', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ groupSlug: newGroupSlug }),
                credentials: 'same-origin',
              });
            }
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
    const groupSlug = ((req.body && req.body.groupSlug) || '').toString().trim();
    if (!title) throw new Error('Title is required.');
    if (!body.trim()) throw new Error('Message body is required.');
    if (body.length > 200000) throw new Error('Message is too long (max 200,000 characters).');
    const slug = nanoid(8);
    mdb.insert({ slug, userId: req.user.id, title, body });
    // If a group was selected, place the new message into it.
    if (groupSlug) {
      const g = gdb.getBySlugForUser(groupSlug, req.user.id);
      if (g) mdb.moveToGroup(slug, req.user.id, g.id);
    }
    console.log(`[msg] user=${req.user.id} created slug=${slug} (${body.length} chars)${groupSlug ? ' group=' + groupSlug : ''}`);
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
  // Use the unified feed-move helper so a standalone message can swap
  // positions with an adjacent group (different table) — reordering
  // works seamlessly across the mixed feed.
  const result = feeddb.move({ kind: 'message', slug: req.params.slug, userId: req.user.id, direction: dir });
  if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
  res.json({ ok: true });
});

// Move a message into a group (or out via groupSlug = null/empty)
app.post('/api/messages/:slug/move-to-group', requireUser, express.json(), (req, res) => {
  const targetSlug = (req.body && req.body.groupSlug || '').toString().trim();
  let groupId = null;
  if (targetSlug) {
    const g = gdb.getBySlugForUser(targetSlug, req.user.id);
    if (!g) return res.status(404).json({ ok: false, error: 'group not found' });
    groupId = g.id;
  }
  const result = mdb.moveToGroup(req.params.slug, req.user.id, groupId);
  if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
  res.json({ ok: true });
});

// ---------- groups ----------

app.get('/groups/new', requireUser, (req, res) => {
  res.send(layout({
    title: 'New group — ' + SITE_NAME,
    user: req.user,
    body: `
      <style>${MESSAGES_CSS}</style>
      <h1>New group</h1>
      <p class="muted">Group related DMs together so you can copy from one place.</p>
      <form id="grpForm" class="card stack">
        <div>
          <label for="title">Group name</label>
          <input id="title" name="title" type="text" required autofocus maxlength="200" placeholder="e.g. BD workshop outreach">
        </div>
        <button type="submit" class="btn btn-block">Create group</button>
        <p class="err" id="formErr" style="display:none;"></p>
        <p class="muted" style="text-align:center; font-size:14px; margin:0;"><a href="/messages">← Back to messages</a></p>
      </form>
      <script>
        document.getElementById('grpForm').addEventListener('submit', async (ev) => {
          ev.preventDefault();
          const errEl = document.getElementById('formErr'); errEl.style.display = 'none';
          const fd = new FormData(ev.target);
          try {
            const res = await fetch('/api/groups', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ title: fd.get('title') }), credentials: 'same-origin',
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Save failed');
            location.href = '/messages?group_saved=1';
          } catch (e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
        });
      </script>
    `,
  }));
});

app.get('/groups/:slug/edit', requireUser, (req, res) => {
  const g = gdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!g) return res.status(404).send(layout({ title: 'Not found', user: req.user, body: '<h1>Not found</h1><p>This group does not exist or is not yours.</p>' }));
  res.send(layout({
    title: 'Rename group — ' + SITE_NAME,
    user: req.user,
    body: `
      <style>${MESSAGES_CSS}</style>
      <h1>Rename group</h1>
      <form id="grpForm" class="card stack">
        <div>
          <label for="title">Group name</label>
          <input id="title" name="title" type="text" required autofocus maxlength="200" value="${escHtml(g.title)}">
        </div>
        <button type="submit" class="btn btn-block">Save</button>
        <p class="err" id="formErr" style="display:none;"></p>
        <p class="muted" style="text-align:center; font-size:14px; margin:0;"><a href="/messages">← Back to messages</a></p>
      </form>
      <script>
        document.getElementById('grpForm').addEventListener('submit', async (ev) => {
          ev.preventDefault();
          const errEl = document.getElementById('formErr'); errEl.style.display = 'none';
          const fd = new FormData(ev.target);
          try {
            const res = await fetch('/api/groups/${escHtml(g.slug)}', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ title: fd.get('title') }), credentials: 'same-origin',
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Save failed');
            location.href = '/messages';
          } catch (e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
        });
      </script>
    `,
  }));
});

app.post('/api/groups', requireUser, express.json(), (req, res) => {
  try {
    const title = ((req.body && req.body.title) || '').toString().trim();
    if (!title) throw new Error('Group name is required.');
    const slug = nanoid(8);
    gdb.insert({ slug, userId: req.user.id, title });
    console.log(`[grp] user=${req.user.id} created slug=${slug}`);
    res.json({ ok: true, slug });
  } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/api/groups/:slug', requireUser, express.json(), (req, res) => {
  try {
    const g = gdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!g) return res.status(404).json({ ok: false, error: 'not found' });
    const title = ((req.body && req.body.title) || '').toString().trim();
    if (!title) throw new Error('Group name is required.');
    gdb.rename(g.id, req.user.id, title);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/api/groups/:slug/delete', requireUser, (req, res) => {
  const g = gdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!g) return res.status(404).json({ ok: false, error: 'not found' });
  gdb.deleteByIdForUser(g.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/groups/:slug/move', requireUser, express.json(), (req, res) => {
  const dir = (req.body && req.body.direction) === 'down' ? 'down' : 'up';
  const result = feeddb.move({ kind: 'group', slug: req.params.slug, userId: req.user.id, direction: dir });
  if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
  res.json({ ok: true });
});

// Reorder the message tiles inside one group. Body: { slugs: ["a","b",...] }
// in the desired top-to-bottom order. Rewrites group_position so the
// next page load preserves the new order. Tiles are scoped to the
// caller (req.user.id) and the named group; foreign slugs are ignored.
app.post('/api/groups/:slug/reorder-tiles', requireUser, express.json({ limit: '200kb' }), (req, res) => {
  const g = gdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!g) return res.status(404).json({ ok: false, error: 'group not found' });
  const slugs = Array.isArray(req.body && req.body.slugs) ? req.body.slugs : null;
  if (!slugs) return res.status(400).json({ ok: false, error: 'slugs array required' });
  // Defensive cap so a malformed client can't blow up the DB
  if (slugs.length > 500) return res.status(400).json({ ok: false, error: 'too many slugs' });
  const safe = slugs.map(s => (s == null ? '' : String(s))).filter(s => s.length > 0 && s.length <= 64);
  const result = mdb.reorderTilesInGroup({ groupId: g.id, userId: req.user.id, slugs: safe });
  res.json({ ok: true, updated: result.updated });
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

  .msg-page-actions { display: flex; gap: 8px; align-items: center; }

  /* ---------- Group card (matrix layout) ---------- */
  .grp-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 3px solid #0d9488;
    border-radius: 12px;
    padding: 12px;
    margin-bottom: 12px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04);
  }
  .grp-head { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px; }
  .grp-head-text { flex: 1 1 auto; min-width: 0; }
  .grp-pill {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 2px 8px; border-radius: 99px;
    background: #0d9488; color: #fff;
    font-size: 10.5px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;
    margin-bottom: 4px;
  }
  .grp-title { margin: 0 0 1px; font-size: 15px; font-weight: 700; color: var(--fg); line-height: 1.25; word-break: break-word; }
  .grp-meta { font-size: 11px; color: var(--muted); }

  .grp-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
  }
  .msg-tile {
    position: relative;
    border-radius: 10px;
    padding: 9px 10px;
    border: 1px solid transparent;
  }
  .msg-tile.tile-orange { background: #fff7ed; border-color: #fed7aa; }
  .msg-tile.tile-teal   { background: #f0fdfa; border-color: #99f6e4; }
  .tile-overflow {
    position: absolute; top: 4px; right: 4px;
    width: 22px; height: 22px; padding: 0;
    background: transparent; border: 0; cursor: pointer;
    color: #475569; font-size: 16px; line-height: 1;
    border-radius: 6px;
  }
  .tile-overflow:hover { background: rgba(0,0,0,0.05); }
  /* Drag handle in the top-LEFT corner. Mirrors .tile-overflow but
     uses the ≡ glyph and a grab cursor. touch-action: none lets
     SortableJS take over the touch sequence on mobile without the
     browser stealing it for scrolling. */
  .tile-drag-handle {
    position: absolute; top: 4px; left: 4px;
    width: 22px; height: 22px; padding: 0;
    background: transparent; border: 0;
    color: #475569; font-size: 16px; line-height: 1;
    border-radius: 6px;
    cursor: grab;
    touch-action: none;
    -webkit-user-select: none; user-select: none;
    display: inline-flex; align-items: center; justify-content: center;
  }
  .tile-drag-handle:hover { background: rgba(0,0,0,0.05); color: #0f172a; }
  .tile-drag-handle:active { cursor: grabbing; }
  /* While a tile is being dragged */
  .msg-tile.sortable-chosen { box-shadow: 0 6px 18px rgba(15,23,42,0.18); }
  .msg-tile.sortable-ghost  { opacity: 0.35; }
  .tile-title {
    font-size: 12.5px; font-weight: 600; color: var(--fg);
    line-height: 1.25; margin-bottom: 4px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    padding-left: 22px;
    padding-right: 22px;
  }
  .tile-preview {
    font-size: 11px; color: var(--muted); line-height: 1.3;
    margin-bottom: 8px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .tile-copy {
    width: 100%; min-height: 38px;
    padding: 8px; border: 0; border-radius: 8px;
    color: #fff; font-size: 13px; font-weight: 600; cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center;
    -webkit-tap-highlight-color: rgba(255,255,255,0.2);
    transition: transform .08s, filter .15s;
  }
  .msg-tile.tile-orange .tile-copy { background: #f97316; }
  .msg-tile.tile-teal   .tile-copy { background: #0d9488; }
  .tile-copy:hover { filter: brightness(1.05); }
  .tile-copy:active { transform: scale(0.97); }
  .tile-copy.is-copied { background: #16a34a !important; }

  .grp-add {
    grid-column: span 2;
    display: flex; align-items: center; justify-content: center;
    min-height: 36px; padding: 8px;
    background: transparent;
    border: 1px dashed #0d9488; color: #0d9488;
    border-radius: 10px; font-size: 12.5px; font-weight: 600;
    text-decoration: none; cursor: pointer;
  }
  .grp-add:hover { background: #f0fdfa; }
  .grp-empty {
    grid-column: span 2; padding: 16px; text-align: center;
    font-size: 13px; color: var(--muted);
  }

  .grp-foot { display: flex; gap: 6px; margin-top: 10px; }
  .grp-foot .btn-sm { flex: 1; }

  /* In-tile overflow menu (popover) */
  .tile-menu { position: absolute; top: 28px; right: 4px; z-index: 10;
    background: #fff; border: 1px solid var(--border); border-radius: 8px;
    box-shadow: 0 4px 14px -4px rgba(0,0,0,0.18); padding: 4px; min-width: 150px;
  }
  .tile-menu button, .tile-menu a {
    display: block; width: 100%; text-align: left;
    background: transparent; border: 0; padding: 8px 10px; border-radius: 6px;
    font-size: 13px; color: var(--fg); cursor: pointer; text-decoration: none;
  }
  .tile-menu button:hover, .tile-menu a:hover { background: #f3f4f6; }
  .tile-menu .danger { color: var(--err); }

  .msg-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 14px 12px; margin-bottom: 12px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .msg-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; margin-bottom: 6px; flex-wrap: nowrap; }
  .msg-card-head-text { flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
  .msg-card-title { margin: 0; font-size: 16px; font-weight: 700; color: var(--fg); letter-spacing: -0.01em; word-break: break-word; line-height: 1.3; }
  .msg-card-date { font-size: 11.5px; color: var(--muted); white-space: nowrap; }

  /* Reorder buttons — laid out side-by-side and modestly sized so the
     card head stays a single line of vertical space. Still 32px tall
     so they're comfortably tappable on mobile (44pt touch target met
     when including the surrounding padding). */
  .msg-reorder { display: flex; flex-direction: row; gap: 4px; flex: 0 0 auto; align-self: flex-start; }
  .msg-reorder-btn {
    width: 32px; height: 32px; padding: 0;
    display: inline-flex; align-items: center; justify-content: center;
    background: #fff; border: 1px solid var(--border); border-radius: 8px;
    font: 600 15px/1 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #475569; cursor: pointer;
    transition: background-color .12s, border-color .12s, transform .08s;
  }
  .msg-reorder-btn:hover { background: #f3f4f6; border-color: #cbd5e1; color: #0f172a; }
  .msg-reorder-btn:active { transform: scale(0.92); }
  .msg-reorder-btn:disabled { opacity: 0.35; cursor: not-allowed; transform: none; }
  .msg-card.is-moving { background-color: #f0fdf4; transition: background-color .35s; }
  .msg-card-preview {
    margin: 0 0 10px;
    padding: 8px 11px;
    background: #f8fafc;
    border: 1px solid var(--border);
    border-radius: 8px;
    font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #334155;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 72px;          /* ~ 3 lines */
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
    padding: 12px 20px;
    border: 0; border-radius: 12px; cursor: pointer;
    font: inherit; font-size: 16px; font-weight: 700; color: #fff;
    background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%);
    box-shadow: 0 1px 2px rgba(29,78,216,0.22), 0 8px 22px -8px rgba(29,78,216,0.55);
    transition: transform .08s, filter .15s, box-shadow .15s;
    margin-bottom: 10px;
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

    // Close any open tile/move menus when clicking elsewhere
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.tile-menu') && !e.target.closest('.tile-overflow') &&
          !e.target.closest('.move-menu') && !e.target.closest('.move-to-group-btn')) {
        document.querySelectorAll('.tile-menu, .move-menu').forEach(m => m.remove());
      }
    });

    list.addEventListener('click', async (e) => {
      const btn = e.target.closest('button, a');
      if (!btn) return;

      // ---------- TILE actions ----------
      const tile = btn.closest('.msg-tile');
      if (tile) {
        // Tile copy
        if (btn.classList.contains('tile-copy')) {
          try {
            const body = JSON.parse(btn.dataset.body);
            await navigator.clipboard.writeText(body);
            btn.classList.add('is-copied');
            const orig = btn.innerHTML;
            btn.textContent = '✓ Copied';
            setTimeout(() => { btn.classList.remove('is-copied'); btn.innerHTML = orig; }, 1500);
            if (navigator.vibrate) { try { navigator.vibrate(12); } catch {} }
          } catch (err) { alert('Copy failed.'); }
          return;
        }
        // Tile overflow → popover with Open / Edit / Remove from group / Delete
        if (btn.classList.contains('tile-overflow')) {
          document.querySelectorAll('.tile-menu').forEach(m => m.remove());
          const slug = btn.dataset.slug;
          const menu = document.createElement('div');
          menu.className = 'tile-menu';
          menu.innerHTML =
            '<a href="/m/' + slug + '" target="_blank" rel="noopener">Open</a>' +
            '<a href="/messages/' + slug + '/edit">Edit</a>' +
            '<button type="button" class="tile-remove-from-group" data-slug="' + slug + '">Remove from group</button>' +
            '<button type="button" class="danger tile-delete" data-slug="' + slug + '">Delete</button>';
          tile.appendChild(menu);
          return;
        }
        // Remove tile from group → standalone
        if (btn.classList.contains('tile-remove-from-group')) {
          const slug = btn.dataset.slug;
          try {
            const res = await fetch('/api/messages/' + slug + '/move-to-group', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ groupSlug: '' }), credentials: 'same-origin',
            });
            if (!res.ok) throw 0;
            location.reload();
          } catch { alert('Move failed.'); }
          return;
        }
        // Delete tile
        if (btn.classList.contains('tile-delete')) {
          const slug = btn.dataset.slug;
          const tileTitle = (tile.querySelector('.tile-title')?.textContent || 'this message').trim();
          window.__confirmDelete({
            title: 'Delete this message?',
            message: 'You\\'re about to delete "' + tileTitle + '". This action is permanent — the message and its share link will be gone forever.',
            then: async () => {
              try {
                const res = await fetch('/api/messages/' + slug + '/delete', { method: 'POST', credentials: 'same-origin' });
                if (!res.ok) throw 0;
                tile.remove();
              } catch { alert('Delete failed.'); }
            }
          });
          return;
        }
      }

      // ---------- GROUP-card actions (reorder + delete group) ----------
      const grpCard = btn.closest('.grp-card');
      if (grpCard) {
        if (btn.classList.contains('grp-up-btn') || btn.classList.contains('grp-down-btn')) {
          const dir = btn.classList.contains('grp-up-btn') ? 'up' : 'down';
          const sibling = dir === 'up' ? grpCard.previousElementSibling : grpCard.nextElementSibling;
          if (sibling && (sibling.classList.contains('grp-card') || sibling.classList.contains('msg-card'))) {
            if (dir === 'up') grpCard.parentNode.insertBefore(grpCard, sibling);
            else              grpCard.parentNode.insertBefore(sibling, grpCard);
          }
          try {
            const res = await fetch('/api/groups/' + grpCard.dataset.slug + '/move', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ direction: dir }), credentials: 'same-origin',
            });
            if (!res.ok) {
              if (sibling) {
                if (dir === 'up') grpCard.parentNode.insertBefore(sibling, grpCard);
                else              grpCard.parentNode.insertBefore(grpCard, sibling);
              }
            }
          } catch {}
          return;
        }
        if (btn.classList.contains('grp-delete-btn')) {
          const title = grpCard.querySelector('.grp-title').textContent.trim();
          window.__confirmDelete({
            title: 'Delete this group?',
            message: 'You\\'re about to delete the group "' + title + '". The group itself is permanently removed; the messages inside will become standalone (not deleted).',
            okText: 'Delete group',
            then: async () => {
              try {
                const res = await fetch('/api/groups/' + grpCard.dataset.slug + '/delete', { method: 'POST', credentials: 'same-origin' });
                if (!res.ok) throw 0;
                location.reload();
              } catch { alert('Delete failed.'); }
            }
          });
          return;
        }
      }

      // ---------- standalone-message-CARD actions (existing behavior) ----------
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

      // Move to group → popover with the user's groups
      if (btn.classList.contains('move-to-group-btn')) {
        document.querySelectorAll('.tile-menu, .move-menu').forEach(m => m.remove());
        const groups = (window.__USER_GROUPS || []);
        const menu = document.createElement('div');
        menu.className = 'tile-menu move-menu';
        if (groups.length === 0) {
          menu.innerHTML = '<div style="padding:10px 12px; font-size:13px; color:var(--muted);">No groups yet.</div>' +
                           '<a href="/groups/new">+ Create a new group</a>';
        } else {
          menu.innerHTML = groups.map(g =>
            '<button type="button" class="move-pick" data-group-slug="' + g.slug.replace(/"/g,'&quot;') + '">' + g.title.replace(/</g,'&lt;') + '</button>'
          ).join('') + '<a href="/groups/new">+ New group…</a>';
        }
        btn.style.position = 'relative';
        btn.appendChild(menu);
        return;
      }
      // Picked a group from the move popover
      if (btn.classList.contains('move-pick')) {
        const groupSlug = btn.dataset.groupSlug;
        const cardEl = btn.closest('.msg-card');
        if (!cardEl) return;
        try {
          const res = await fetch('/api/messages/' + cardEl.dataset.slug + '/move-to-group', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ groupSlug }), credentials: 'same-origin',
          });
          if (!res.ok) throw 0;
          location.reload();
        } catch { alert('Move failed.'); }
        return;
      }

      // Delete
      if (btn.classList.contains('msg-delete-btn')) {
        const title = card.querySelector('.msg-card-title').textContent.trim();
        window.__confirmDelete({
          title: 'Delete this message?',
          message: 'You\\'re about to delete "' + title + '". This is permanent — the message and its share link will be gone forever.',
          then: async () => {
            btn.disabled = true; btn.textContent = 'Deleting…';
            try {
              const res = await fetch('/api/messages/' + card.dataset.slug + '/delete', {
                method: 'POST', credentials: 'same-origin',
              });
              if (!res.ok) throw 0;
              card.remove();
            } catch { btn.disabled = false; btn.textContent = 'Delete'; alert('Delete failed.'); }
          }
        });
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
          ${rejected} upload${rejected === 1 ? ' was' : 's were'} not activated because a Starter account holds one file of each kind. Ask the workspace admin to set your account to Regular.
        </p>
      </div>
    `;
  } else if (claimed === 0 && rejected > 0) {
    claimedBanner = `
      <div class="card" style="border-left:4px solid var(--err); background:#fef2f2;">
        <h2 style="margin:0 0 4px; color:#991b1b; font-size:18px;">Upload not activated — Starter account is full.</h2>
        <p class="muted" style="margin:0; font-size:14px;">
          A Starter account holds one file of each kind, and that slot is already used. Ask the workspace admin to set your account to Regular.
        </p>
      </div>
    `;
  }

  const firstPage = fdb.listRecentByUser(req.user.id, { limit: RECENT_PAGE_SIZE });
  const nextCursor = firstPage.length === RECENT_PAGE_SIZE
    ? firstPage[firstPage.length - 1].sort_order : null;

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
    <div id="recent-list" class="reorder-list">${firstPage.map(renderRecentCard).join('')}</div>
    <div id="recent-sentinel"
         data-cursor="${nextCursor != null ? nextCursor : ''}"
         class="muted"
         style="text-align: center; padding: 16px;${nextCursor == null ? 'display:none;' : ''}">
      Loading more…
    </div>
    <script src="/vendor/sortable.min.js" defer></script>
    <script>${REORDER_JS}</script>
    <script>${RECENT_LIST_JS}</script>
  `;

  const caps = { Images: fmtBytes(SIZE_CAPS.image), Audio: fmtBytes(SIZE_CAPS.audio), Video: fmtBytes(SIZE_CAPS.video), PDFs: fmtBytes(SIZE_CAPS.pdf), Text: fmtBytes(SIZE_CAPS.text) };
  const capsHint = Object.entries(caps).map(([k, v]) => `${k} up to ${v}`).join(' · ');

  const trialBanner = isTrial ? `
    <div class="card" style="border-left: 4px solid #f59e0b;">
      <strong>Starter account</strong> — one file of each kind. The workspace admin can set your account to Regular for more.
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
        <div>
          <label for="notes">Notes (optional)</label>
          <textarea id="notes" name="notes" class="notes-input" rows="4"
                    maxlength="${NOTES_MAX_CHARS}"
                    placeholder="Paste a prompt, a caption, the steps you talked through…"></textarea>
          <p class="muted" style="font-size: 12px; margin: 6px 0 0;">
            Shown under the file on the share page, with a Copy button — so whoever you send the link to can lift the text.
          </p>
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
            errMsg.textContent = 'A Starter account holds one ' + c.kind + ' file. Ask the workspace admin to set your account to Regular.';
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
          // Notes ARE cleared: they describe one specific file, and a stale
          // prompt silently riding onto the next upload is the worse bug.
          fileInput.value = '';
          const notesEl = document.getElementById('notes');
          if (notesEl) notesEl.value = '';
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
    // Drag-to-reorder. Sortable is bound to the container, not the cards,
    // so it survives every innerHTML swap below — only the arrow-button
    // enabled state has to be re-synced after a re-render.
    const reorder = window.__initReorder({
      container: list,
      itemSelector: '.recent-item',
      endpoint: '/api/recent/reorder',
    });
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
        reorder.refresh();
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
        if (data.html) { list.insertAdjacentHTML('beforeend', data.html); reorder.refresh(); }
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
      if (btn.classList.contains('notes-btn')) {
        const item = btn.closest('.recent-item');
        window.__editNotes({
          title: 'Notes for this file',
          value: item.dataset.notes || '',
          then: async (text) => {
            const res = await fetch('/api/notes/' + btn.dataset.slug, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ notes: text }),
              credentials: 'same-origin',
            });
            if (!res.ok) { alert('Could not save the notes.'); return; }
            const data = await res.json();
            item.dataset.notes = data.notes;
            btn.textContent = data.notes ? 'Edit notes' : 'Add notes';
            const badge = item.querySelector('.notes-state');
            if (badge) badge.style.display = data.notes ? '' : 'none';
          },
        });
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
        window.__confirmDelete({
          title: 'Delete this file?',
          message: 'You\\'re about to delete "' + title + '". The share link will stop working and the file is removed from storage. This is permanent and cannot be reversed.',
          then: async () => {
            btn.disabled = true; btn.textContent = 'Deleting…';
            const res = await fetch('/api/delete/' + btn.dataset.slug, { method: 'POST', credentials: 'same-origin' });
            if (res.ok) { btn.closest('.recent-item').remove(); reorder.refresh(); }
            else { btn.disabled = false; btn.textContent = 'Delete'; alert('Delete failed.'); }
          }
        });
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
    const notes = (req.body.notes || '').toString().slice(0, NOTES_MAX_CHARS);
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
      user_id: req.user.id, notes,
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

    // Push "files are ready" to any iOS devices the user already registered.
    if (apns.configured && claimed > 0) {
      process.nextTick(async () => {
        try {
          const toks = dtdb.listByUser(u.id);
          if (!toks.length) return;
          await apns.fanOut(toks, {
            title: '✅ Files ready',
            body: claimed === 1 ? '1 file is now in your account' : `${claimed} files are now in your account`,
            data: { kind: 'magic_link_claimed', count: claimed },
          });
        } catch (e) {
          console.warn('[apns] magic-claimed push failed:', e.message);
        }
      });
    }

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

// In-memory "we've already pushed for this slug" set so the owner only
// gets one share_link_first_view notification per file per server-life.
// Survives misses on container restart by design — cheap and correct
// enough for a best-effort push.
const firstViewPushed = new Set();

function pushOnFirstView(rec, req) {
  if (!apns.configured) return;
  if (!rec || !rec.user_id) return;
  if (firstViewPushed.has(rec.slug)) return;
  // Skip if owner is viewing their own file (best-effort: compare via cookie)
  const viewerUid = parseInt(req.signedCookies.uid, 10);
  if (Number.isFinite(viewerUid) && viewerUid === rec.user_id) return;
  firstViewPushed.add(rec.slug);
  process.nextTick(async () => {
    try {
      const toks = dtdb.listByUser(rec.user_id);
      if (!toks.length) return;
      await apns.fanOut(toks, {
        title: '📥 Your file was opened',
        body: rec.title || rec.original_filename || 'a shared file',
        data: { slug: rec.slug, kind: 'file_first_view' },
      });
    } catch (e) {
      console.warn('[apns] first-view push failed:', e.message);
    }
  });
}

app.get('/raw/:slug', async (req, res) => {
  const rec = fdb.getBySlug(req.params.slug);
  if (!rec) return res.status(404).send('Not found');
  // Don't leak the bytes of a pending-activation file — the share link
  // isn't live yet. Treat it the same as not-found so we don't confirm
  // existence to someone guessing slugs.
  if (!rec.activated) return res.status(404).send('Not found');
  pushOnFirstView(rec, req);
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
          ${viewers.renderNotes(rec.notes)}
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
        ${viewers.renderNotes(rec.notes)}
      `;
  }

  res.send(layout({ title: ogTitle + ' — ' + SITE_NAME, user: req.user, body, ogTitle, ogDescription, ogImageUrl, noindex: true }));
});

// ============================================================================
// CHATS — an ordered run of screenshots shared as one scrolling page.
//
// The job: a long chat won't fit in one screenshot, so people take five or
// ten. Uploading them as five separate links is useless — the reader has to
// open each one and guess the order. A chat scroll stacks them edge-to-edge
// at /c/<slug> so scrolling the page IS scrolling the conversation.
//
// Ordering is decided in the browser BEFORE anything uploads (thumbnails are
// local blobs, so reordering is instant and costs no round-trips), and can be
// changed afterwards on the edit page. Both use the same drag-handle +
// serial-number list so the two screens feel like one thing.
// ============================================================================

const CHAT_MAX_ITEMS = 60;
const CHAT_TRIAL_MAX_ITEMS = 10;
const CHAT_TRIAL_MAX_CHATS = 1;

const CHAT_CSS = `
  /* ----- shared: the reorderable screenshot list (new + edit pages) ----- */
  .shot-list { list-style: none; margin: 0; padding: 0; }
  .shot-list li.shot {
    display: flex; align-items: center; gap: 10px;
    padding: 8px; margin-bottom: 8px;
    background: #fff; border: 1px solid var(--border); border-radius: 10px;
  }
  .shot-list li.shot.sortable-ghost { opacity: 0.35; }
  .shot-list li.shot.sortable-chosen { box-shadow: 0 6px 20px -6px rgba(0,0,0,0.25); }
  /* A full 40x44 target — the old 26x34 grip was hard to hit with a thumb. */
  .shot-handle {
    flex: 0 0 auto; cursor: grab; color: #94a3b8; font-size: 19px; line-height: 1;
    width: 40px; height: 44px; margin: -4px 0;
    display: inline-flex; align-items: center; justify-content: center;
    touch-action: none; user-select: none; -webkit-user-select: none;
  }
  .shot-handle:active { cursor: grabbing; }
  .shot-num {
    flex: 0 0 auto; min-width: 26px; height: 26px; border-radius: 99px;
    background: var(--brand); color: #fff; font-size: 13px; font-weight: 700;
    display: inline-flex; align-items: center; justify-content: center; padding: 0 7px;
  }
  .shot-thumb {
    flex: 0 0 auto; width: 46px; height: 46px; object-fit: cover;
    border-radius: 8px; background: #f1f5f9; border: 1px solid var(--border);
    cursor: zoom-in;
  }
  .shot-meta { flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
  .shot-name { font-size: 13px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .shot-sub { font-size: 11px; color: var(--muted); }
  .shot-actions { flex: 0 0 auto; display: flex; gap: 4px; }
  .shot-actions button {
    width: 32px; height: 32px; border-radius: 8px; border: 1px solid var(--border);
    background: #fff; cursor: pointer; font-size: 14px; line-height: 1; color: #475569;
  }
  .shot-actions button:hover { background: #f3f4f6; }
  .shot-actions button:disabled { opacity: 0.3; cursor: not-allowed; }
  .shot-actions .shot-del { color: var(--err); border-color: #fecaca; }
  .shot-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; margin: 4px 0 10px; }
  .shot-count { font-size: 14px; font-weight: 600; }
  .chat-progress { display: none; }
  .chat-progress.on { display: block; }
  .chat-progress-track { height: 8px; background: #e5e7eb; border-radius: 99px; overflow: hidden; }
  .chat-progress-fill { height: 100%; width: 0%; background: var(--brand); transition: width .2s ease; }
  .chat-progress-text { font-size: 13px; color: var(--muted); margin-top: 6px; }

  /* ----- the chat card on /chats -----
     The card itself is now a plain block so the drag grip bar can sit above
     the row; .chat-card-inner keeps the old strip + body flex layout. */
  .chat-card-inner { display: flex; gap: 12px; align-items: flex-start; }
  .chat-strip { flex: 0 0 auto; display: flex; gap: 3px; }
  .chat-strip img { width: 34px; height: 46px; object-fit: cover; object-position: top; border-radius: 5px; border: 1px solid var(--border); background: #f1f5f9; }
  .chat-card-body { flex: 1 1 auto; min-width: 0; }

  /* ----- the public viewer at /c/<slug> ----- */
  main.chat-main { max-width: 520px; padding: 0 0 48px; }
  .chat-head { padding: 16px 18px 12px; }
  .chat-head h1 { font-size: 20px; margin: 0 0 2px; }
  .chat-scroll { background: #fff; border-left: 1px solid var(--border); border-right: 1px solid var(--border); }
  /* display:block kills the inline-element baseline gap that would otherwise
     draw a hairline seam between consecutive screenshots. */
  .chat-shot { display: block; width: 100%; height: auto; cursor: zoom-in; background: #fff; }
  .chat-foot { padding: 18px; text-align: center; }
  .chat-bar { position: fixed; top: 0; left: 0; height: 3px; background: var(--brand); width: 0%; z-index: 50; transition: width .08s linear; }
  .chat-pos {
    position: fixed; right: 12px; bottom: 12px; z-index: 50;
    background: rgba(15,23,42,0.82); color: #fff; font-size: 12px; font-weight: 600;
    padding: 6px 11px; border-radius: 99px; opacity: 0; transition: opacity .25s;
    pointer-events: none; backdrop-filter: blur(4px);
  }
  .chat-pos.on { opacity: 1; }
  .lightbox { position: fixed; inset: 0; z-index: 9998; background: rgba(0,0,0,0.92); display: none; overflow: auto; -webkit-overflow-scrolling: touch; }
  .lightbox.on { display: block; }
  .lightbox img { display: block; width: 100%; height: auto; margin: 0 auto; }
  .lightbox-close {
    position: fixed; top: 10px; right: 10px; z-index: 9999;
    width: 40px; height: 40px; border-radius: 99px; border: 0;
    background: rgba(255,255,255,0.9); color: #0f172a; font-size: 20px; cursor: pointer;
  }
  .lightbox-dl {
    position: fixed; bottom: 14px; left: 50%; transform: translateX(-50%); z-index: 9999;
    background: rgba(255,255,255,0.92); color: #0f172a; text-decoration: none;
    padding: 10px 18px; border-radius: 99px; font-size: 14px; font-weight: 600;
  }
`;

// Shared client-side helpers for both chat editors. Kept as plain string
// concatenation (no template literals) because this whole block lives inside
// a server-side template literal.
const CHAT_SHARED_JS = `
  function chatFmtBytes(b) {
    if (!b) return '0 B';
    var u = ['B','KB','MB','GB']; var i = 0; var n = b;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
  }
  function chatEsc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
    });
  }
  // Screenshots of one conversation are captured in order, so capture time is
  // almost always the order the reader wants. Timestamps that are all
  // identical (some pickers zero them out) are useless, so fall back to a
  // natural filename sort — IMG_9 before IMG_10, not after.
  function chatSortCaptureOrder(files) {
    var stamps = files.map(function (f) { return f.lastModified || 0; });
    var allSame = stamps.every(function (s) { return s === stamps[0]; });
    return files.slice().sort(function (a, b) {
      if (!allSame) return (a.lastModified || 0) - (b.lastModified || 0);
      return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
    });
  }
  function chatBindDropzone(zone, input, onFiles) {
    ['dragenter','dragover'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); e.stopPropagation(); zone.classList.add('is-dragover'); });
    });
    ['dragleave','drop'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); e.stopPropagation(); zone.classList.remove('is-dragover'); });
    });
    zone.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) onFiles(e.dataTransfer.files);
    });
    input.addEventListener('change', function () {
      if (input.files && input.files.length) onFiles(input.files);
      // Reset so picking the same file twice in a row still fires 'change'.
      input.value = '';
    });
  }
  // Wait for the drag library, but give up after ~3s instead of polling
  // forever. Every reorder is also reachable through the ↑/↓ buttons, so
  // losing drag degrades the page rather than breaking it.
  function chatWhenSortable(fn, tries) {
    tries = tries || 0;
    if (typeof Sortable !== 'undefined') return fn();
    if (tries > 60) {
      console.warn('[chat] drag library unavailable — use the up/down buttons to reorder');
      return;
    }
    setTimeout(function () { chatWhenSortable(fn, tries + 1); }, 50);
  }
  function chatRenumber(listEl) {
    Array.prototype.forEach.call(listEl.querySelectorAll('.shot'), function (li, i) {
      var n = li.querySelector('.shot-num');
      if (n) n.textContent = i + 1;
      var up = li.querySelector('.shot-up');
      var down = li.querySelector('.shot-down');
      if (up) up.disabled = i === 0;
      if (down) down.disabled = i === listEl.querySelectorAll('.shot').length - 1;
    });
  }
`;

// ---- create page: pick → arrange locally → upload in the chosen order ----
const CHAT_NEW_JS = `
(function () {
  ${CHAT_SHARED_JS}

  var CAP = window.__CHAT_CAP || 60;
  var IMAGE_CAP = window.__IMAGE_CAP || 26214400;

  var picker    = document.getElementById('chat-file');
  var dropzone  = document.getElementById('chat-dropzone');
  var wrap      = document.getElementById('shot-wrap');
  var listEl    = document.getElementById('shot-list');
  var countEl   = document.getElementById('shot-count');
  var createBtn = document.getElementById('chat-create');
  var retryBtn  = document.getElementById('chat-retry');
  var errEl     = document.getElementById('chat-err');
  var progEl    = document.getElementById('chat-progress');
  var fillEl    = document.getElementById('chat-progress-fill');
  var textEl    = document.getElementById('chat-progress-text');
  var doneEl    = document.getElementById('chat-done');
  var titleEl   = document.getElementById('chat-title');
  var dlEl      = document.getElementById('chat-dl');

  var shots = [];      // { key, file, url, w, h, done, frac }
  var nextKey = 1;
  var chatSlug = null; // set once the draft exists, so a retry resumes it

  function showErr(msg) {
    errEl.textContent = msg || '';
    errEl.style.display = msg ? 'block' : 'none';
  }

  function measure(shot) {
    return new Promise(function (resolve) {
      var img = new Image();
      img.onload = function () { shot.w = img.naturalWidth; shot.h = img.naturalHeight; resolve(); };
      img.onerror = function () { resolve(); };
      img.src = shot.url;
    });
  }

  function addFiles(fileList) {
    var incoming = Array.prototype.slice.call(fileList || []);
    if (!incoming.length) return;

    var rejected = [];
    incoming = incoming.filter(function (f) {
      if (f.type && f.type.indexOf('image/') !== 0) { rejected.push(chatEsc(f.name) + ' is not an image'); return false; }
      if (f.size > IMAGE_CAP) { rejected.push(f.name + ' is ' + chatFmtBytes(f.size) + ' (max ' + chatFmtBytes(IMAGE_CAP) + ')'); return false; }
      return true;
    });
    incoming = chatSortCaptureOrder(incoming);

    var room = CAP - shots.length;
    if (incoming.length > room) {
      rejected.push('only ' + CAP + ' screenshots fit in one scroll, so the extras were left out');
      incoming = incoming.slice(0, Math.max(0, room));
    }

    var added = incoming.map(function (f) {
      var s = { key: nextKey++, file: f, url: URL.createObjectURL(f), w: 0, h: 0, done: false, frac: 0 };
      shots.push(s);
      return s;
    });

    showErr(rejected.join(' · '));
    render();
    Promise.all(added.map(measure));
  }

  function render() {
    listEl.innerHTML = shots.map(function (s, i) {
      return '<li class="shot" data-key="' + s.key + '">' +
        '<span class="shot-handle" title="Drag to reorder">&#10265;</span>' +
        '<span class="shot-num">' + (i + 1) + '</span>' +
        '<img class="shot-thumb" src="' + s.url + '" alt="">' +
        '<span class="shot-meta">' +
          '<span class="shot-name">' + chatEsc(s.file.name) + '</span>' +
          '<span class="shot-sub">' + chatFmtBytes(s.file.size) + '</span>' +
        '</span>' +
        '<span class="shot-actions">' +
          '<button type="button" class="shot-up" title="Move up">&#8593;</button>' +
          '<button type="button" class="shot-down" title="Move down">&#8595;</button>' +
          '<button type="button" class="shot-del" title="Remove">&#10005;</button>' +
        '</span>' +
      '</li>';
    }).join('');
    chatRenumber(listEl);
    countEl.textContent = shots.length + ' screenshot' + (shots.length === 1 ? '' : 's');
    wrap.style.display = shots.length ? 'block' : 'none';
    createBtn.disabled = shots.length === 0;
    createBtn.textContent = shots.length
      ? 'Create the scroll link (' + shots.length + ' screenshot' + (shots.length === 1 ? '' : 's') + ')'
      : 'Create the scroll link';
  }

  function indexOfKey(key) {
    for (var i = 0; i < shots.length; i++) if (shots[i].key === key) return i;
    return -1;
  }

  // After a drag, take the DOM's word for the order rather than re-rendering
  // — re-rendering mid-gesture would rip out the node Sortable is animating.
  function syncFromDom() {
    var order = Array.prototype.map.call(listEl.querySelectorAll('.shot'), function (li) {
      return parseInt(li.dataset.key, 10);
    });
    shots.sort(function (a, b) { return order.indexOf(a.key) - order.indexOf(b.key); });
    chatRenumber(listEl);
  }

  chatBindDropzone(dropzone, picker, addFiles);

  listEl.addEventListener('click', function (e) {
    var btn = e.target.closest('button');
    if (!btn) return;
    var li = btn.closest('.shot');
    if (!li) return;
    var i = indexOfKey(parseInt(li.dataset.key, 10));
    if (i < 0) return;
    if (btn.classList.contains('shot-up') && i > 0) {
      shots.splice(i - 1, 0, shots.splice(i, 1)[0]);
    } else if (btn.classList.contains('shot-down') && i < shots.length - 1) {
      shots.splice(i + 1, 0, shots.splice(i, 1)[0]);
    } else if (btn.classList.contains('shot-del')) {
      URL.revokeObjectURL(shots[i].url);
      shots.splice(i, 1);
    } else { return; }
    render();
  });

  document.getElementById('shot-reverse').addEventListener('click', function () {
    shots.reverse();
    render();
  });
  document.getElementById('shot-clear').addEventListener('click', function () {
    shots.forEach(function (s) { URL.revokeObjectURL(s.url); });
    shots = [];
    render();
    showErr('');
  });

  chatWhenSortable(function () {
    Sortable.create(listEl, {
      animation: 160,
      handle: '.shot-handle',
      draggable: '.shot',
      ghostClass: 'sortable-ghost',
      chosenClass: 'sortable-chosen',
      touchStartThreshold: 5,
      onEnd: syncFromDom,
    });
  });

  // ---- upload ----

  function paint() {
    var total = shots.length || 1;
    var sum = shots.reduce(function (acc, s) { return acc + (s.done ? 1 : (s.frac || 0)); }, 0);
    fillEl.style.width = Math.round((sum / total) * 100) + '%';
  }

  function uploadOne(slug, shot) {
    return new Promise(function (resolve, reject) {
      var fd = new FormData();
      fd.append('file', shot.file, shot.file.name);
      fd.append('width', String(shot.w || 0));
      fd.append('height', String(shot.h || 0));
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/chats/' + encodeURIComponent(slug) + '/items');
      xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable) { shot.frac = e.loaded / e.total; paint(); }
      });
      xhr.onload = function () {
        var data = null;
        try { data = JSON.parse(xhr.responseText); } catch (err) {}
        if (xhr.status >= 200 && xhr.status < 300 && data && data.ok) {
          shot.done = true; shot.frac = 1; paint(); resolve(data);
        } else {
          reject(new Error((data && data.error) || 'Upload failed on ' + shot.file.name));
        }
      };
      xhr.onerror = function () { reject(new Error('Lost connection while uploading ' + shot.file.name + '.')); };
      xhr.send(fd);
    });
  }

  function success(link, count) {
    document.getElementById('chat-form').style.display = 'none';
    doneEl.style.display = 'block';
    doneEl.innerHTML =
      '<div class="card">' +
        '<h2 style="margin:0 0 6px;">&#9989; Your chat scroll is live</h2>' +
        '<p class="muted" style="font-size:14px;">' + count + ' screenshot' + (count === 1 ? '' : 's') + ', in your order. Send this one link — they just scroll.</p>' +
        '<input type="text" readonly id="done-link" value="' + chatEsc(link) + '" style="width:100%; margin-bottom:10px;">' +
        '<div class="row">' +
          '<button type="button" class="btn" id="done-copy">Copy link</button>' +
          '<a class="btn btn-secondary" href="' + chatEsc(link) + '" target="_blank" rel="noopener">Open</a>' +
          '<a class="btn btn-secondary" href="/chats/' + encodeURIComponent(chatSlug) + '/edit">Edit order</a>' +
        '</div>' +
      '</div>' +
      '<a class="btn btn-secondary btn-block" href="/chats/new">Create another</a>';
    document.getElementById('done-copy').addEventListener('click', async function () {
      var btn = this;
      try {
        await navigator.clipboard.writeText(link);
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = 'Copy link'; }, 1500);
      } catch (err) {
        document.getElementById('done-link').select();
        btn.textContent = 'Press Cmd/Ctrl+C';
      }
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  async function run() {
    if (!shots.length) return;
    showErr('');
    retryBtn.style.display = 'none';
    createBtn.disabled = true;
    progEl.classList.add('on');
    paint();

    try {
      if (!chatSlug) {
        var res = await fetch('/api/chats', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            title: titleEl.value.trim(),
            notes: (document.getElementById('chat-notes') || { value: '' }).value,
            allow_download: !!dlEl.checked,
          }),
        });
        var d = await res.json();
        if (!res.ok || !d.ok) throw new Error(d.error || 'Could not start the upload.');
        chatSlug = d.slug;
      }

      // Strictly sequential: each screenshot's position is assigned server-side
      // in arrival order, so uploading in parallel would scramble the sequence
      // the user just spent time arranging.
      for (var i = 0; i < shots.length; i++) {
        if (shots[i].done) continue;
        textEl.textContent = 'Uploading screenshot ' + (i + 1) + ' of ' + shots.length + '…';
        await uploadOne(chatSlug, shots[i]);
      }

      textEl.textContent = 'Building your link…';
      var fin = await fetch('/api/chats/' + encodeURIComponent(chatSlug) + '/finalize', {
        method: 'POST', credentials: 'same-origin',
      });
      var fdata = await fin.json();
      if (!fin.ok || !fdata.ok) throw new Error(fdata.error || 'Could not publish the scroll.');
      success(fdata.shareLink, fdata.count);
    } catch (err) {
      progEl.classList.remove('on');
      showErr(err.message);
      createBtn.disabled = false;
      var pending = shots.filter(function (s) { return !s.done; }).length;
      if (chatSlug && pending && pending < shots.length) {
        retryBtn.textContent = 'Retry the ' + pending + ' that did not upload';
        retryBtn.style.display = 'block';
      }
    }
  }

  createBtn.addEventListener('click', run);
  retryBtn.addEventListener('click', run);

  // A half-finished draft is swept server-side after 24h, but warn anyway —
  // leaving mid-upload loses the screenshots that hadn't gone up yet.
  window.addEventListener('beforeunload', function (e) {
    var uploading = chatSlug && shots.some(function (s) { return !s.done; }) && progEl.classList.contains('on');
    if (uploading) { e.preventDefault(); e.returnValue = ''; }
  });

  render();
})();
`;

// ---- edit page: reorder / remove / append against a chat that already exists ----
const CHAT_EDIT_JS = `
(function () {
  ${CHAT_SHARED_JS}

  var SLUG = window.__CHAT_SLUG;
  var CAP = window.__CHAT_CAP || 60;
  var IMAGE_CAP = window.__IMAGE_CAP || 26214400;

  var listEl   = document.getElementById('shot-list');
  var countEl  = document.getElementById('shot-count');
  var picker   = document.getElementById('chat-file');
  var dropzone = document.getElementById('chat-dropzone');
  var errEl    = document.getElementById('chat-err');
  var progEl   = document.getElementById('chat-progress');
  var fillEl   = document.getElementById('chat-progress-fill');
  var textEl   = document.getElementById('chat-progress-text');

  function showErr(msg) {
    errEl.textContent = msg || '';
    errEl.style.display = msg ? 'block' : 'none';
  }
  function count() { return listEl.querySelectorAll('.shot').length; }
  function refreshCount() {
    var n = count();
    countEl.textContent = n + ' screenshot' + (n === 1 ? '' : 's');
    chatRenumber(listEl);
  }

  async function saveOrder() {
    var ids = Array.prototype.map.call(listEl.querySelectorAll('.shot'), function (li) {
      return parseInt(li.dataset.id, 10);
    });
    try {
      var res = await fetch('/api/chats/' + encodeURIComponent(SLUG) + '/reorder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ ids: ids }),
      });
      if (!res.ok) throw new Error('Save failed');
      showErr('');
    } catch (err) {
      showErr('Could not save the new order — reload and try again.');
    }
  }

  chatWhenSortable(function () {
    Sortable.create(listEl, {
      animation: 160,
      handle: '.shot-handle',
      draggable: '.shot',
      ghostClass: 'sortable-ghost',
      chosenClass: 'sortable-chosen',
      touchStartThreshold: 5,
      onEnd: function (evt) {
        if (evt.oldIndex === evt.newIndex) return;
        refreshCount();
        saveOrder();
      },
    });
  });

  listEl.addEventListener('click', function (e) {
    var btn = e.target.closest('button');
    if (!btn) return;
    var li = btn.closest('.shot');
    if (!li) return;

    if (btn.classList.contains('shot-up')) {
      var prev = li.previousElementSibling;
      if (!prev) return;
      listEl.insertBefore(li, prev);
      refreshCount(); saveOrder(); return;
    }
    if (btn.classList.contains('shot-down')) {
      var next = li.nextElementSibling;
      if (!next) return;
      listEl.insertBefore(next, li);
      refreshCount(); saveOrder(); return;
    }
    if (btn.classList.contains('shot-del')) {
      if (count() <= 1) { showErr('A chat scroll needs at least one screenshot. Delete the whole scroll instead.'); return; }
      window.__confirmDelete({
        title: 'Remove this screenshot?',
        message: 'It is removed from the scroll and from storage. This cannot be reversed.',
        then: async function () {
          var res = await fetch('/api/chats/' + encodeURIComponent(SLUG) + '/items/' + li.dataset.id + '/delete', {
            method: 'POST', credentials: 'same-origin',
          });
          if (res.ok) { li.remove(); refreshCount(); }
          else { showErr('Could not remove that screenshot.'); }
        },
      });
    }
  });

  document.getElementById('shot-reverse').addEventListener('click', function () {
    var items = Array.prototype.slice.call(listEl.querySelectorAll('.shot'));
    items.reverse().forEach(function (li) { listEl.appendChild(li); });
    refreshCount();
    saveOrder();
  });

  // ---- settings ----
  document.getElementById('chat-save').addEventListener('click', async function () {
    var btn = this;
    btn.disabled = true;
    try {
      var res = await fetch('/api/chats/' + encodeURIComponent(SLUG) + '/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          title: document.getElementById('chat-title').value.trim(),
          notes: document.getElementById('chat-notes').value,
          allow_download: !!document.getElementById('chat-dl').checked,
        }),
      });
      if (!res.ok) throw new Error('Save failed');
      var saved = document.getElementById('chat-saved');
      saved.style.display = 'block';
      setTimeout(function () { saved.style.display = 'none'; }, 2000);
    } catch (err) {
      showErr('Could not save. Try again.');
    } finally { btn.disabled = false; }
  });

  document.querySelectorAll('.chat-copy').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      try {
        await navigator.clipboard.writeText(btn.dataset.url);
        var prev = btn.textContent; btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = prev; }, 1500);
      } catch (err) { btn.textContent = 'Copy failed'; }
    });
  });

  document.getElementById('chat-delete').addEventListener('click', function () {
    window.__confirmDelete({
      title: 'Delete this chat scroll?',
      message: 'The link stops working and every screenshot in it is removed from storage. This is permanent and cannot be reversed.',
      then: async function () {
        var res = await fetch('/api/chats/' + encodeURIComponent(SLUG) + '/delete', {
          method: 'POST', credentials: 'same-origin',
        });
        if (res.ok) window.location.href = '/chats';
        else showErr('Delete failed.');
      },
    });
  });

  // ---- append more screenshots ----

  function measure(file) {
    return new Promise(function (resolve) {
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function () { URL.revokeObjectURL(url); resolve({ w: img.naturalWidth, h: img.naturalHeight }); };
      img.onerror = function () { URL.revokeObjectURL(url); resolve({ w: 0, h: 0 }); };
      img.src = url;
    });
  }

  function appendRow(data) {
    var li = document.createElement('li');
    li.className = 'shot';
    li.dataset.id = data.id;
    li.innerHTML =
      '<span class="shot-handle" title="Drag to reorder">&#10265;</span>' +
      '<span class="shot-num"></span>' +
      '<img class="shot-thumb" src="' + data.thumb + '" alt="">' +
      '<span class="shot-meta">' +
        '<span class="shot-name">' + chatEsc(data.name) + '</span>' +
        '<span class="shot-sub">' + chatFmtBytes(data.size) + '</span>' +
      '</span>' +
      '<span class="shot-actions">' +
        '<button type="button" class="shot-up" title="Move up">&#8593;</button>' +
        '<button type="button" class="shot-down" title="Move down">&#8595;</button>' +
        '<button type="button" class="shot-del" title="Remove">&#10005;</button>' +
      '</span>';
    listEl.appendChild(li);
  }

  async function addFiles(fileList) {
    var incoming = Array.prototype.slice.call(fileList || []);
    if (!incoming.length) return;

    var rejected = [];
    incoming = incoming.filter(function (f) {
      if (f.type && f.type.indexOf('image/') !== 0) { rejected.push(f.name + ' is not an image'); return false; }
      if (f.size > IMAGE_CAP) { rejected.push(f.name + ' is ' + chatFmtBytes(f.size) + ' (max ' + chatFmtBytes(IMAGE_CAP) + ')'); return false; }
      return true;
    });
    incoming = chatSortCaptureOrder(incoming);

    var room = CAP - count();
    if (incoming.length > room) {
      rejected.push('this scroll only has room for ' + Math.max(0, room) + ' more');
      incoming = incoming.slice(0, Math.max(0, room));
    }
    showErr(rejected.join(' · '));
    if (!incoming.length) return;

    progEl.classList.add('on');
    for (var i = 0; i < incoming.length; i++) {
      textEl.textContent = 'Adding screenshot ' + (i + 1) + ' of ' + incoming.length + '…';
      fillEl.style.width = Math.round((i / incoming.length) * 100) + '%';
      try {
        var dims = await measure(incoming[i]);
        var fd = new FormData();
        fd.append('file', incoming[i], incoming[i].name);
        fd.append('width', String(dims.w));
        fd.append('height', String(dims.h));
        var res = await fetch('/api/chats/' + encodeURIComponent(SLUG) + '/items', {
          method: 'POST', body: fd, credentials: 'same-origin',
        });
        var data = await res.json();
        if (!res.ok || !data.ok) throw new Error(data.error || 'Upload failed');
        appendRow(data);
        refreshCount();
      } catch (err) {
        showErr(err.message);
        break;
      }
    }
    fillEl.style.width = '100%';
    setTimeout(function () { progEl.classList.remove('on'); fillEl.style.width = '0%'; }, 600);
  }

  chatBindDropzone(dropzone, picker, addFiles);
  refreshCount();
})();
`;

// ---- public viewer: scroll progress, position pill, tap-to-zoom ----
const CHAT_VIEW_JS = `
(function () {
  var bar = document.getElementById('chat-bar');
  var pos = document.getElementById('chat-pos');
  var scroll = document.getElementById('chat-scroll');
  var shots = Array.prototype.slice.call(scroll.querySelectorAll('.chat-shot'));
  var total = shots.length;
  var hideTimer = null;

  function onScroll() {
    var h = document.documentElement.scrollHeight - window.innerHeight;
    var pct = h > 0 ? (window.scrollY / h) * 100 : 0;
    bar.style.width = Math.max(0, Math.min(100, pct)) + '%';

    // Which screenshot owns the middle of the viewport right now.
    var mid = window.scrollY + window.innerHeight / 2;
    var current = 1;
    for (var i = 0; i < shots.length; i++) {
      var top = shots[i].getBoundingClientRect().top + window.scrollY;
      if (top <= mid) current = i + 1; else break;
    }
    pos.textContent = current + ' / ' + total;
    pos.classList.add('on');
    clearTimeout(hideTimer);
    hideTimer = setTimeout(function () { pos.classList.remove('on'); }, 1200);
  }

  if (total > 1) {
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    onScroll();
  }

  // Tap any screenshot to blow it up full width — chat text is small, and
  // opening a new tab would cost the reader their place in the scroll.
  var box = document.getElementById('lightbox');
  var boxImg = document.getElementById('lightbox-img');
  var boxDl = document.getElementById('lightbox-dl');
  var closeBtn = document.getElementById('lightbox-close');
  var savedScroll = 0;

  function open(src) {
    savedScroll = window.scrollY;
    boxImg.src = src;
    if (boxDl) boxDl.href = src;
    box.classList.add('on');
    box.scrollTop = 0;
    document.body.style.overflow = 'hidden';
  }
  function close() {
    box.classList.remove('on');
    boxImg.src = '';
    document.body.style.overflow = '';
    window.scrollTo(0, savedScroll);
  }

  scroll.addEventListener('click', function (e) {
    var img = e.target.closest('.chat-shot');
    if (img) open(img.src);
  });
  closeBtn.addEventListener('click', close);
  box.addEventListener('click', function (e) {
    if (e.target === box || e.target === boxImg) close();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && box.classList.contains('on')) close();
  });
})();
`;

/** Trial users get one chat scroll; regular users get as many as they like. */
function chatGate(user) {
  if (!user) return { ok: false, reason: 'Not logged in.' };
  if (user.status === 'deactivated') return { ok: false, reason: 'Your account is deactivated. Contact the admin.' };
  if (user.status === 'trial' && cdb.countReadyByUser(user.id) >= CHAT_TRIAL_MAX_CHATS) {
    return {
      ok: false,
      reason: `A Starter account holds ${CHAT_TRIAL_MAX_CHATS} chat scroll. Ask the workspace admin to set your account to Regular for more.`,
    };
  }
  return { ok: true };
}

function chatItemCap(user) {
  return user && user.status === 'trial' ? CHAT_TRIAL_MAX_ITEMS : CHAT_MAX_ITEMS;
}

/** Best-effort GHL cleanup for a list of image urls owned by one user. */
function purgeChatImages(urls, userRow) {
  if (!urls || !urls.length) return;
  let cfg = null;
  try { cfg = users.effectiveGhlConfig(userRow); } catch { cfg = null; }
  for (const u of urls) {
    try { ghl.tryDeleteFromGhl(u, cfg); } catch {}
  }
}

// Drop chats whose upload was abandoned before finalize. Called opportunistically
// when someone opens the create page — no cron needed for something this cheap.
function sweepStaleChatDrafts() {
  try {
    const urls = cdb.deleteStaleDrafts();
    if (urls.length) {
      console.log(`[chat-sweep] removed ${urls.length} orphan image(s) from abandoned drafts`);
      for (const u of urls) { try { ghl.tryDeleteFromGhl(u); } catch {} }
    }
  } catch (e) { console.warn('[chat-sweep] failed:', e.message); }
}

// ---------- chats: list ----------

app.get('/chats', requireUser, (req, res) => {
  const rows = cdb.listByUser(req.user.id, { limit: 50 });
  const gate = chatGate(req.user);

  const cards = rows.map(c => {
    const items = cdb.items(c.id).slice(0, 4);
    const strip = items.map(i =>
      `<img src="/cr/${escHtml(c.slug)}/${i.id}" alt="" loading="lazy">`
    ).join('');
    const link = `${PUBLIC_ORIGIN}/c/${c.slug}`;
    return `
      <div class="card chat-card reorder-item" data-slug="${escHtml(c.slug)}">
        ${reorderBar('Drag to reorder')}
        <div class="chat-card-inner">
          <div class="chat-strip">${strip}</div>
          <div class="chat-card-body">
            <div style="font-weight:600; margin-bottom:2px;">💬 ${escHtml(c.title || 'Untitled chat')}</div>
            <div class="muted" style="font-size:13px; margin-bottom:8px;">
              ${c.item_count} screenshot${c.item_count === 1 ? '' : 's'}${c.download_allowed ? ' · downloads on' : ''}
              ${fmtGstTimestamp(c.created_at) ? ' · ' + escHtml(fmtGstTimestamp(c.created_at)) : ''}
            </div>
            <div class="row">
              <button type="button" class="btn btn-secondary chat-copy" data-url="${escHtml(link)}">Copy link</button>
              <a class="btn btn-secondary" href="/c/${escHtml(c.slug)}" target="_blank" rel="noopener">Open</a>
              <a class="btn btn-secondary" href="/chats/${escHtml(c.slug)}/edit">Edit</a>
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  res.send(layout({
    title: 'Chat scrolls — ' + SITE_NAME,
    user: req.user,
    body: `
      <h1>Chat scrolls</h1>
      <p class="muted">A long conversation takes several screenshots. Put them in order once and share a single link that reads top to bottom, exactly like scrolling the real chat.</p>
      ${gate.ok
        ? `<a class="btn btn-block" href="/chats/new">➕ New chat scroll</a>`
        : `<div class="card" style="border-left:4px solid #f59e0b;"><strong>Starter account is full</strong><p class="muted" style="margin:6px 0 0; font-size:14px;">${escHtml(gate.reason)}</p></div>`}
      ${rows.length
        ? `<div id="chat-list" class="reorder-list">${cards}</div>`
        : `<div class="recent-empty">No chat scrolls yet. Create one and the link will show up here.</div>`}
      <script src="/vendor/sortable.min.js" defer></script>
      <script>${REORDER_JS}</script>
      <script>
        window.__initReorder({
          container: '#chat-list',
          itemSelector: '.chat-card',
          endpoint: '/api/chats/reorder-list',
        });

        document.addEventListener('click', async function (e) {
          var btn = e.target.closest('.chat-copy');
          if (!btn) return;
          try {
            await navigator.clipboard.writeText(btn.dataset.url);
            var prev = btn.textContent; btn.textContent = 'Copied!';
            setTimeout(function () { btn.textContent = prev; }, 1500);
          } catch (err) { btn.textContent = 'Copy failed — long-press the link'; }
        });
      </script>
    `,
  }));
});

// ---------- chats: create page ----------

app.get('/chats/new', requireUser, (req, res) => {
  sweepStaleChatDrafts();

  const gate = chatGate(req.user);
  if (!gate.ok) {
    return res.send(layout({
      title: 'Chat scrolls — ' + SITE_NAME,
      user: req.user,
      body: `<h1>Starter account is full</h1><p>${escHtml(gate.reason)}</p><a class="btn btn-block" href="/chats">Back to chat scrolls</a>`,
    }));
  }

  const cap = chatItemCap(req.user);

  res.send(layout({
    title: 'New chat scroll — ' + SITE_NAME,
    user: req.user,
    body: `
      <h1>Share a chat</h1>
      <p class="muted">Drop in your screenshots. They stack into one page the reader just scrolls — no zooming, no guessing which shot came first.</p>

      <form class="card stack" id="chat-form" onsubmit="return false;">
        <div>
          <label for="chat-title">Title (optional)</label>
          <input id="chat-title" type="text" placeholder="e.g. Chat with Sarah — Tuesday">
        </div>

        <div>
          <label>Screenshots</label>
          <div class="dropzone" id="chat-dropzone">
            <input id="chat-file" type="file" accept="image/*" multiple>
            <div class="dropzone-inner">
              <div class="dropzone-icon" id="chat-dz-icon">🖼</div>
              <div class="dropzone-text">
                <strong>Drop your screenshots here</strong>
                <span class="sub">or tap to choose from your phone · pick them all at once</span>
              </div>
            </div>
          </div>
          <p class="muted" style="font-size:12px; margin:6px 0 0;">
            Up to ${cap} screenshots · ${fmtBytes(SIZE_CAPS.image)} each. They're sorted oldest first — drag to change the order.
          </p>
        </div>

        <div id="shot-wrap" style="display:none;">
          <div class="shot-toolbar">
            <span class="shot-count" id="shot-count">0 screenshots</span>
            <span class="row" style="flex:0 0 auto;">
              <button type="button" class="btn btn-secondary btn-sm" id="shot-reverse">↕ Reverse order</button>
              <button type="button" class="btn btn-secondary btn-sm" id="shot-clear">Clear all</button>
            </span>
          </div>
          <ul class="shot-list" id="shot-list"></ul>
          <p class="muted" style="font-size:12px; margin:2px 0 0;">Number 1 is the top of the scroll — the start of the conversation.</p>
        </div>

        <div>
          <label for="chat-notes">Notes (optional)</label>
          <textarea id="chat-notes" class="notes-input" rows="4" maxlength="${NOTES_MAX_CHARS}"
                    placeholder="Paste the prompt behind this conversation…"></textarea>
          <p class="muted" style="font-size:12px; margin:6px 0 0;">Shown at the end of the scroll with a Copy button.</p>
        </div>

        <label class="checkbox-row" for="chat-dl">
          <input id="chat-dl" type="checkbox">
          <span>Allow viewers to download the screenshots
            <span class="hint">When off, the page only shows them — no download button.</span>
          </span>
        </label>

        <button type="button" class="btn btn-block" id="chat-create" disabled>Create the scroll link</button>

        <div class="chat-progress" id="chat-progress" aria-live="polite">
          <div class="chat-progress-track"><div class="chat-progress-fill" id="chat-progress-fill"></div></div>
          <div class="chat-progress-text" id="chat-progress-text">Starting…</div>
        </div>
        <p class="err" id="chat-err" style="display:none;"></p>
        <button type="button" class="btn btn-block" id="chat-retry" style="display:none;">Retry the ones that failed</button>
      </form>

      <div id="chat-done" style="display:none;"></div>

      <script>
        window.__CHAT_CAP = ${cap};
        window.__IMAGE_CAP = ${SIZE_CAPS.image};
        window.__ORIGIN = ${JSON.stringify(PUBLIC_ORIGIN)};
      </script>
      <script src="/vendor/sortable.min.js" defer></script>
      <script defer>${CHAT_NEW_JS}</script>
    `,
  }));
});

// ---------- chats: edit page ----------

app.get('/chats/:slug/edit', requireUser, (req, res) => {
  const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!c) {
    return res.status(404).send(layout({ title: 'Not found', user: req.user, body: `<h1>Not found</h1><p>That chat scroll doesn't exist.</p><a class="btn btn-block" href="/chats">Back to chat scrolls</a>` }));
  }
  const items = cdb.items(c.id);
  const cap = chatItemCap(req.user);
  const link = `${PUBLIC_ORIGIN}/c/${c.slug}`;

  const rows = items.map((it, idx) => `
    <li class="shot" data-id="${it.id}">
      <span class="shot-handle" title="Drag to reorder">⠿</span>
      <span class="shot-num">${idx + 1}</span>
      <img class="shot-thumb" src="/cr/${escHtml(c.slug)}/${it.id}" alt="" loading="lazy">
      <span class="shot-meta">
        <span class="shot-name">${escHtml(it.original_filename || 'screenshot')}</span>
        <span class="shot-sub">${fmtBytes(it.size_bytes)}</span>
      </span>
      <span class="shot-actions">
        <button type="button" class="shot-up" title="Move up">↑</button>
        <button type="button" class="shot-down" title="Move down">↓</button>
        <button type="button" class="shot-del" title="Remove">✕</button>
      </span>
    </li>
  `).join('');

  res.send(layout({
    title: 'Edit chat scroll — ' + SITE_NAME,
    user: req.user,
    body: `
      <h1>Edit chat scroll</h1>
      <div class="card">
        <label for="chat-title">Title</label>
        <input id="chat-title" type="text" value="${escHtml(c.title)}" placeholder="Untitled chat">
        <label for="chat-notes" style="display:block; margin-top:12px;">Notes (optional)</label>
        <textarea id="chat-notes" class="notes-input" rows="4" maxlength="${NOTES_MAX_CHARS}"
                  placeholder="Paste the prompt behind this conversation…">${escHtml(c.notes || '')}</textarea>
        <p class="muted" style="font-size:12px; margin:6px 0 0;">Shown at the end of the scroll with a Copy button.</p>
        <label class="checkbox-row" for="chat-dl" style="margin-top:12px;">
          <input id="chat-dl" type="checkbox" ${c.download_allowed ? 'checked' : ''}>
          <span>Allow viewers to download the screenshots</span>
        </label>
        <div class="row" style="margin-top:12px;">
          <button type="button" class="btn btn-secondary" id="chat-save">Save</button>
          <button type="button" class="btn btn-secondary chat-copy" data-url="${escHtml(link)}">Copy link</button>
          <a class="btn btn-secondary" href="/c/${escHtml(c.slug)}" target="_blank" rel="noopener">Open</a>
        </div>
        <p class="muted" id="chat-saved" style="font-size:13px; margin:8px 0 0; display:none;">Saved.</p>
      </div>

      <div class="card">
        <div class="shot-toolbar">
          <span class="shot-count" id="shot-count">${items.length} screenshot${items.length === 1 ? '' : 's'}</span>
          <button type="button" class="btn btn-secondary btn-sm" id="shot-reverse">↕ Reverse order</button>
        </div>
        <ul class="shot-list" id="shot-list">${rows}</ul>
        <p class="muted" style="font-size:12px; margin:2px 0 12px;">Drag the ⠿ handle to reorder. Number 1 is the top of the scroll. Changes save automatically.</p>

        <div class="dropzone" id="chat-dropzone">
          <input id="chat-file" type="file" accept="image/*" multiple>
          <div class="dropzone-inner">
            <div class="dropzone-icon">➕</div>
            <div class="dropzone-text">
              <strong>Add more screenshots</strong>
              <span class="sub">they go to the end — drag them where you want</span>
            </div>
          </div>
        </div>
        <div class="chat-progress" id="chat-progress" aria-live="polite">
          <div class="chat-progress-track"><div class="chat-progress-fill" id="chat-progress-fill"></div></div>
          <div class="chat-progress-text" id="chat-progress-text">Starting…</div>
        </div>
        <p class="err" id="chat-err" style="display:none;"></p>
      </div>

      <div class="card">
        <button type="button" class="btn btn-danger btn-block" id="chat-delete">Delete this chat scroll</button>
      </div>

      <script>
        window.__CHAT_SLUG = ${JSON.stringify(c.slug)};
        window.__CHAT_CAP = ${cap};
        window.__IMAGE_CAP = ${SIZE_CAPS.image};
      </script>
      <script src="/vendor/sortable.min.js" defer></script>
      <script defer>${CHAT_EDIT_JS}</script>
    `,
  }));
});

// ---------- chats: write APIs ----------

app.post('/api/chats', requireUser, express.json({ limit: '256kb' }), (req, res) => {
  const gate = chatGate(req.user);
  if (!gate.ok) return res.status(403).json({ ok: false, error: gate.reason });

  const title = (req.body.title || '').toString().trim().slice(0, 200);
  const notes = (req.body.notes || '').toString().slice(0, NOTES_MAX_CHARS);
  const allowDownload = req.body.allow_download === true || req.body.allow_download === 'true';
  const slug = nanoid(8);
  cdb.create({ slug, user_id: req.user.id, title, notes, download_allowed: allowDownload ? 1 : 0 });
  console.log(`[chat] user=${req.user.id} created draft ${slug}`);
  res.json({ ok: true, slug });
});

app.post('/api/chats/:slug/items', requireUser, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ ok: false, error: 'No image uploaded.' });

  try {
    const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!c) throw new Error('That chat scroll no longer exists.');

    const fresh = udb.getById(req.user.id);
    if (!fresh) throw new Error('Account not found.');
    if (fresh.status === 'deactivated') throw new Error('Your account is deactivated. Contact the admin.');

    const cls = classify(file.originalname, file.mimetype);
    if (cls.kind !== 'image') throw new Error(`${file.originalname} isn't an image — a chat scroll only takes screenshots.`);
    if (file.size > SIZE_CAPS.image) {
      throw new Error(`${file.originalname} is ${fmtBytes(file.size)} but the limit is ${fmtBytes(SIZE_CAPS.image)} per screenshot.`);
    }

    const cap = chatItemCap(fresh);
    const count = cdb.countItems(c.id);
    if (count >= cap) throw new Error(`This scroll is full at ${cap} screenshots.`);

    const position = cdb.nextPosition(c.id);
    const uniq = nanoid(6);
    const safeBase = sanitizeForFilename(c.title || 'chat');
    const ghlDisplayName = `${safeBase}-${String(position + 1).padStart(3, '0')}-${uniq}.${cls.ghlExt}`;

    const ghlCfg = users.effectiveGhlConfig(fresh);
    const ghlUrl = ghl.uploadToGhl(file.path, ghlDisplayName, cls.ghlMime, ghlCfg);

    // Width/height come from the browser, which already decoded the image to
    // draw the thumbnail. Storing them lets the viewer reserve the right box
    // per screenshot, so a lazy-loaded image never shifts the reader's place
    // mid-scroll. Zero is a safe fallback — we just omit the attributes.
    const width = Math.max(0, parseInt(req.body.width, 10) || 0);
    const height = Math.max(0, parseInt(req.body.height, 10) || 0);

    const itemId = cdb.addItem({
      chat_id: c.id, position, ghl_url: ghlUrl,
      original_filename: file.originalname,
      mime_type: cls.mime, size_bytes: file.size,
      width, height,
    });
    cdb.touch(c.id);

    res.json({
      ok: true, id: itemId, position,
      thumb: `/cr/${c.slug}/${itemId}`,
      name: file.originalname,
      size: file.size,
      count: count + 1,
    });
  } catch (err) {
    console.error('[chat-item] failed:', err.message);
    res.status(400).json({ ok: false, error: err.message || 'Upload failed' });
  } finally {
    try { fs.unlinkSync(file.path); } catch {}
  }
});

app.post('/api/chats/:slug/finalize', requireUser, (req, res) => {
  const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Not found.' });
  const count = cdb.countItems(c.id);
  if (count < 1) return res.status(400).json({ ok: false, error: 'Add at least one screenshot first.' });
  cdb.markReady(c.id);
  const shareLink = `${PUBLIC_ORIGIN}/c/${c.slug}`;
  console.log(`[chat] user=${req.user.id} published ${c.slug} with ${count} screenshot(s)`);
  res.json({ ok: true, slug: c.slug, shareLink, count });
});

// Reorder the chat-scroll CARDS on /chats (not the screenshots inside one —
// that's /api/chats/:slug/reorder below). Body: { slugs: [...] } top-to-bottom.
app.post('/api/chats/reorder-list', requireUser, express.json({ limit: '200kb' }), (req, res) => {
  const slugs = Array.isArray(req.body && req.body.slugs) ? req.body.slugs : null;
  if (!slugs) return res.status(400).json({ ok: false, error: 'slugs required' });
  res.json(cdb.reorderForUser(req.user.id, slugs));
});

app.post('/api/chats/:slug/reorder', requireUser, express.json({ limit: '100kb' }), (req, res) => {
  const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Not found.' });
  const ids = Array.isArray(req.body.ids) ? req.body.ids.slice(0, CHAT_MAX_ITEMS + 10) : [];
  const n = cdb.reorder(c.id, ids);
  res.json({ ok: true, count: n });
});

app.post('/api/chats/:slug/settings', requireUser, express.json({ limit: '256kb' }), (req, res) => {
  const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Not found.' });
  if (typeof req.body.title === 'string') cdb.setTitle(c.id, req.body.title.trim());
  if (typeof req.body.notes === 'string') cdb.setNotes(c.id, req.body.notes.slice(0, NOTES_MAX_CHARS));
  if (typeof req.body.allow_download === 'boolean') cdb.setDownload(c.id, req.body.allow_download);
  res.json({ ok: true });
});

app.post('/api/chats/:slug/items/:id/delete', requireUser, (req, res) => {
  const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Not found.' });
  const removed = cdb.deleteItem(c.id, parseInt(req.params.id, 10));
  if (!removed) return res.status(404).json({ ok: false, error: 'That screenshot is already gone.' });
  // Close the gap left behind so positions stay 0..n-1.
  cdb.reorder(c.id, cdb.items(c.id).map(i => i.id));
  purgeChatImages([removed.ghl_url], udb.getById(req.user.id));
  res.json({ ok: true, count: cdb.countItems(c.id) });
});

app.post('/api/chats/:slug/delete', requireUser, (req, res) => {
  const userRow = udb.getById(req.user.id);
  const urls = cdb.deleteForUser(req.params.slug, req.user.id);
  if (urls == null) return res.status(404).json({ ok: false, error: 'Not found.' });
  purgeChatImages(urls, userRow);
  console.log(`[chat] user=${req.user.id} deleted ${req.params.slug} (${urls.length} image(s))`);
  res.json({ ok: true });
});

// ---------- chats: image proxy ----------
//
// Same reasoning as /raw/<slug>: serve the bytes through us so the GHL CDN
// URL never appears in the page source. A draft's images are owner-only —
// the scroll isn't published yet, so nobody else should be able to pull
// frames out of it by guessing the slug.

app.get('/cr/:slug/:id', async (req, res) => {
  const c = cdb.getBySlug(req.params.slug);
  if (!c) return res.status(404).send('Not found');
  if (c.status !== 'ready') {
    const viewerUid = parseInt(req.signedCookies.uid, 10);
    if (!Number.isFinite(viewerUid) || viewerUid !== c.user_id) return res.status(404).send('Not found');
  }
  const item = cdb.getItem(c.id, parseInt(req.params.id, 10));
  if (!item) return res.status(404).send('Not found');

  try {
    const upstream = await fetch(item.ghl_url);
    if (!upstream.ok || !upstream.body) return res.status(502).send('Upstream error');
    res.status(200);
    res.set('Content-Type', item.mime_type || 'image/jpeg');
    const len = upstream.headers.get('content-length');
    if (len) res.set('Content-Length', len);
    res.set('Cache-Control', c.status === 'ready' ? 'public, max-age=86400' : 'private, max-age=0');
    const { Readable } = require('node:stream');
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (err) {
    console.error('[chat-raw]', err);
    res.status(502).send('Stream failed');
  }
});

// ---------- chats: public viewer ----------

app.get('/c/:slug', (req, res) => {
  const c = cdb.getBySlug(req.params.slug);
  if (!c || c.status !== 'ready') {
    return res.status(404).send(layout({
      title: 'Not found',
      user: req.user,
      body: `<h1>Not found</h1><p>This link does not exist or was removed.</p>`,
    }));
  }
  res.set('X-Robots-Tag', 'noindex, nofollow');

  const items = cdb.items(c.id);
  pushOnFirstView({ slug: c.slug, user_id: c.user_id, title: c.title, original_filename: 'a chat scroll' }, req);

  // width/height reserve the exact box each screenshot will occupy, so
  // lazy-loading never yanks the page out from under the reader.
  const shots = items.map((it, idx) => {
    const dims = it.width > 0 && it.height > 0 ? ` width="${it.width}" height="${it.height}"` : '';
    return `<img class="chat-shot" src="/cr/${escHtml(c.slug)}/${it.id}"${dims}` +
           ` loading="${idx < 2 ? 'eager' : 'lazy'}" decoding="async"` +
           ` alt="Screenshot ${idx + 1} of ${items.length}" data-n="${idx + 1}">`;
  }).join('');

  const title = c.title || 'Shared chat';
  const first = items[0];

  res.send(layout({
    title: title + ' — ' + SITE_NAME,
    user: req.user,
    mainClass: 'chat-main',
    ogTitle: title,
    ogDescription: `${items.length} screenshot${items.length === 1 ? '' : 's'} · scroll to read the whole conversation`,
    ogImageUrl: first ? `${PUBLIC_ORIGIN}/cr/${c.slug}/${first.id}` : '',
    noindex: true,
    body: `
      <div class="chat-bar" id="chat-bar"></div>
      <div class="chat-head">
        <h1>💬 ${escHtml(title)}</h1>
        <p class="muted" style="margin:0; font-size:13px;">${items.length} screenshot${items.length === 1 ? '' : 's'} · scroll to read it all</p>
      </div>
      <div class="chat-scroll" id="chat-scroll">${shots}</div>
      ${c.notes ? `<div style="padding: 16px 18px 0;">${viewers.renderNotes(c.notes)}</div>` : ''}
      <div class="chat-foot">
        <p class="muted" style="font-size:13px; margin:0;">End of the conversation · shared from ${escHtml(SITE_NAME)}</p>
      </div>
      <div class="chat-pos" id="chat-pos">1 / ${items.length}</div>
      <div class="lightbox" id="lightbox">
        <button type="button" class="lightbox-close" id="lightbox-close" aria-label="Close">✕</button>
        <img id="lightbox-img" alt="">
        ${c.download_allowed ? `<a class="lightbox-dl" id="lightbox-dl" href="#" download>⬇ Download this screenshot</a>` : ''}
      </div>
      <script>${CHAT_VIEW_JS}</script>
    `,
  }));
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
  const nextCursor = rows.length === limit ? rows[rows.length - 1].sort_order : null;
  res.json({ html: rows.map(renderRecentCard).join(''), nextCursor });
});

// Save a drag-and-drop (or ↑/↓) reorder of the file list. Body:
// { slugs: ["a","b",...] } in the desired top-to-bottom order.
app.post('/api/recent/reorder', requireUser, express.json({ limit: '200kb' }), (req, res) => {
  const slugs = Array.isArray(req.body && req.body.slugs) ? req.body.slugs : null;
  if (!slugs) return res.status(400).json({ ok: false, error: 'slugs required' });
  const result = fdb.reorderForUser(req.user.id, slugs);
  res.json(result);
});

app.post('/api/rename/:slug', requireUser, express.json(), (req, res) => {
  const title = (req.body && req.body.title || '').toString().trim();
  if (!title) return res.status(400).json({ ok: false, error: 'title required' });
  const changed = fdb.updateTitle(req.params.slug, req.user.id, title.slice(0, 200));
  if (!changed) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({ ok: true, title });
});

// Notes save. An empty body is a valid save — it's how you remove notes —
// so unlike rename there is no "required" check. The JSON limit has to
// clear NOTES_MAX_CHARS with room for multi-byte characters.
app.post('/api/notes/:slug', requireUser, express.json({ limit: '256kb' }), (req, res) => {
  const notes = (req.body && req.body.notes != null ? req.body.notes : '').toString().slice(0, NOTES_MAX_CHARS);
  const changed = fdb.updateNotes(req.params.slug, req.user.id, notes);
  if (!changed) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({ ok: true, notes });
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
              window.__confirmDelete({
                title: 'Delete this account?',
                message: 'You\\'re about to delete the account ' + who + ' along with every share link and every file they uploaded. This is permanent and cannot be reversed.',
                okText: 'Delete account',
                then: async () => {
                  btn.disabled = true;
                  try {
                    const res = await fetch('/admin/users/' + id + '/delete', { method: 'POST', credentials: 'same-origin' });
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    tr.remove();
                  } catch { alert('Delete failed.'); btn.disabled = false; }
                }
              });
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
  // Chat rows cascade away with the user, but the images behind them live in
  // GHL — collect their URLs before the cascade so they don't leak.
  const chatUrls = cdb.listUrlsByUser(id);
  udb.deleteById(id);
  for (const u of urls) { try { ghl.tryDeleteFromGhl(u, userCfg); } catch {} }
  for (const u of chatUrls) { try { ghl.tryDeleteFromGhl(u, userCfg); } catch {} }
  res.json({ ok: true, deletedFiles: urls.length, deletedChatImages: chatUrls.length });
});

// ---------- healthz ----------

app.get('/healthz', (req, res) => res.json({ ok: true, site: SITE_NAME, api_v1: true, apns: apns.configured }));

// ---------- Privacy + support pages (App Store required URLs) ----------

const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'engrmoshbari@gmail.com';
const SITE_LAUNCH_DATE = '2026';

function legalPageWrapper(title, body) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escHtml(title)} — ${escHtml(SITE_NAME)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         color: #0f172a; max-width: 720px; margin: 40px auto; padding: 0 20px;
         line-height: 1.55; }
  h1 { font-size: 28px; margin: 0 0 8px; }
  h2 { font-size: 20px; margin: 28px 0 8px; }
  p, li { color: #334155; }
  a { color: #2661ea; }
  hr { border: 0; border-top: 1px solid #e2e8f0; margin: 28px 0; }
  .muted { color: #64748b; font-size: 14px; }
</style>
</head><body>
<p class="muted"><a href="/">← ${escHtml(SITE_NAME)}</a></p>
<h1>${escHtml(title)}</h1>
${body}
<hr>
<p class="muted">Last updated: ${SITE_LAUNCH_DATE}. Questions: <a href="mailto:${escHtml(SUPPORT_EMAIL)}">${escHtml(SUPPORT_EMAIL)}</a>.</p>
</body></html>`;
}

app.get('/privacy', (req, res) => {
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(legalPageWrapper('Privacy Policy', `
    <p>ShareZPresso (the "Service") lets you upload files and share them via short links, and lets you save text snippets that you can tap-to-copy on the go. This Privacy Policy explains what data we collect and why.</p>
    <h2>What we collect</h2>
    <ul>
      <li><strong>Account info</strong> — email and name when you sign up. Email is used to identify you and to send password-reset links.</li>
      <li><strong>Files you upload</strong> — stored on our content delivery partner (GoHighLevel Media) so they can be served at the share link. We never share the contents of your files with anyone except people who have your share link.</li>
      <li><strong>Saved text snippets</strong> — stored in our database under your account. We never read or share them.</li>
      <li><strong>Device identifier for push notifications</strong> — when you opt in to push, the iOS app sends us a per-device identifier (Apple's APNs token) so our servers can notify you when your share link is first opened. Push tokens are deleted on logout.</li>
      <li><strong>Standard server logs</strong> — IP address, request path, and timestamp for the most recent ~24 hours, used to detect abuse and debug crashes.</li>
    </ul>
    <h2>What we do NOT collect</h2>
    <ul>
      <li>No analytics SDKs (Google Analytics, Mixpanel, etc.).</li>
      <li>No advertising identifiers (IDFA, IDFV).</li>
      <li>No location data.</li>
      <li>No contacts, calendar, or other personal data from your device.</li>
      <li>No microphone, camera, or photo data unless you explicitly share a file via the app's upload buttons.</li>
    </ul>
    <h2>Who can see your files</h2>
    <p>Anyone with the share link can open the file. Share links are randomly generated (8 characters) and not guessable. You can disable downloads on a per-file basis, and you can delete any file at any time from the app — deletion removes it from our database and from our content delivery partner.</p>
    <h2>Account deletion</h2>
    <p>You can delete your account in the app: Account tab → Log out (and then ask the administrator to delete the account), or write to the support email below. Deletion is irreversible and removes all your files, share links, saved snippets, and device push tokens.</p>
    <h2>Children</h2>
    <p>ShareZPresso is not directed at children under 13.</p>
    <h2>Contact</h2>
    <p>For privacy questions, email <a href="mailto:${escHtml(SUPPORT_EMAIL)}">${escHtml(SUPPORT_EMAIL)}</a>.</p>
  `));
});

app.get('/support', (req, res) => {
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(legalPageWrapper('Support', `
    <p>ShareZPresso is a small tool to upload a file and share a link, plus a place to keep text snippets that you can tap-to-copy and paste into chats or emails.</p>
    <h2>Common questions</h2>
    <h3>How do I share a file?</h3>
    <p>Open the app, tap the big "Pick a file to share" button, choose Camera / Photo Library / Files, set an optional title, and tap Upload. You get a share link you can copy and send anywhere.</p>
    <h3>Why is my share link returning 404?</h3>
    <p>The file owner may have deleted the file, or the link is misspelled. Ask them for a fresh one.</p>
    <h3>How do push notifications work?</h3>
    <p>You'll get a push the first time someone (other than you) opens one of your share links. You can turn this off in iOS Settings → Notifications → ShareZPresso.</p>
    <h3>I forgot my password</h3>
    <p>On the Login screen, tap "Forgot password?" — we send a reset link to your email that's valid for 24 hours.</p>
    <h3>Can I use this on the web instead of the app?</h3>
    <p>Yes. The same account works on <a href="/">share.bizapp.club</a> in any browser.</p>
    <h2>Still stuck?</h2>
    <p>Email <a href="mailto:${escHtml(SUPPORT_EMAIL)}">${escHtml(SUPPORT_EMAIL)}</a>. Replies usually come within one business day.</p>
  `));
});

// Mount ShareZPresso iOS JSON namespace. All routes added under /api/v1/*
// in a separate file so the diff against server.js stays tiny. The web UI
// and existing /api/* routes are untouched.
apiV1.attach(app, {
  db: { users: udb, files: fdb, passwordResets: prdb, magicLinks: mldb, messages: mdb, groups: gdb, feed: feeddb, chats: cdb, apiTokens: atdb, deviceTokens: dtdb, NOTES_MAX_CHARS },
  users,
  ghl,
  transcode,
  email,
  classify: { classify, fmtBytes },
  apns,
  upload,
  PUBLIC_ORIGIN,
  baseFilename,
  sanitizeForFilename,
  kindEmoji,
  // Chat-scroll gating lives in server.js so the web pages and the iOS API
  // enforce exactly the same limits from one definition.
  chatHelpers: { gate: chatGate, itemCap: chatItemCap, purge: purgeChatImages },
});

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

// share.bizapp.club — upload any file, share a link with a built-in viewer.
//
// Flow (mirrors listen.bizapp.club's shape but generalised across file kinds):
//   1. Owner logs in with UPLOAD_PASSWORD.
//   2. Owner picks a file (image, video, audio, PDF, text/code/markdown).
//   3. Server classifies it, enforces per-type size cap, uploads to GHL.
//   4. Row written to SQLite with slug + kind + ghl_url + download flag.
//   5. Owner gets a share link like /f/<slug>.
//   6. Recipient opens the link → sees a viewer tailored to the file kind.
//      Per-file uploader toggle decides whether the download button shows.
//
// Storage: GHL media library (sub-account folder share.bizapp.club).
// Persistence: SQLite under /app/data (Coolify volume).

const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { nanoid } = require('nanoid');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const db = require('./lib/db');
const ghl = require('./lib/ghl');
const { classify, SIZE_CAPS, fmtBytes } = require('./lib/classify');
const viewers = require('./lib/viewers');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const UPLOAD_PASSWORD = process.env.UPLOAD_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SITE_NAME = process.env.SITE_NAME || 'share.bizapp.club';
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || 'https://share.bizapp.club';
const RECENT_PAGE_SIZE = 10;

if (!UPLOAD_PASSWORD) {
  console.error('[boot] UPLOAD_PASSWORD is not set — refusing to start');
  process.exit(1);
}

// ---------- middleware ----------

app.use(cookieParser(SESSION_SECRET));
app.disable('x-powered-by');
app.set('trust proxy', 1);

// Serve static assets (PDF.js viewer + worker live under /pdfjs/)
app.use('/pdfjs', express.static(path.join(__dirname, 'public', 'pdfjs'), {
  setHeaders(res, filePath) {
    // The PDF.js viewer pulls .mjs modules — make sure Node serves them
    // with a JS MIME type so the browser doesn't refuse them.
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

// Multer: stream to disk, hard cap = the largest type (video) so the cap
// never bites on a legitimate request. Per-type validation runs after.
const upload = multer({
  dest: process.env.UPLOAD_TMP || os.tmpdir(),
  limits: { fileSize: SIZE_CAPS.video }, // 4 GB
});

function requireOwner(req, res, next) {
  if (req.signedCookies.auth === 'ok') return next();
  return res.redirect('/login');
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
    const date = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Asia/Dubai', month: 'short', day: 'numeric', year: 'numeric',
    }).format(d);
    const time = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Asia/Dubai', hour: 'numeric', minute: '2-digit', hour12: true,
    }).format(d);
    return `${date} · ${time} GST`;
  } catch { return ''; }
}

function kindEmoji(kind) {
  return ({
    image: '🖼', video: '🎬', audio: '🎙', pdf: '📄', text: '📝', unknown: '📎',
  })[kind] || '📎';
}

const BASE_CSS = `
  :root { --fg:#111; --muted:#666; --bg:#fafafa; --card:#fff; --brand:#2563eb; --brand-dark:#1d4ed8; --ok:#16a34a; --err:#dc2626; --border:#e5e7eb; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body { font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--fg); min-height: 100vh; }
  .site-header { background: #0f172a; padding: 14px 20px; }
  .site-header .brand { display: inline-flex; align-items: center; gap: 8px; color: #fff; text-decoration: none; font-weight: 700; font-size: 17px; letter-spacing: -0.01em; }
  .site-header .brand:hover { opacity: 0.85; }
  .site-header .brand-mark { font-size: 20px; line-height: 1; }
  main { max-width: 720px; margin: 0 auto; padding: 32px 20px 64px; }
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
  .row { display: flex; gap: 8px; flex-wrap: wrap; }
  .row .btn { flex: 1 1 auto; padding: 10px 14px; font-size: 14px; min-height: 44px; text-align: center; }
  .stack > * + * { margin-top: 12px; }
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
  input[type="text"], input[type="password"] { display: block; width: 100%; padding: 12px 14px; font-size: 16px; border: 1px solid var(--border); border-radius: 10px; background: #fff; }
  label { display: block; font-weight: 600; margin-bottom: 6px; }
  .checkbox-row { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #f8fafc; border: 1px solid var(--border); border-radius: 10px; cursor: pointer; }
  .checkbox-row input { width: 18px; height: 18px; margin: 0; }
  .checkbox-row span { flex: 1; font-weight: 500; color: var(--fg); }
  .checkbox-row .hint { display: block; font-weight: 400; font-size: 13px; color: var(--muted); margin-top: 2px; }
  /* ---------- Upload progress: rainbow, animated, satisfying ---------- */
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
  .progress-bar {
    position: relative; height: 16px; background: #e5e7eb; border-radius: 99px; overflow: hidden;
    box-shadow: inset 0 1px 3px rgba(0,0,0,0.08);
  }
  .progress-fill {
    position: relative; height: 100%; width: 0%; border-radius: 99px;
    background: linear-gradient(90deg, #2563eb, #9333ea, #ec4899, #f97316);
    background-size: 200% 100%;
    animation: progress-gradient-slide 2s linear infinite;
    transition: width .25s cubic-bezier(.4,0,.2,1);
    box-shadow: 0 0 12px rgba(147, 51, 234, 0.45);
  }
  @keyframes progress-gradient-slide { 0% { background-position: 0% 0%; } 100% { background-position: 200% 0%; } }
  /* Diagonal stripes overlay so motion is visible even when % isn't changing */
  .progress-fill::after {
    content: ''; position: absolute; inset: 0; border-radius: 99px;
    background-image: linear-gradient(45deg,
      rgba(255,255,255,.22) 25%, transparent 25%,
      transparent 50%, rgba(255,255,255,.22) 50%,
      rgba(255,255,255,.22) 75%, transparent 75%, transparent);
    background-size: 24px 24px;
    animation: progress-stripes-move 1s linear infinite;
  }
  @keyframes progress-stripes-move { 0% { background-position: 0 0; } 100% { background-position: 24px 0; } }
  .progress-meta { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; color: var(--muted); margin-top: 10px; flex-wrap: wrap; }
  .progress-meta strong { color: var(--fg); font-weight: 600; }
  .progress.is-done .progress-fill { animation: none; background: var(--ok); box-shadow: 0 0 12px rgba(22, 163, 74, 0.45); }
  .progress.is-done .progress-fill::after { animation: none; opacity: 0; }
  .progress.is-done .progress-pct { animation: none; background: none; -webkit-text-fill-color: var(--ok); color: var(--ok); }
  .link-box { padding: 14px; background: #f3f4f6; border-radius: 10px; font-family: ui-monospace, monospace; word-break: break-all; font-size: 14px; border: 1px solid var(--border); }
  .ok { color: var(--ok); }
  .err { color: var(--err); }
  .footer { margin-top: 40px; color: var(--muted); font-size: 13px; text-align: center; }
  /* Viewer specifics */
  .full-image { display: block; width: 100%; height: auto; border-radius: 8px; cursor: zoom-in; }
  .full-media { width: 100%; border-radius: 8px; background: #000; }
  .full-audio { width: 100%; }
  .image-card { padding: 12px; }
  .pdf-card { padding: 12px; }
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

function layout({ title, body, ogTitle, ogDescription, ogImageUrl, noindex = true }) {
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
  </header>
  <main>
    ${body}
  </main>
</body>
</html>`;
}

// ---------- recent list rendering ----------

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

// ---------- routes ----------

app.get('/', (req, res) => {
  if (req.signedCookies.auth === 'ok') return res.redirect('/upload');
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.send(layout({
    title: 'Log in — ' + SITE_NAME,
    body: `
      <h1>Log in</h1>
      <p class="muted">Enter your password to upload a file.</p>
      <form class="card stack" method="POST" action="/login">
        <div>
          <label for="password">Password</label>
          <input id="password" name="password" type="password" required autofocus>
        </div>
        <button type="submit" class="btn btn-block">Log in</button>
        ${req.query.err ? '<p class="err">Wrong password. Try again.</p>' : ''}
      </form>
    `,
  }));
});

app.post('/login', express.urlencoded({ extended: false }), (req, res) => {
  if (req.body.password === UPLOAD_PASSWORD) {
    res.cookie('auth', 'ok', {
      signed: true, httpOnly: true, sameSite: 'lax', secure: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
    return res.redirect('/upload');
  }
  return res.redirect('/login?err=1');
});

app.post('/logout', (req, res) => {
  res.clearCookie('auth');
  res.redirect('/login');
});

app.get('/upload', requireOwner, (req, res) => {
  const firstPage = db.listRecent({ limit: RECENT_PAGE_SIZE });
  const nextCursor = firstPage.length === RECENT_PAGE_SIZE
    ? firstPage[firstPage.length - 1].id
    : null;

  const recentHtml = firstPage.length === 0 ? '' : `
    <h2>Recent</h2>
    <div id="recent-list">
      ${firstPage.map(renderRecentCard).join('')}
    </div>
    ${nextCursor != null ? `
      <div id="recent-sentinel" data-cursor="${nextCursor}" class="muted" style="text-align: center; padding: 16px;">
        Loading more…
      </div>
    ` : ''}
    <script>
      (function () {
        const list = document.getElementById('recent-list');
        if (!list) return;

        list.addEventListener('click', async (e) => {
          const btn = e.target.closest('button, a');
          if (!btn) return;

          if (btn.classList.contains('copy-btn')) {
            const url = btn.dataset.url;
            try {
              await navigator.clipboard.writeText(url);
              const prev = btn.textContent;
              btn.textContent = 'Copied!';
              setTimeout(() => { btn.textContent = prev; }, 1500);
            } catch (err) {
              btn.textContent = 'Copy failed — long-press the link';
            }
            return;
          }

          if (btn.classList.contains('rename-btn')) {
            const item = btn.closest('.recent-item');
            const current = item.querySelector('.recent-title').textContent.trim().replace(/^[^\\s]+\\s+/, '');
            const next = prompt('New title', current);
            if (next == null) return;
            const title = next.trim();
            if (!title) { alert('Title cannot be empty.'); return; }
            const res = await fetch('/api/rename/' + btn.dataset.slug, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ title }),
              credentials: 'same-origin',
            });
            if (res.ok) {
              const titleEl = item.querySelector('.recent-title');
              const emoji = titleEl.textContent.trim().split(' ')[0];
              titleEl.textContent = emoji + ' ' + title;
              const delBtn = item.querySelector('.delete-btn');
              if (delBtn) delBtn.dataset.title = title;
            } else {
              alert('Rename failed.');
            }
            return;
          }

          if (btn.classList.contains('toggle-dl-btn')) {
            const item = btn.closest('.recent-item');
            const current = item.dataset.download === '1';
            btn.disabled = true;
            const res = await fetch('/api/toggle-download/' + btn.dataset.slug, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ allowed: !current }),
              credentials: 'same-origin',
            });
            btn.disabled = false;
            if (res.ok) {
              const data = await res.json();
              item.dataset.download = data.allowed ? '1' : '0';
              const stateEl = item.querySelector('.dl-state');
              stateEl.textContent = data.allowed ? 'Downloads ON' : 'Downloads OFF';
              stateEl.className = 'dl-state ' + (data.allowed ? 'ok' : 'muted');
            } else {
              alert('Toggle failed.');
            }
            return;
          }

          if (btn.classList.contains('delete-btn')) {
            const title = btn.dataset.title || 'this file';
            const ok = confirm('Delete "' + title + '"?\\n\\nThe share link will stop working and the file will be removed from storage. This cannot be undone.');
            if (!ok) return;
            btn.disabled = true;
            btn.textContent = 'Deleting…';
            const res = await fetch('/api/delete/' + btn.dataset.slug, {
              method: 'POST', credentials: 'same-origin',
            });
            if (res.ok) {
              btn.closest('.recent-item').remove();
            } else {
              btn.disabled = false;
              btn.textContent = 'Delete';
              alert('Delete failed.');
            }
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
              const res = await fetch('/api/recent?before=' + encodeURIComponent(cursor) + '&limit=${RECENT_PAGE_SIZE}', {
                credentials: 'same-origin',
              });
              if (!res.ok) throw new Error('HTTP ' + res.status);
              const data = await res.json();
              if (data.html) list.insertAdjacentHTML('beforeend', data.html);
              if (data.nextCursor == null) {
                io.disconnect();
                sentinel.remove();
              } else {
                sentinel.dataset.cursor = data.nextCursor;
                loading = false;
              }
            } catch (err) {
              sentinel.textContent = 'Could not load more — scroll to retry.';
              loading = false;
            }
          }
        }, { rootMargin: '200px 0px' });
        io.observe(sentinel);
      })();
    </script>
  `;

  // Per-type cap labels for the upload-page hint
  const caps = {
    Images: fmtBytes(SIZE_CAPS.image),
    Audio:  fmtBytes(SIZE_CAPS.audio),
    Video:  fmtBytes(SIZE_CAPS.video),
    PDFs:   fmtBytes(SIZE_CAPS.pdf),
    Text:   fmtBytes(SIZE_CAPS.text),
  };
  const capsHint = Object.entries(caps).map(([k, v]) => `${k} up to ${v}`).join(' · ');

  res.send(layout({
    title: 'Upload — ' + SITE_NAME,
    body: `
      <h1>Share a file</h1>
      <p class="muted">Drop any file. Get a link with a built-in viewer.</p>
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
          <span>
            Allow viewers to download
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
      <div class="footer">
        <form method="POST" action="/logout" style="display:inline;">
          <button type="submit" class="btn btn-secondary" style="padding: 8px 14px; min-height: 36px; font-size: 14px;">Log out</button>
        </form>
      </div>
      <script>
        // ---- Per-type caps mirrored for client-side validation ----
        // The server still re-validates after multer streams the file —
        // this is a courtesy check so we don't waste 4 GB of upload bandwidth.
        const SIZE_CAPS = ${JSON.stringify(SIZE_CAPS)};

        function classifyClient(name, mime) {
          const ext = (name.split('.').pop() || '').toLowerCase();
          const m = (mime || '').toLowerCase();
          if (m.startsWith('image/')) return { kind: 'image', cap: SIZE_CAPS.image };
          if (m.startsWith('video/')) return { kind: 'video', cap: SIZE_CAPS.video };
          if (m.startsWith('audio/')) return { kind: 'audio', cap: SIZE_CAPS.audio };
          if (m === 'application/pdf' || ext === 'pdf') return { kind: 'pdf', cap: SIZE_CAPS.pdf };
          // Anything with no MIME or text-y MIME → treat as text and cap small
          return { kind: 'text', cap: SIZE_CAPS.text };
        }

        function fmtBytes(b) {
          if (!b) return '0 B';
          const u = ['B','KB','MB','GB']; let i=0; let n=b;
          while (n>=1024 && i<u.length-1) { n/=1024; i++; }
          return (n<10 && i>0 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
        }

        // ---- Dropzone wiring ----
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('file');
        const filenameEl = document.getElementById('dropzoneFilename');
        const iconEl = document.getElementById('dropzoneIcon');

        function showFilename() {
          const f = fileInput.files && fileInput.files[0];
          if (f) {
            filenameEl.textContent = f.name + ' (' + fmtBytes(f.size) + ')';
            dropzone.classList.add('has-file');
            iconEl.textContent = '✅';
          } else {
            filenameEl.textContent = '';
            dropzone.classList.remove('has-file');
            iconEl.textContent = '📤';
          }
        }
        ['dragenter','dragover'].forEach(ev => {
          dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('is-dragover'); });
        });
        ['dragleave','drop'].forEach(ev => {
          dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('is-dragover'); });
        });
        dropzone.addEventListener('drop', (e) => {
          if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
            try { fileInput.files = e.dataTransfer.files; } catch (err) {}
            showFilename();
          }
        });
        fileInput.addEventListener('change', showFilename);

        // ---- Submit via XHR for real progress ----
        const form = document.getElementById('uploadForm');
        const btn = document.getElementById('submitBtn');
        const progress = document.getElementById('progress');
        const progressFill = document.getElementById('progressFill');
        const progressPct = document.getElementById('progressPct');
        const progressBytes = document.getElementById('progressBytes');
        const progressSpeed = document.getElementById('progressSpeed');
        const progressEta = document.getElementById('progressEta');
        const errMsg = document.getElementById('errMsg');

        function fmtEta(sec) {
          if (!Number.isFinite(sec) || sec <= 0) return '';
          if (sec < 60) return Math.round(sec) + 's left';
          if (sec < 3600) return Math.round(sec / 60) + 'm left';
          return (sec / 3600).toFixed(1) + 'h left';
        }
        function fmtSpeed(bps) {
          if (!Number.isFinite(bps) || bps <= 0) return '';
          return fmtBytes(bps) + '/s';
        }

        form.addEventListener('submit', (ev) => {
          ev.preventDefault();
          errMsg.style.display = 'none';
          const f = fileInput.files && fileInput.files[0];
          if (!f) return;

          // Client-side cap (server still re-checks)
          const c = classifyClient(f.name, f.type);
          if (f.size > c.cap) {
            errMsg.textContent = f.name + ' is ' + fmtBytes(f.size) + ' but the limit for this type is ' + fmtBytes(c.cap) + '.';
            errMsg.style.display = 'block';
            return;
          }

          const fd = new FormData(form);
          const xhr = new XMLHttpRequest();
          xhr.open('POST', '/api/upload');
          xhr.responseType = 'document';

          // Smoothed speed + ETA: a windowed average dampens the jitter you
          // get from a raw "bytes since last event" calculation, especially
          // on cellular where progress events arrive in bursts.
          const startedAt = performance.now();
          let lastTime = startedAt;
          let lastLoaded = 0;
          let smoothedBps = 0;
          const ALPHA = 0.25; // EMA weight on the latest sample

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
              smoothedBps = smoothedBps === 0 ? sampleBps : (ALPHA * sampleBps + (1 - ALPHA) * smoothedBps);
              lastTime = now;
              lastLoaded = e.loaded;
            }
            progressSpeed.textContent = fmtSpeed(smoothedBps);
            const remaining = (e.total - e.loaded) / Math.max(smoothedBps, 1);
            progressEta.textContent = fmtEta(remaining);
          });

          xhr.addEventListener('load', () => {
            if (xhr.status >= 200 && xhr.status < 300 && xhr.responseXML) {
              // Snap to 100% and a green "Done!" state for half a beat so
              // the user sees the success before the page flips.
              progressFill.style.width = '100%';
              progressPct.textContent = '100%';
              progressEta.textContent = 'Done!';
              progress.classList.add('is-done');
              setTimeout(() => {
                document.open();
                document.write(xhr.responseText);
                document.close();
              }, 350);
            } else {
              btn.disabled = false;
              btn.textContent = 'Upload and make link';
              progress.classList.remove('is-active');
              errMsg.textContent = 'Upload failed: ' + (xhr.status || 'network error');
              errMsg.style.display = 'block';
            }
          });
          xhr.addEventListener('error', () => {
            btn.disabled = false;
            btn.textContent = 'Upload and make link';
            progress.classList.remove('is-active');
            errMsg.textContent = 'Upload failed: network error';
            errMsg.style.display = 'block';
          });

          btn.disabled = true;
          btn.textContent = 'Uploading…';
          progress.classList.add('is-active');
          xhr.send(fd);
        });
      </script>
    `,
  }));
});

app.post('/api/upload', requireOwner, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send(uploadErrorPage('No file uploaded'));

  try {
    console.log(`[upload] received ${file.originalname} mime=${file.mimetype} size=${file.size}`);

    const cls = classify(file.originalname, file.mimetype);
    if (cls.kind === 'unknown') {
      throw new Error(cls.reason || 'Unsupported file type');
    }
    if (file.size > cls.maxBytes) {
      throw new Error(`${file.originalname} is ${fmtBytes(file.size)} but the limit for ${cls.kind} files is ${fmtBytes(cls.maxBytes)}.`);
    }

    // Resolve title and a safe display name for GHL.
    const userTitle = (req.body.title || '').toString().trim();
    const fallbackTitle = baseFilename(file.originalname) || 'File';
    const title = (userTitle || fallbackTitle).slice(0, 200);
    // HTML checkboxes only appear in the form payload when checked. We accept
    // a few truthy variants so this works whether the form is submitted as
    // urlencoded, multipart, or JSON in the future.
    const allowDownload = req.body.allow_download === 'on'
      || req.body.allow_download === 'true'
      || req.body.allow_download === '1';

    const slug = nanoid(8);
    const uniq = nanoid(4);
    const safeBase = sanitizeForFilename(title);
    // GHL display name uses our coerced extension (e.g. .txt for code files)
    // so the upload doesn't trip INVALID_FILE_TYPE. Original name is in DB.
    const ghlDisplayName = `${safeBase}-${uniq}.${cls.ghlExt}`;

    const ghlUrl = ghl.uploadToGhl(file.path, ghlDisplayName, cls.ghlMime);

    db.insert({
      slug,
      title,
      original_filename: file.originalname,
      kind: cls.kind,
      mime_type: cls.mime,
      size_bytes: file.size,
      download_allowed: allowDownload,
      ghl_url: ghlUrl,
    });

    const shareLink = `${PUBLIC_ORIGIN}/f/${slug}`;
    console.log(`[upload] done: ${shareLink}`);

    res.send(layout({
      title: 'Link ready — ' + SITE_NAME,
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
        </div>
        <a href="/upload" class="btn btn-secondary btn-block">Upload another</a>
        <script>
          const btn = document.getElementById('copyBtn');
          btn.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(${JSON.stringify(shareLink)});
              btn.textContent = 'Copied!';
              setTimeout(() => { btn.textContent = 'Copy link'; }, 1500);
            } catch (e) {
              btn.textContent = 'Copy failed — long-press the link';
            }
          });
        </script>
      `,
    }));
  } catch (err) {
    console.error('[upload] failed:', err);
    res.status(500).send(uploadErrorPage(err.message || 'Unknown error'));
  } finally {
    try { fs.unlinkSync(file.path); } catch {}
  }
});

function uploadErrorPage(msg) {
  return layout({
    title: 'Upload failed — ' + SITE_NAME,
    body: `
      <h1 class="err">Upload failed</h1>
      <p>${escHtml(msg)}</p>
      <a href="/upload" class="btn btn-block">Try again</a>
    `,
  });
}

// ---- /raw/:slug — proxy GHL bytes through us ----
//
// Used by the viewer pages (img/video/audio src, PDF.js fetch). Always
// inline (no Content-Disposition: attachment) so the browser previews.
// Still fires regardless of `download_allowed` — the flag controls whether
// a Download button appears, not whether previewable content is visible.
app.get('/raw/:slug', async (req, res) => {
  const rec = db.getBySlug(req.params.slug);
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

// ---- /d/:slug — download proxy with attachment disposition ----
//
// Only available when download_allowed=1. Sets Content-Disposition so
// the browser saves to disk with the original filename instead of opening
// the asset inline.
app.get('/d/:slug', async (req, res) => {
  const rec = db.getBySlug(req.params.slug);
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

// ---- /f/:slug — viewer page, dispatch by kind ----
app.get('/f/:slug', async (req, res) => {
  const rec = db.getBySlug(req.params.slug);
  if (!rec) {
    return res.status(404).send(layout({
      title: 'Not found',
      body: `<h1>Not found</h1><p>This link does not exist or was removed.</p>`,
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
      // Stream the file content into memory for inline rendering. Text files
      // are capped at 100 MB but rendering a 100 MB text file would crash the
      // page anyway — soft-cap the inline render at 5 MB and show a notice
      // for anything larger (download-only beyond that).
      const SOFT_INLINE_CAP = 5 * 1024 * 1024;
      if (rec.size_bytes > SOFT_INLINE_CAP) {
        body = `
          <h1>${escHtml(rec.title || rec.original_filename || 'Text')}</h1>
          <p class="muted">${escHtml(rec.original_filename || '')} · ${fmtBytes(rec.size_bytes)}</p>
          <div class="card">
            <p>This text file is too large to preview inline (${fmtBytes(rec.size_bytes)} > ${fmtBytes(SOFT_INLINE_CAP)}).</p>
            ${rec.download_allowed ? `<a class="btn btn-block" href="/d/${rec.slug}" download>⬇ Download to read</a>` : '<p class="muted">Downloads are disabled for this file.</p>'}
          </div>
          <div class="footer">Shared from ${escHtml(SITE_NAME)}</div>
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
        <div class="card">
          <p>This file type does not have a built-in viewer.</p>
          ${rec.download_allowed ? `<a class="btn btn-block" href="/d/${rec.slug}" download>⬇ Download</a>` : '<p class="muted">Downloads are disabled for this file.</p>'}
        </div>
      `;
  }

  res.send(layout({
    title: ogTitle + ' — ' + SITE_NAME,
    body,
    ogTitle,
    ogDescription,
    ogImageUrl,
    noindex: true,
  }));
});

// ---- Admin APIs (recent / rename / toggle-download / delete) ----

app.get('/api/recent', requireOwner, (req, res) => {
  const before = parseInt(req.query.before, 10);
  if (!Number.isFinite(before) || before <= 0) {
    return res.status(400).json({ error: 'before cursor required' });
  }
  const limit = Math.max(1, Math.min(50, parseInt(req.query.limit, 10) || RECENT_PAGE_SIZE));
  const rows = db.listRecent({ before, limit });
  const nextCursor = rows.length === limit ? rows[rows.length - 1].id : null;
  res.json({
    html: rows.map(renderRecentCard).join(''),
    nextCursor,
  });
});

app.post('/api/rename/:slug', requireOwner, express.json(), (req, res) => {
  const title = (req.body && req.body.title || '').toString().trim();
  if (!title) return res.status(400).json({ ok: false, error: 'title required' });
  const changed = db.updateTitle(req.params.slug, title.slice(0, 200));
  if (!changed) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({ ok: true, title });
});

app.post('/api/toggle-download/:slug', requireOwner, express.json(), (req, res) => {
  const allowed = !!(req.body && req.body.allowed);
  const changed = db.setDownloadAllowed(req.params.slug, allowed);
  if (!changed) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({ ok: true, allowed });
});

app.post('/api/delete/:slug', requireOwner, (req, res) => {
  const ghlUrl = db.deleteBySlug(req.params.slug);
  if (!ghlUrl) return res.status(404).json({ ok: false, error: 'not found' });
  try { ghl.tryDeleteFromGhl(ghlUrl); } catch {}
  res.json({ ok: true });
});

app.get('/healthz', (req, res) => {
  res.json({ ok: true, site: SITE_NAME });
});

// ---------- boot ----------

console.log(`[boot] starting ${SITE_NAME} on :${PORT}`);
const check = ghl.healthCheck();
if (check.ok) console.log('[boot] GHL reachable');
else console.warn('[boot] GHL check failed:', check.reason);

app.listen(PORT, () => {
  console.log(`[boot] listening on :${PORT}`);
});

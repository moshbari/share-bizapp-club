// Per-kind viewer renderers for /f/<slug>.
//
// Each renderer returns the inner HTML body that the layout() wrapper
// in server.js wraps. Stylesheet lives in server.js (BASE_CSS) so all
// pages share one CSS payload — no flash of unstyled content between
// the upload page and the viewer.
//
// We always serve the raw bytes through /raw/<slug> rather than letting
// the browser fetch the GHL CDN URL directly. Reasons:
//   - PDF.js does an XHR fetch for the PDF — same-origin avoids CORS
//   - Text/markdown rendering happens server-side, but if the user clicks
//     "View source" we fetch /raw/ from JS and want it same-origin too
//   - Keeps the GHL CDN URL out of devtools, so listeners who shouldn't
//     download still can't right-click → save the asset URL directly.
//     (They CAN still grab it from network tab — true protection isn't
//     possible for previewable content. This is a polish win, not a lock.)

const path = require('node:path');
const { marked } = require('marked');

function escHtml(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function downloadButton(slug, allowed, label = '⬇ Download') {
  if (!allowed) return '';
  return `<a class="btn btn-secondary btn-block" href="/d/${escHtml(slug)}" download>${label}</a>`;
}

function fmtBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0; let n = bytes;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}

function metaLine(rec) {
  const parts = [];
  if (rec.original_filename) parts.push(escHtml(rec.original_filename));
  parts.push(fmtBytes(rec.size_bytes));
  return parts.join(' · ');
}

// ---------- IMAGE ----------
function renderImage(rec, siteName) {
  return `
    <h1>${escHtml(rec.title || rec.original_filename || 'Image')}</h1>
    <p class="muted">${metaLine(rec)}</p>
    <div class="card image-card">
      <a href="/raw/${escHtml(rec.slug)}" target="_blank" rel="noopener" title="Open full size in new tab">
        <img src="/raw/${escHtml(rec.slug)}" alt="${escHtml(rec.title || rec.original_filename || '')}" class="full-image">
      </a>
      ${downloadButton(rec.slug, rec.download_allowed)}
    </div>
    <div class="footer">Shared from ${escHtml(siteName)}</div>
  `;
}

// ---------- VIDEO ----------
function renderVideo(rec, siteName) {
  const mime = escHtml(rec.mime_type || 'video/mp4');
  // controlsList="nodownload" hides the menu's download item in Chromium —
  // it's a hint, not a lock. The download proxy is still the only blessed path.
  const noDl = rec.download_allowed ? '' : 'controlsList="nodownload" disablePictureInPicture';
  return `
    <h1>${escHtml(rec.title || rec.original_filename || 'Video')}</h1>
    <p class="muted">${metaLine(rec)}</p>
    <div class="card">
      <video controls preload="metadata" class="full-media" ${noDl}>
        <source src="/raw/${escHtml(rec.slug)}" type="${mime}">
        Your browser can't play this video. Use the download button below if available.
      </video>
      ${downloadButton(rec.slug, rec.download_allowed)}
    </div>
    <div class="footer">Shared from ${escHtml(siteName)}</div>
  `;
}

// ---------- AUDIO ----------
function renderAudio(rec, siteName) {
  const noDl = rec.download_allowed ? '' : 'controlsList="nodownload"';
  return `
    <h1>${escHtml(rec.title || rec.original_filename || 'Audio')}</h1>
    <p class="muted">${metaLine(rec)}</p>
    <div class="card">
      <audio controls preload="metadata" class="full-audio" src="/raw/${escHtml(rec.slug)}" ${noDl}></audio>
      ${downloadButton(rec.slug, rec.download_allowed)}
    </div>
    <div class="footer">Shared from ${escHtml(siteName)}</div>
  `;
}

// ---------- PDF ----------
//
// We embed the prebuilt PDF.js viewer (copied into /public/pdfjs/ at build
// time — see Dockerfile). The viewer reads `?file=<URL>`, has built-in
// page nav, zoom, search, thumbnail sidebar, and text selection.
function renderPdf(rec, siteName) {
  const fileUrl = `/raw/${encodeURIComponent(rec.slug)}`;
  const viewerUrl = `/pdfjs/web/viewer.html?file=${encodeURIComponent(fileUrl)}`;
  return `
    <h1>${escHtml(rec.title || rec.original_filename || 'PDF')}</h1>
    <p class="muted">${metaLine(rec)}</p>
    <div class="card pdf-card">
      <iframe src="${escHtml(viewerUrl)}" class="pdf-frame" title="PDF viewer"></iframe>
      ${downloadButton(rec.slug, rec.download_allowed, '⬇ Download PDF')}
    </div>
    <div class="footer">Shared from ${escHtml(siteName)}</div>
  `;
}

// ---------- TEXT / MARKDOWN ----------
//
// `bodyText` is the file content (already a JS string in UTF-8). We render
// markdown for .md/.markdown, otherwise show as a plain <pre>. A "View
// source" toggle flips markdown back to raw. A "Copy" button puts the raw
// text on the clipboard.
function renderText(rec, bodyText, siteName) {
  const ext = (path.extname(rec.original_filename || '') || '').toLowerCase().replace(/^\./, '');
  const isMarkdown = ext === 'md' || ext === 'markdown';

  let renderedHtml = '';
  if (isMarkdown) {
    try {
      renderedHtml = marked.parse(bodyText, { async: false, breaks: false, gfm: true });
    } catch (e) {
      renderedHtml = `<pre>${escHtml(bodyText)}</pre>`;
    }
  }

  // Stash the raw text in a JSON-encoded data attribute so the source/copy
  // buttons can pull from the DOM instead of needing a fetch round-trip.
  // JSON.stringify safely encodes quotes and control characters for HTML.
  const rawJson = JSON.stringify(bodyText);

  return `
    <h1>${escHtml(rec.title || rec.original_filename || 'Text')}</h1>
    <p class="muted">${metaLine(rec)}</p>
    <div class="card text-card">
      ${isMarkdown ? `
        <div class="row" style="margin-bottom: 12px;">
          <button type="button" class="btn btn-secondary" id="md-toggle" data-mode="rendered">View source</button>
          <button type="button" class="btn btn-secondary" id="md-copy">Copy</button>
        </div>
        <div id="md-rendered" class="markdown-body">${renderedHtml}</div>
        <pre id="md-source" class="raw-text" style="display:none;">${escHtml(bodyText)}</pre>
      ` : `
        <div class="row" style="margin-bottom: 12px;">
          <button type="button" class="btn btn-secondary" id="md-copy">Copy</button>
        </div>
        <pre class="raw-text">${escHtml(bodyText)}</pre>
      `}
      ${downloadButton(rec.slug, rec.download_allowed)}
    </div>
    <div class="footer">Shared from ${escHtml(siteName)}</div>
    <script id="raw-text-data" type="application/json">${escHtml(rawJson).replace(/</g, '\\u003c')}</script>
    <script>
      (function () {
        // Read the raw text out of the JSON island. Using JSON parse is
        // safer than embedding a JS string literal — it side-steps tricky
        // escaping of newlines, quotes, and angle brackets inside the file.
        var raw = '';
        try {
          var node = document.getElementById('raw-text-data');
          if (node) raw = JSON.parse(node.textContent.replace(/\\\\u003c/g, '<'));
        } catch (e) { raw = ''; }

        var toggleBtn = document.getElementById('md-toggle');
        var copyBtn = document.getElementById('md-copy');
        var rendered = document.getElementById('md-rendered');
        var source = document.getElementById('md-source');

        if (toggleBtn && rendered && source) {
          toggleBtn.addEventListener('click', function () {
            var mode = toggleBtn.dataset.mode;
            if (mode === 'rendered') {
              rendered.style.display = 'none';
              source.style.display = 'block';
              toggleBtn.textContent = 'View rendered';
              toggleBtn.dataset.mode = 'source';
            } else {
              rendered.style.display = 'block';
              source.style.display = 'none';
              toggleBtn.textContent = 'View source';
              toggleBtn.dataset.mode = 'rendered';
            }
          });
        }

        if (copyBtn) {
          copyBtn.addEventListener('click', async function () {
            try {
              await navigator.clipboard.writeText(raw);
              var prev = copyBtn.textContent;
              copyBtn.textContent = 'Copied!';
              setTimeout(function () { copyBtn.textContent = prev; }, 1500);
            } catch (e) {
              copyBtn.textContent = 'Copy failed';
            }
          });
        }
      })();
    </script>
  `;
}

module.exports = { renderImage, renderVideo, renderAudio, renderPdf, renderText, escHtml, fmtBytes };

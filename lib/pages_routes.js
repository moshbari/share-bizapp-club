// Routes + rendering for "My page" (/@<handle>). Data lives in lib/pages.js.
//
// Kept out of server.js the same way the iOS API is: server.js hands in the
// helpers it already owns (layout, reorder bar, GHL config) so the public
// page and the editor look and behave like the rest of the site.
//
// WORDING: this page is on the same website App Review read when it rejected
// the iOS app over "upgrade / free trial". So nothing here says upgrade,
// unlock, premium or free trial — the email gate says "enter your email to
// open it", which is what it does.

const express = require('express');
const fs = require('node:fs');
const QRCode = require('qrcode');
const { pages, upsertGhlContact } = require('./pages');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const BOT_RE = /bot|crawl|spider|slurp|facebookexternalhit|whatsapp|telegram|slack|discord|preview|embedly|headless|lighthouse/i;
const MAX_BLOCKS = 60;

function attach(app, deps) {
  const {
    db: { users: udb, files: fdb, groups: gdb, messages: mdb, chats: cdb, raw },
    users, ghl, classify, upload, layout, escHtml, reorderBar, REORDER_JS,
    appStoreCta, APPSTORE_CSS, PUBLIC_ORIGIN, SITE_NAME, requireUser, kindEmoji,
  } = deps;

  // ---------- small helpers ----------

  const buckets = new Map();
  /** true when this ip has used up `limit` hits in `windowMs` for `key`. */
  function limited(req, key, limit, windowMs) {
    const id = key + '|' + (req.ip || 'unknown');
    const now = Date.now();
    const arr = (buckets.get(id) || []).filter(t => now - t < windowMs);
    if (arr.length >= limit) { buckets.set(id, arr); return true; }
    arr.push(now);
    buckets.set(id, arr);
    if (buckets.size > 20000) buckets.clear(); // never let this grow unbounded
    return false;
  }

  function viewerIsOwner(req, page) {
    return !!(req.user && req.user.id === page.user_id);
  }

  function pageUrl(page) { return `${PUBLIC_ORIGIN}/@${page.handle}`; }

  const noteForCopyStmt = raw.prepare(`SELECT id, user_id, group_id FROM messages WHERE slug = ?`);
  const allFilesStmt = raw.prepare(`
    SELECT slug, title, original_filename, kind FROM files
    WHERE user_id = ? AND activated = 1 ORDER BY sort_order DESC LIMIT 500
  `);

  /**
   * Resolve what a block points at, as the visitor will see it. Returns null
   * when the thing was deleted or doesn't belong to the page owner — that
   * block is then skipped on the public page and flagged in the editor.
   * (Ownership matters: a block must never be able to publish SOMEONE ELSE's
   * file just because its slug was typed in.)
   */
  function resolveBlock(b, ownerId) {
    switch (b.kind) {
      case 'heading':
        return { dest: '', icon: '', autoTitle: b.title, autoSub: '' };
      case 'link': {
        let host = '';
        try { host = new URL(b.url).hostname.replace(/^www\./, ''); } catch {}
        if (!host) return null;
        return { dest: b.url, external: true, icon: '🔗', autoTitle: host, autoSub: host };
      }
      case 'file': {
        const f = fdb.getBySlug(b.ref_slug);
        if (!f || f.user_id !== ownerId || !f.activated) return null;
        const verb = { video: 'Watch it here', audio: 'Listen here', pdf: 'Read it here', image: 'See it here', text: 'Read it here' }[f.kind] || 'Open it here';
        return { dest: `/f/${f.slug}`, icon: kindEmoji(f.kind), autoTitle: f.title || f.original_filename || 'File', autoSub: verb, kindLabel: f.kind };
      }
      case 'folder': {
        const g = gdb.getBySlug(b.ref_slug);
        if (!g || g.user_id !== ownerId) return null;
        const n = mdb.listInGroup(g.id, ownerId).length;
        return { dest: `/g/${g.slug}`, icon: '📁', autoTitle: g.title || 'Folder', autoSub: `${n} ${n === 1 ? 'note' : 'notes'} you can copy`, group: g, count: n };
      }
      case 'chat': {
        const c = cdb.getBySlug(b.ref_slug);
        if (!c || c.user_id !== ownerId || c.status !== 'ready') return null;
        const items = cdb.items(c.id);
        return {
          dest: `/c/${c.slug}`, icon: '💬', autoTitle: c.title || 'Chat',
          autoSub: `${items.length} screenshot${items.length === 1 ? '' : 's'} · scroll to read`,
          thumb: items[0] ? `/cr/${c.slug}/${items[0].id}` : '',
        };
      }
      default:
        return null;
    }
  }

  function initials(name) {
    const parts = (name || '').trim().split(/\s+/).filter(Boolean);
    return ((parts[0] || '?')[0] + (parts[1] ? parts[1][0] : '')).toUpperCase();
  }

  function avatarHtml(page, cls) {
    return page.avatar_url
      ? `<img class="${cls}" src="/pa/${escHtml(page.handle)}?v=${escHtml(String(page.updated_at || '').replace(/\D/g, ''))}" alt="">`
      : `<span class="${cls} ${cls}-initials" aria-hidden="true">${escHtml(initials(page.display_name || page.handle))}</span>`;
  }

  function ghlStatusFor(owner) {
    const cfg = users.effectiveGhlConfig(owner);
    // The shared env storage belongs to the workspace admin. Only the admin's
    // leads may go there — a starter account's visitors must never land in
    // somebody else's CRM.
    const allowed = cfg.source === 'user' || !!owner.is_admin;
    return { cfg, allowed };
  }

  // ======================================================================
  // PUBLIC PAGE
  // ======================================================================

  const PAGE_CSS = `
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body.pg {
      --bg: #fff7ed; --bg2: #f0fdfa; --fg: #0f172a; --muted: #64748b;
      --card: #ffffff; --card-border: #fed7aa; --accent: #f97316; --accent2: #14b8a6;
      --accent-fg: #fff; --ring: rgba(249,115,22,0.25);
      font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: var(--fg); min-height: 100vh;
      background: linear-gradient(180deg, var(--bg) 0%, var(--bg2) 100%) fixed;
      -webkit-text-size-adjust: 100%;
    }
    body.th-midnight { --bg:#0b1120; --bg2:#111827; --fg:#f1f5f9; --muted:#94a3b8; --card:#1e293b; --card-border:#334155; --accent:#14b8a6; --accent2:#f97316; --ring: rgba(20,184,166,0.3); }
    body.th-mint     { --bg:#ecfdf5; --bg2:#f0fdfa; --fg:#064e3b; --muted:#4b7c6b; --card:#ffffff; --card-border:#a7f3d0; --accent:#0d9488; --accent2:#059669; --ring: rgba(13,148,136,0.25); }
    body.th-mono     { --bg:#fafafa; --bg2:#f4f4f5; --fg:#111111; --muted:#6b7280; --card:#ffffff; --card-border:#e5e7eb; --accent:#111111; --accent2:#374151; --ring: rgba(17,17,17,0.15); }

    .pg-owner-bar { background: #0f172a; color: #e2e8f0; font-size: 14px; padding: 10px 16px; text-align: center; }
    .pg-owner-bar a { color: #5eead4; font-weight: 700; }
    .pg-wrap { max-width: 560px; margin: 0 auto; padding: 36px 16px 40px; }

    .pg-head { text-align: center; margin-bottom: 26px; }
    .pg-avatar { width: 96px; height: 96px; border-radius: 50%; object-fit: cover; display: inline-block;
                 border: 3px solid var(--card); box-shadow: 0 6px 20px rgba(15,23,42,0.18); background: var(--card); }
    .pg-avatar-initials { display: inline-flex; align-items: center; justify-content: center;
                          font-size: 34px; font-weight: 800; color: var(--accent-fg); background: var(--accent); }
    .pg-name { margin: 14px 0 4px; font-size: 26px; line-height: 1.2; font-weight: 800; letter-spacing: -0.02em; word-break: break-word; }
    .pg-handle { margin: 0 0 8px; font-size: 14px; color: var(--muted); }
    .pg-bio { margin: 0 auto; max-width: 440px; font-size: 15px; color: var(--fg); opacity: .85; white-space: pre-line; word-break: break-word; }

    .pg-blocks { display: flex; flex-direction: column; gap: 12px; }
    .pg-section { margin: 14px 4px 0; font-size: 13px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }

    .pg-card {
      display: flex; align-items: center; gap: 14px; width: 100%;
      padding: 14px 16px; min-height: 72px; text-align: left;
      background: var(--card); color: var(--fg); text-decoration: none; font: inherit;
      border: 1.5px solid var(--card-border); border-left: 6px solid var(--accent);
      border-radius: 16px; cursor: pointer;
      box-shadow: 0 1px 2px rgba(15,23,42,0.05);
      transition: transform .12s, box-shadow .12s;
    }
    .pg-card.alt { border-left-color: var(--accent2); }
    .pg-card:hover { transform: translateY(-1px); box-shadow: 0 8px 22px -8px rgba(15,23,42,0.25); }
    .pg-card:active { transform: translateY(1px); }
    .pg-card:focus-visible { outline: none; box-shadow: 0 0 0 4px var(--ring); }
    .pg-ico { flex: 0 0 auto; width: 46px; height: 46px; border-radius: 12px; display: inline-flex; align-items: center; justify-content: center;
              font-size: 24px; background: color-mix(in srgb, var(--accent) 12%, transparent); overflow: hidden; }
    .pg-card.alt .pg-ico { background: color-mix(in srgb, var(--accent2) 12%, transparent); }
    .pg-ico img { width: 100%; height: 100%; object-fit: cover; object-position: top; }
    .pg-txt { flex: 1 1 auto; min-width: 0; }
    .pg-title { display: block; font-size: 16px; font-weight: 700; line-height: 1.3; word-break: break-word; }
    .pg-sub { display: block; font-size: 13px; color: var(--muted); margin-top: 2px; word-break: break-word; }
    .pg-badge { display: inline-block; margin-top: 6px; font-size: 11.5px; font-weight: 700; padding: 3px 9px; border-radius: 99px;
                background: var(--accent); color: var(--accent-fg); }
    .pg-card.alt .pg-badge { background: var(--accent2); }
    .pg-arrow { flex: 0 0 auto; font-size: 20px; color: var(--muted); }

    .pg-empty { text-align: center; color: var(--muted); padding: 30px 10px; }
    .pg-foot { margin-top: 36px; text-align: center; }
    .pg-credit { margin: 14px 0 0; font-size: 12.5px; color: var(--muted); }
    .pg-credit a { color: var(--muted); }
    body.th-midnight .appstore-cta-text { color: #94a3b8; }

    /* the email sheet */
    .pg-back { position: fixed; inset: 0; background: rgba(15,23,42,.55); z-index: 90; }
    .pg-sheet { position: fixed; z-index: 100; left: 50%; bottom: 0; transform: translateX(-50%);
                width: min(480px, 100%); background: #fff; color: #0f172a; border-radius: 18px 18px 0 0;
                padding: 20px 18px calc(18px + env(safe-area-inset-bottom)); box-shadow: 0 -10px 40px rgba(15,23,42,.35); }
    @media (min-width: 640px) { .pg-sheet { bottom: auto; top: 50%; transform: translate(-50%, -50%); border-radius: 18px; } }
    .pg-back[hidden], .pg-sheet[hidden] { display: none; }
    .pg-sheet h2 { margin: 0 34px 4px 0; font-size: 19px; line-height: 1.3; word-break: break-word; }
    .pg-sheet p { margin: 0 0 14px; font-size: 14px; color: #475569; }
    .pg-sheet label { display: block; font-size: 13px; font-weight: 700; margin: 10px 0 5px; }
    .pg-sheet input { width: 100%; font: inherit; font-size: 16px; padding: 12px 13px; border: 1.5px solid #cbd5e1; border-radius: 11px; }
    .pg-sheet input:focus { outline: none; border-color: #0d9488; box-shadow: 0 0 0 3px rgba(13,148,136,.2); }
    .pg-hp { position: absolute !important; left: -9999px !important; width: 1px; height: 1px; opacity: 0; }
    .pg-go { width: 100%; margin-top: 16px; min-height: 52px; border: 0; border-radius: 13px; font: inherit; font-size: 17px; font-weight: 800;
             background: #0d9488; color: #fff; cursor: pointer; }
    .pg-go:disabled { opacity: .6; cursor: default; }
    .pg-err { color: #b91c1c; font-size: 14px; margin: 10px 0 0; min-height: 1em; }
    .pg-fine { font-size: 12px !important; color: #64748b !important; margin: 10px 0 0 !important; text-align: center; }
    .pg-x { position: absolute; top: 14px; right: 14px; width: 32px; height: 32px; border-radius: 50%; border: 0; background: #f1f5f9; cursor: pointer; font-size: 14px; }
  `;

  // Remembers the visitor's email on THIS device so the second gated block on
  // the page is one tap, not a second form. Each block still records its own
  // lead row (and its own GHL tag), because "what did they come for" is the
  // part the owner actually wants to know.
  const PAGE_JS = `
    (function () {
      var handle = document.body.getAttribute('data-handle');
      var KEY = 'szp-page-visitor';
      var back = document.getElementById('pg-back');
      var sheet = document.getElementById('pg-sheet');
      var form = document.getElementById('pg-form');
      var titleEl = document.getElementById('pg-sheet-title');
      var errEl = document.getElementById('pg-err');
      var goBtn = document.getElementById('pg-go');
      var current = null;

      function remembered() {
        try { return JSON.parse(localStorage.getItem(KEY) || 'null'); } catch (e) { return null; }
      }
      function remember(v) {
        try { localStorage.setItem(KEY, JSON.stringify(v)); } catch (e) {}
      }

      async function send(block, email, name, website) {
        var res = await fetch('/api/p/' + encodeURIComponent(handle) + '/lead', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ block: block, email: email, name: name, website: website || '' }),
        });
        var data = {};
        try { data = await res.json(); } catch (e) {}
        if (!res.ok || !data.ok) throw new Error(data.error || 'Something went wrong. Try again.');
        return data;
      }

      function open(card) {
        current = card;
        titleEl.textContent = card.getAttribute('data-title') || '';
        errEl.textContent = '';
        goBtn.disabled = false;
        goBtn.textContent = 'Open it';
        var r = remembered();
        if (r) {
          form.elements.email.value = r.email || '';
          form.elements.name.value = r.name || '';
        }
        back.hidden = false; sheet.hidden = false;
        document.body.style.overflow = 'hidden';
        setTimeout(function () { (form.elements.email.value ? goBtn : form.elements.email).focus(); }, 60);
      }
      function close() {
        back.hidden = true; sheet.hidden = true;
        document.body.style.overflow = '';
      }

      document.addEventListener('click', function (e) {
        var card = e.target.closest('.pg-gated');
        if (!card) return;
        e.preventDefault();
        open(card);
      });
      back.addEventListener('click', close);
      document.getElementById('pg-x').addEventListener('click', close);
      document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !sheet.hidden) close(); });

      form.addEventListener('submit', async function (e) {
        e.preventDefault();
        if (!current) return;
        var email = (form.elements.email.value || '').trim();
        var name = (form.elements.name.value || '').trim();
        if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]{2,}$/.test(email)) {
          errEl.textContent = 'Please type a real email address.';
          form.elements.email.focus();
          return;
        }
        goBtn.disabled = true;
        goBtn.textContent = 'Opening…';
        errEl.textContent = '';
        try {
          var data = await send(current.getAttribute('data-block'), email, name, form.elements.website.value);
          remember({ email: email, name: name });
          close();
          if (data.external) window.open(data.url, '_blank', 'noopener');
          else window.location.href = data.url;
        } catch (err) {
          errEl.textContent = err.message;
          goBtn.disabled = false;
          goBtn.textContent = 'Open it';
        }
      });
    })();
  `;

  function renderPublicPage(page, owner, blocks, { isOwner }) {
    const name = page.display_name || owner.name || page.handle;
    let visible = 0;
    let n = 0;
    const cards = blocks.map((b) => {
      if (b.hidden) return '';
      const r = resolveBlock(b, owner.id);
      if (!r) return '';
      if (b.kind === 'heading') {
        return b.title ? `<h2 class="pg-section">${escHtml(b.title)}</h2>` : '';
      }
      visible++;
      const alt = (n++ % 2) === 1 ? ' alt' : '';
      const title = b.title || r.autoTitle;
      const sub = b.subtitle || r.autoSub;
      const ico = r.thumb ? `<img src="${escHtml(r.thumb)}" alt="" loading="lazy">` : escHtml(r.icon);
      const inner = `
        <span class="pg-ico">${ico}</span>
        <span class="pg-txt">
          <span class="pg-title">${escHtml(title)}</span>
          ${sub ? `<span class="pg-sub">${escHtml(sub)}</span>` : ''}
          ${b.gated ? `<span class="pg-badge">✉️ Enter your email to open</span>` : ''}
        </span>
        <span class="pg-arrow" aria-hidden="true">›</span>`;
      if (b.gated) {
        // No destination anywhere in the markup — the link only comes back
        // from the server once an email is given.
        return `<button type="button" class="pg-card pg-gated${alt}" data-block="${escHtml(b.slug)}" data-title="${escHtml(title)}">${inner}</button>`;
      }
      const ext = r.external ? ' target="_blank" rel="noopener nofollow"' : '';
      return `<a class="pg-card${alt}" href="/go/${escHtml(b.slug)}"${ext}>${inner}</a>`;
    }).join('');

    const desc = page.bio || `${name} on ${SITE_NAME}`;
    const ogImg = page.avatar_url ? `${PUBLIC_ORIGIN}/pa/${page.handle}` : '';
    const indexable = page.published && !isOwner;

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escHtml(name)} (@${escHtml(page.handle)})</title>
  ${indexable ? '' : '<meta name="robots" content="noindex,nofollow">'}
  <link rel="canonical" href="${escHtml(pageUrl(page))}">
  <meta name="description" content="${escHtml(desc)}">
  <meta property="og:site_name" content="${escHtml(SITE_NAME)}">
  <meta property="og:type" content="profile">
  <meta property="og:title" content="${escHtml(name)}">
  <meta property="og:description" content="${escHtml(desc)}">
  <meta property="og:url" content="${escHtml(pageUrl(page))}">
  ${ogImg ? `<meta property="og:image" content="${escHtml(ogImg)}">` : ''}
  <meta name="twitter:card" content="summary">
  <style>${PAGE_CSS}${APPSTORE_CSS}</style>
</head>
<body class="pg th-${escHtml(page.theme)}" data-handle="${escHtml(page.handle)}">
  ${isOwner ? `<div class="pg-owner-bar">${page.published ? 'This is your page — visitors see exactly this.' : '🙈 Your page is switched OFF — only you can see it.'} <a href="/page">Edit it →</a></div>` : ''}
  <main class="pg-wrap">
    <header class="pg-head">
      ${avatarHtml(page, 'pg-avatar')}
      <h1 class="pg-name">${escHtml(name)}</h1>
      <p class="pg-handle">@${escHtml(page.handle)}</p>
      ${page.bio ? `<p class="pg-bio">${escHtml(page.bio)}</p>` : ''}
    </header>

    <section class="pg-blocks">
      ${visible ? cards : `<div class="pg-empty">${isOwner ? 'Nothing here yet — add your first block in the editor.' : 'Nothing here yet. Check back soon.'}</div>`}
    </section>

    <footer class="pg-foot">
      ${appStoreCta({ text: 'Make a page like this with ShareZPresso.' })}
      <p class="pg-credit">Made with <a href="/" target="_blank" rel="noopener">${escHtml(SITE_NAME)}</a></p>
    </footer>
  </main>

  <div class="pg-back" id="pg-back" hidden></div>
  <div class="pg-sheet" id="pg-sheet" hidden role="dialog" aria-modal="true" aria-labelledby="pg-sheet-title">
    <button type="button" class="pg-x" id="pg-x" aria-label="Close">✕</button>
    <h2 id="pg-sheet-title"></h2>
    <p>Enter your email and it opens straight away.</p>
    <form id="pg-form" novalidate>
      <label for="pg-email">Your email</label>
      <input id="pg-email" name="email" type="email" inputmode="email" autocomplete="email" placeholder="you@example.com" required>
      <label for="pg-name">Your first name <span style="font-weight:400;color:#64748b;">(optional)</span></label>
      <input id="pg-name" name="name" type="text" autocomplete="given-name" maxlength="80">
      <input class="pg-hp" name="website" type="text" tabindex="-1" autocomplete="off" aria-hidden="true">
      <button type="submit" class="pg-go" id="pg-go">Open it</button>
      <p class="pg-err" id="pg-err" role="alert"></p>
      <p class="pg-fine">Your email goes to ${escHtml(name)} only.</p>
    </form>
  </div>
  <script>${PAGE_JS}</script>
</body>
</html>`;
  }

  function notFoundPage(req, msg) {
    return layout({ title: 'Not found', user: req.user, body: `<h1>Not found</h1><p>${escHtml(msg)}</p>` });
  }

  app.get('/@:handle', (req, res) => {
    const page = pages.getByHandle(req.params.handle);
    if (!page) return res.status(404).send(notFoundPage(req, 'There is no page with that name.'));
    // Always serve the lowercase spelling so links and stats don't split.
    if (req.params.handle !== page.handle) return res.redirect(301, `/@${page.handle}`);
    const owner = udb.getById(page.user_id);
    const isOwner = viewerIsOwner(req, page);
    if (!owner || owner.status === 'deactivated' || (!page.published && !isOwner)) {
      return res.status(404).send(notFoundPage(req, 'This page is not public right now.'));
    }
    if (!isOwner && !BOT_RE.test(req.get('user-agent') || '')) pages.bump(page.id, 0, 'view');
    res.set('Cache-Control', 'private, max-age=0');
    res.send(renderPublicPage(page, owner, pages.blocks(page.id), { isOwner }));
  });

  // Some chat apps mangle "@" in a link, so /p/<handle> is the safe spelling.
  app.get('/p/:handle', (req, res) => res.redirect(302, `/@${encodeURIComponent(req.params.handle)}`));

  // Every non-gated card goes through here, so a tap is counted before the
  // visitor lands on the file, folder, chat or outside link.
  app.get('/go/:slug', (req, res) => {
    const b = pages.blockBySlug(req.params.slug);
    if (!b) return res.status(404).send(notFoundPage(req, 'This link was removed.'));
    const page = raw.prepare('SELECT * FROM pages WHERE id = ?').get(b.page_id);
    if (!page) return res.status(404).send(notFoundPage(req, 'This link was removed.'));
    if (b.gated || b.hidden || b.kind === 'heading') return res.redirect(302, `/@${page.handle}`);
    const r = resolveBlock(b, page.user_id);
    if (!r || !r.dest) return res.redirect(302, `/@${page.handle}`);
    if (!viewerIsOwner(req, page) && !BOT_RE.test(req.get('user-agent') || '')) pages.bump(page.id, b.id, 'click');
    res.redirect(302, r.dest);
  });

  // The profile picture, proxied so the storage URL never shows in the page.
  app.get('/pa/:handle', async (req, res) => {
    const page = pages.getByHandle(req.params.handle);
    if (!page || !page.avatar_url) return res.status(404).send('Not found');
    try {
      const upstream = await fetch(page.avatar_url);
      if (!upstream.ok || !upstream.body) return res.status(502).send('Upstream error');
      res.set('Content-Type', upstream.headers.get('content-type') || 'image/jpeg');
      res.set('Cache-Control', 'public, max-age=86400');
      const { Readable } = require('node:stream');
      Readable.fromWeb(upstream.body).pipe(res);
    } catch (err) {
      console.error('[page-avatar]', err.message);
      res.status(502).send('Stream failed');
    }
  });

  app.post('/api/p/:handle/lead', express.json({ limit: '8kb' }), async (req, res) => {
    const page = pages.getByHandle(req.params.handle);
    if (!page || !page.published) return res.status(404).json({ ok: false, error: 'This page is not available.' });
    const b = pages.blockBySlug((req.body && req.body.block) || '');
    if (!b || b.page_id !== page.id || b.hidden || !b.gated) {
      return res.status(404).json({ ok: false, error: 'That item was removed. Reload the page.' });
    }
    const owner = udb.getById(page.user_id);
    const r = owner && owner.status !== 'deactivated' ? resolveBlock(b, owner.id) : null;
    if (!r || !r.dest) return res.status(404).json({ ok: false, error: 'That item was removed. Reload the page.' });

    const email = ((req.body.email || '') + '').trim().toLowerCase().slice(0, 200);
    const name = ((req.body.name || '') + '').trim().slice(0, 80);
    if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'Please type a real email address.' });

    const payload = { ok: true, url: r.dest, external: !!r.external };
    // A bot fills every field it finds, including the invisible one. Give it
    // the same answer a person gets, and record nothing.
    if (req.body.website) return res.json(payload);
    if (limited(req, 'lead', 20, 10 * 60 * 1000)) {
      return res.status(429).json({ ok: false, error: 'Too many tries from this connection. Wait a few minutes.' });
    }

    // Every open is a tap, whether or not this email is new.
    pages.bump(page.id, b.id, 'click');
    const lead = pages.addLead(page, b, { email, name, title: b.title || r.autoTitle });
    if (lead) {
      pages.bump(page.id, b.id, 'lead');
      const { cfg, allowed } = ghlStatusFor(owner);
      if (!allowed) {
        pages.setLeadGhlStatus(lead.id, 'not connected');
      } else {
        // Don't make the visitor wait on the CRM — they came for the item.
        upsertGhlContact(cfg, {
          email, name,
          source: `ShareZPresso page @${page.handle}`,
          tags: ['sharezpresso-page', `page-${page.handle}`, `opened: ${(b.title || r.autoTitle || '').slice(0, 60)}`],
        }).then((out) => {
          pages.setLeadGhlStatus(lead.id, out.ok ? 'sent' : `failed — ${out.error}`);
          if (!out.ok) console.warn(`[page-lead] GHL push failed for page ${page.handle}: ${out.error}`);
        });
      }
    }
    res.json(payload);
  });

  // Copy counts on folder pages (/g/<slug>). Fired by sendBeacon, so it never
  // slows the Copy button down; the answer is ignored.
  app.post('/api/note-copied/:slug', (req, res) => {
    if (limited(req, 'copy', 120, 10 * 60 * 1000)) return res.status(204).end();
    // messages.getBySlug doesn't select group_id, hence the direct query.
    const m = noteForCopyStmt.get(String(req.params.slug || ''));
    if (m && m.group_id && !(req.user && req.user.id === m.user_id)) pages.bumpNoteCopy(m.id);
    res.status(204).end();
  });

  // ======================================================================
  // OWNER EDITOR
  // ======================================================================

  function ensurePage(user) {
    return pages.getByUser(user.id) || pages.create(user);
  }

  const EDITOR_CSS = `
    .pe-head h1 { margin-bottom: 4px; }
    .pe-link { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
    .pe-link-main { flex: 1 1 280px; min-width: 0; }
    .pe-qr { flex: 0 0 auto; text-align: center; }
    .pe-qr img { width: 132px; height: 132px; display: block; border: 1px solid var(--border); border-radius: 10px; background: #fff; }
    .pe-qr a { font-size: 13px; }
    .pe-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 0 0 16px; }
    .pe-stat { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 12px; text-align: center; }
    .pe-stat b { display: block; font-size: 26px; line-height: 1.1; }
    .pe-stat span { font-size: 12.5px; color: var(--muted); }
    .pe-avatar-row { display: flex; align-items: center; gap: 14px; }
    .pe-avatar { width: 64px; height: 64px; border-radius: 50%; object-fit: cover; flex: 0 0 auto; background: #e2e8f0; }
    .pe-avatar-initials { display: inline-flex; align-items: center; justify-content: center; font-weight: 800; font-size: 22px; color: #fff; background: #f97316; }
    .pe-handle { display: flex; align-items: stretch; }
    .pe-handle span { display: inline-flex; align-items: center; padding: 0 10px; background: #f1f5f9; border: 1px solid var(--border); border-right: 0; border-radius: 10px 0 0 10px; color: var(--muted); font-size: 14px; white-space: nowrap; }
    .pe-handle input { border-radius: 0 10px 10px 0 !important; }
    textarea.pe-bio { width: 100%; min-height: 76px; padding: 12px 14px; font: inherit; font-size: 15px; border: 1px solid var(--border); border-radius: 10px; resize: vertical; }
    .pe-themes { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
    .pe-theme { position: relative; display: flex; align-items: center; gap: 8px; padding: 10px; border: 2px solid var(--border); border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 14px; margin: 0; }
    .pe-theme input { position: absolute; opacity: 0; }
    .pe-theme:has(input:checked) { border-color: var(--brand); background: #eff6ff; }
    .pe-swatch { width: 22px; height: 22px; border-radius: 6px; flex: 0 0 auto; border: 1px solid rgba(0,0,0,.1); }
    .block-card { padding: 20px; }
    .block-top { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
    .block-ico { font-size: 22px; }
    .block-kind { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
    .block-dest { font-size: 13px; color: var(--muted); word-break: break-all; }
    .block-missing { color: var(--err); font-weight: 600; font-size: 14px; }
    .block-fields { display: grid; gap: 8px; }
    .block-fields input[type=text], .block-fields input[type=url] { padding: 10px 12px; font-size: 15px; }
    .block-stats { font-size: 13px; color: var(--muted); margin-top: 8px; }
    .block-top-copied { font-size: 13px; margin-top: 4px; }
    .block-hidden { opacity: .6; }
    .pe-kinds { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
    .pe-panel[hidden] { display: none; }
    .pe-panel select { width: 100%; padding: 12px; font-size: 15px; border: 1px solid var(--border); border-radius: 10px; background: #fff; }
    table.pe-leads { width: 100%; border-collapse: collapse; font-size: 14px; }
    table.pe-leads th, table.pe-leads td { padding: 9px 8px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
    table.pe-leads th { font-size: 12px; text-transform: uppercase; color: var(--muted); letter-spacing: .04em; }
    .pe-table-wrap { overflow-x: auto; }
    .pe-ghl-ok { color: var(--ok); } .pe-ghl-bad { color: var(--err); }
    @media (max-width: 480px) { .pe-stat b { font-size: 21px; } }
  `;

  const EDITOR_JS = `
    (function () {
      function toast(msg, bad) {
        var t = document.createElement('div');
        t.className = 'reorder-toast on' + (bad ? ' err' : '');
        t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(function () { t.remove(); }, bad ? 3200 : 1500);
      }
      async function post(url, body) {
        var res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}), credentials: 'same-origin' });
        var data = {};
        try { data = await res.json(); } catch (e) {}
        if (!res.ok || !data.ok) throw new Error(data.error || ('HTTP ' + res.status));
        return data;
      }
      async function copy(text) {
        try { await navigator.clipboard.writeText(text); return true; } catch (e) {}
        try {
          var ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.top = '-1000px';
          document.body.appendChild(ta); ta.select(); var ok = document.execCommand('copy'); ta.remove(); return ok;
        } catch (e) { return false; }
      }

      var list = document.getElementById('block-list');
      if (list && window.__initReorder) {
        window.__initReorder({ container: '#block-list', itemSelector: '.block-card', endpoint: '/api/page/blocks/reorder' });
      }

      document.addEventListener('click', async function (e) {
        var cp = e.target.closest('.pe-copy-link');
        if (cp) {
          var ok = await copy(cp.dataset.url);
          toast(ok ? 'Link copied' : 'Copy failed — long-press the link', !ok);
          return;
        }
        var sh = e.target.closest('.pe-share');
        if (sh) {
          if (navigator.share) { try { await navigator.share({ url: sh.dataset.url }); } catch (err) {} }
          else { var ok2 = await copy(sh.dataset.url); toast(ok2 ? 'Link copied' : 'Copy failed', !ok2); }
          return;
        }
        var kindBtn = e.target.closest('.pe-kind');
        if (kindBtn) {
          document.querySelectorAll('.pe-kind').forEach(function (b) { b.classList.toggle('is-active', b === kindBtn); });
          document.querySelectorAll('.pe-panel').forEach(function (p) { p.hidden = p.dataset.kind !== kindBtn.dataset.kind; });
          document.getElementById('add-kind').value = kindBtn.dataset.kind;
          document.getElementById('add-gate-row').hidden = kindBtn.dataset.kind === 'heading';
          return;
        }
        var save = e.target.closest('.block-save');
        if (save) {
          var card = save.closest('.block-card');
          var body = {};
          card.querySelectorAll('[data-field]').forEach(function (el) {
            body[el.dataset.field] = el.type === 'checkbox' ? el.checked : el.value;
          });
          save.disabled = true;
          try {
            await post('/api/page/blocks/' + encodeURIComponent(card.dataset.slug), body);
            toast('Saved');
            card.classList.toggle('block-hidden', !!body.hidden);
          } catch (err) { toast(err.message, true); }
          save.disabled = false;
          return;
        }
        var del = e.target.closest('.block-delete');
        if (del) {
          var c = del.closest('.block-card');
          window.__confirmDelete({
            title: 'Remove this block?',
            message: 'It comes off your page. The file, folder or chat itself is NOT deleted.',
            okText: 'Remove from page',
            then: async function () {
              try { await post('/api/page/blocks/' + encodeURIComponent(c.dataset.slug) + '/delete'); c.remove(); toast('Removed'); }
              catch (err) { toast(err.message, true); }
            },
          });
          return;
        }
      });

      // Any change to a block's fields lights up its Save button, so it is
      // obvious an edit hasn't been saved yet.
      document.addEventListener('input', function (e) {
        var card = e.target.closest('.block-card');
        if (card) { var s = card.querySelector('.block-save'); if (s) s.classList.remove('btn-secondary'); }
      });
      document.addEventListener('change', function (e) {
        var card = e.target.closest('.block-card');
        if (card) { var s = card.querySelector('.block-save'); if (s) s.classList.remove('btn-secondary'); }
      });

      var addForm = document.getElementById('add-form');
      if (addForm) addForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        var kind = document.getElementById('add-kind').value;
        var panel = document.querySelector('.pe-panel[data-kind="' + kind + '"]');
        var body = { kind: kind, gated: document.getElementById('add-gated').checked };
        panel.querySelectorAll('[name]').forEach(function (el) { body[el.name] = el.value; });
        var btn = addForm.querySelector('button[type=submit]');
        btn.disabled = true;
        try {
          await post('/api/page/blocks', body);
          window.location.href = '/page?added=1#blocks';
        } catch (err) { toast(err.message, true); btn.disabled = false; }
      });

      var av = document.getElementById('avatar-input');
      if (av) av.addEventListener('change', function () { if (av.files.length) av.form.submit(); });
    })();
  `;

  const THEME_SWATCH = {
    sunrise: 'linear-gradient(135deg,#f97316 50%,#14b8a6 50%)',
    midnight: 'linear-gradient(135deg,#0b1120 50%,#14b8a6 50%)',
    mint: 'linear-gradient(135deg,#ecfdf5 50%,#0d9488 50%)',
    mono: 'linear-gradient(135deg,#ffffff 50%,#111111 50%)',
  };

  const KIND_META = {
    file:    { icon: '📎', label: 'File' },
    folder:  { icon: '📁', label: 'Folder of notes' },
    chat:    { icon: '💬', label: 'Chat scroll' },
    link:    { icon: '🔗', label: 'Link' },
    heading: { icon: '🔤', label: 'Section title' },
  };

  function renderBlockCard(b, owner, totals) {
    const meta = KIND_META[b.kind] || { icon: '▫️', label: b.kind };
    const r = resolveBlock(b, owner.id);
    const st = totals.blocks[b.id] || {};
    const isHeading = b.kind === 'heading';

    let dest = '';
    if (r && r.dest) {
      dest = b.kind === 'link'
        ? `<a href="${escHtml(r.dest)}" target="_blank" rel="noopener">${escHtml(r.dest)}</a>`
        : `<a href="${escHtml(r.dest)}" target="_blank" rel="noopener">${escHtml(PUBLIC_ORIGIN + r.dest)}</a>`;
    }

    let copied = '';
    if (r && r.group) {
      const top = pages.copiesInGroup(r.group.id, 30).filter(x => x.n > 0).slice(0, 3);
      copied = top.length
        ? `<div class="block-top-copied">🔥 Most copied: ${top.map(x => `<strong>${escHtml(x.title || '(untitled)')}</strong> (${x.n})`).join(' · ')}</div>`
        : `<div class="block-top-copied muted">No copies yet in the last 30 days.</div>`;
    }

    return `
      <div class="card block-card reorder-item${b.hidden ? ' block-hidden' : ''}" data-slug="${escHtml(b.slug)}">
        ${reorderBar('Drag to move it up or down your page')}
        <div class="block-top">
          <span class="block-ico">${r && r.icon ? escHtml(r.icon) : meta.icon}</span>
          <div style="min-width:0;">
            <div class="block-kind">${escHtml(meta.label)}</div>
            ${r ? `<div class="block-dest">${dest || (isHeading ? 'Shows as a small title between blocks' : '')}</div>`
                : `<div class="block-missing">⚠️ The ${escHtml(b.kind)} this pointed to was deleted — visitors don't see this block. Remove it.</div>`}
          </div>
        </div>
        <div class="block-fields">
          <input type="text" data-field="title" maxlength="120" value="${escHtml(b.title)}" placeholder="${escHtml(isHeading ? 'Section title' : (r ? r.autoTitle : 'Title'))}" aria-label="Title">
          ${isHeading ? '' : `<input type="text" data-field="subtitle" maxlength="200" value="${escHtml(b.subtitle)}" placeholder="${escHtml(r ? (r.autoSub || 'Short line under the title') : 'Short line under the title')}" aria-label="Line under the title">`}
          ${b.kind === 'link' ? `<input type="url" data-field="url" maxlength="2000" value="${escHtml(b.url)}" placeholder="https://…" aria-label="Link address">` : ''}
          ${isHeading ? '' : `
            <label class="checkbox-row"><input type="checkbox" data-field="gated"${b.gated ? ' checked' : ''}>
              <span>Ask for their email before it opens<span class="hint">You get their email; they get the item straight away.</span></span></label>`}
          <label class="checkbox-row"><input type="checkbox" data-field="hidden"${b.hidden ? ' checked' : ''}>
            <span>Hide it from my page for now</span></label>
        </div>
        ${isHeading ? '' : `<div class="block-stats">Last 30 days: <strong>${st.click || 0}</strong> tap${(st.click || 0) === 1 ? '' : 's'} · <strong>${st.lead || 0}</strong> email${(st.lead || 0) === 1 ? '' : 's'} given</div>`}
        ${copied}
        <div class="row" style="margin-top:12px;">
          <button type="button" class="btn btn-secondary block-save">Save</button>
          <button type="button" class="btn btn-danger block-delete">Remove</button>
        </div>
      </div>
    `;
  }

  app.get('/page', requireUser, (req, res) => {
    const owner = udb.getById(req.user.id);
    const page = ensurePage(owner);
    const blocks = pages.blocks(page.id);
    const totals = pages.totals(page.id, 30);
    const url = pageUrl(page);
    const clicks = Object.values(totals.blocks).reduce((s, x) => s + (x.click || 0), 0);
    const leads = pages.leads(page.id, 100);
    const leadCount = pages.leadCount(page.id);
    const { allowed: ghlOn } = ghlStatusFor(owner);

    const err = (req.query.err || '').toString().slice(0, 300);
    const ok = req.query.saved ? 'Saved.' : req.query.pic ? 'New picture is up.' : req.query.added ? 'Block added to the bottom of your page.' : '';

    // Preselect "add block" from the ➕ buttons on the folder / file lists.
    const preKind = pages.KINDS.includes(req.query.add) ? req.query.add : 'file';
    const preRef = (req.query.ref || '').toString();

    const myFiles = allFilesStmt.all(owner.id);
    const myFolders = gdb.listForUser(owner.id, { limit: 200 });
    const myChats = cdb.listByUser(owner.id, { limit: 100 });

    const opt = (value, label, sel) => `<option value="${escHtml(value)}"${sel ? ' selected' : ''}>${escHtml(label)}</option>`;
    const fileOpts = myFiles.map(f => opt(f.slug, `${kindEmoji(f.kind)} ${f.title || f.original_filename}`, preKind === 'file' && f.slug === preRef)).join('');
    const folderOpts = myFolders.map(g => opt(g.slug, `📁 ${g.title || '(untitled folder)'}`, preKind === 'folder' && g.slug === preRef)).join('');
    const chatOpts = myChats.map(c => opt(c.slug, `💬 ${c.title || 'Untitled chat'} (${c.item_count})`, preKind === 'chat' && c.slug === preRef)).join('');
    const emptySel = (what, where) => `<p class="muted" style="margin:0;">You have no ${what} yet — <a href="${where}">make one first</a>.</p>`;

    const themeChoices = Object.entries(pages.THEMES).map(([k, t]) => `
      <label class="pe-theme"><input type="radio" name="theme" value="${k}"${page.theme === k ? ' checked' : ''}>
        <span class="pe-swatch" style="background:${THEME_SWATCH[k]}"></span>${escHtml(t.label)}</label>`).join('');

    const leadRows = leads.map(l => {
      const g = l.ghl_status || '';
      const gCls = g === 'sent' ? 'pe-ghl-ok' : g.startsWith('failed') ? 'pe-ghl-bad' : 'muted';
      return `<tr>
        <td style="white-space:nowrap;">${escHtml((l.created_at || '').slice(0, 10))}</td>
        <td>${escHtml(l.name || '—')}</td>
        <td style="word-break:break-all;">${escHtml(l.email)}</td>
        <td>${escHtml(l.block_title || '—')}</td>
        <td class="${gCls}" style="font-size:12.5px;">${escHtml(g || '—')}</td>
      </tr>`;
    }).join('');

    const body = `
      <div class="pe-head">
        <h1>My page</h1>
        <p class="muted">One link for your bio. Put your videos, prompt folders, chat scrolls and links on it — people open them right there, and you can ask for their email first.</p>
      </div>
      ${ok ? `<p class="ok"><strong>✓ ${escHtml(ok)}</strong></p>` : ''}
      ${err ? `<p class="err"><strong>${escHtml(err)}</strong></p>` : ''}

      <div class="card pe-link">
        <div class="pe-link-main stack">
          <div><strong>${page.published ? '🟢 Your page is live' : '🙈 Your page is switched off'}</strong></div>
          <div class="link-box">${escHtml(url)}</div>
          <div class="row">
            <button type="button" class="btn pe-copy-link" data-url="${escHtml(url)}">Copy link</button>
            <a class="btn btn-secondary" href="/@${escHtml(page.handle)}" target="_blank" rel="noopener">Open my page</a>
            <button type="button" class="btn btn-secondary pe-share" data-url="${escHtml(url)}">Share</button>
          </div>
        </div>
        <div class="pe-qr">
          <img src="/page/qr.svg?h=${escHtml(page.handle)}" alt="QR code for your page" width="132" height="132">
          <a href="/page/qr.svg?h=${escHtml(page.handle)}&download=1">Download QR</a>
        </div>
      </div>

      <div class="pe-stats">
        <div class="pe-stat"><b>${totals.page.view || 0}</b><span>visits · 30 days</span></div>
        <div class="pe-stat"><b>${clicks}</b><span>taps · 30 days</span></div>
        <div class="pe-stat"><b>${leadCount}</b><span>emails collected</span></div>
      </div>

      <h2>Your profile</h2>
      <form class="card stack" method="POST" action="/page/avatar" enctype="multipart/form-data">
        <div class="pe-avatar-row">
          ${avatarHtml(page, 'pe-avatar')}
          <div>
            <label for="avatar-input" class="btn btn-secondary btn-sm" style="margin:0; display:inline-block;">${page.avatar_url ? 'Change picture' : 'Add a picture'}</label>
            <input id="avatar-input" type="file" name="file" accept="image/*" hidden>
            <div class="muted" style="font-size:12.5px; margin-top:4px;">A square photo of your face works best.</div>
          </div>
        </div>
      </form>
      <form class="card stack" method="POST" action="/page/profile">
        <div>
          <label for="pe-name">Name on the page</label>
          <input id="pe-name" name="display_name" type="text" maxlength="80" value="${escHtml(page.display_name)}" placeholder="${escHtml(owner.name || 'Your name')}">
        </div>
        <div>
          <label for="pe-h">Your page address</label>
          <div class="pe-handle"><span>${escHtml(PUBLIC_ORIGIN.replace(/^https?:\/\//, ''))}/@</span>
            <input id="pe-h" name="handle" type="text" maxlength="30" required value="${escHtml(page.handle)}" autocapitalize="none" autocorrect="off" spellcheck="false"></div>
          <div class="muted" style="font-size:12.5px; margin-top:4px;">Changing this changes your link — old links stop working.</div>
        </div>
        <div>
          <label for="pe-bio">Short bio</label>
          <textarea id="pe-bio" class="pe-bio" name="bio" maxlength="300" placeholder="Who you help and what they'll find here.">${escHtml(page.bio)}</textarea>
        </div>
        <div>
          <label>Colours</label>
          <div class="pe-themes">${themeChoices}</div>
        </div>
        <label class="checkbox-row"><input type="checkbox" name="published" value="1"${page.published ? ' checked' : ''}>
          <span>Page is live<span class="hint">Untick to hide the whole page while you build it.</span></span></label>
        <button type="submit" class="btn btn-block">Save profile</button>
      </form>

      <h2 id="blocks">Your blocks</h2>
      ${blocks.length
        ? `<div id="block-list" class="reorder-list">${blocks.map(b => renderBlockCard(b, owner, totals)).join('')}</div>`
        : `<div class="recent-empty">No blocks yet — add your first one below.</div>`}

      <h2>Add a block</h2>
      <form class="card stack" id="add-form">
        <input type="hidden" id="add-kind" value="${preKind}">
        <div class="pe-kinds">
          ${pages.KINDS.map(k => `<button type="button" class="chip-btn pe-kind${k === preKind ? ' is-active' : ''}" data-kind="${k}">${KIND_META[k].icon} ${escHtml(KIND_META[k].label)}</button>`).join('')}
        </div>
        <div class="pe-panel" data-kind="file"${preKind === 'file' ? '' : ' hidden'}>
          ${myFiles.length ? `<label for="add-file">Pick a file</label><select id="add-file" name="ref_slug">${fileOpts}</select>` : emptySel('files', '/upload')}
        </div>
        <div class="pe-panel" data-kind="folder"${preKind === 'folder' ? '' : ' hidden'}>
          ${myFolders.length ? `<label for="add-folder">Pick a folder of notes</label><select id="add-folder" name="ref_slug">${folderOpts}</select>` : emptySel('folders', '/messages')}
        </div>
        <div class="pe-panel" data-kind="chat"${preKind === 'chat' ? '' : ' hidden'}>
          ${myChats.length ? `<label for="add-chat">Pick a chat scroll</label><select id="add-chat" name="ref_slug">${chatOpts}</select>` : emptySel('chat scrolls', '/chats/new')}
        </div>
        <div class="pe-panel stack" data-kind="link"${preKind === 'link' ? '' : ' hidden'}>
          <div><label for="add-url">Link address</label><input id="add-url" name="url" type="text" inputmode="url" placeholder="https://…"></div>
          <div><label for="add-link-title">Button text</label><input id="add-link-title" name="title" type="text" maxlength="120" placeholder="e.g. Book a call with me"></div>
        </div>
        <div class="pe-panel" data-kind="heading"${preKind === 'heading' ? '' : ' hidden'}>
          <label for="add-heading">Section title</label><input id="add-heading" name="title" type="text" maxlength="120" placeholder="e.g. Free prompts">
        </div>
        <label class="checkbox-row" id="add-gate-row"${preKind === 'heading' ? ' hidden' : ''}><input type="checkbox" id="add-gated">
          <span>Ask for their email before it opens</span></label>
        <button type="submit" class="btn btn-block">➕ Add to my page</button>
      </form>

      <h2 id="leads">Emails collected</h2>
      <div class="card stack">
        <p class="muted" style="margin:0; font-size:14px;">
          ${ghlOn
            ? 'Every new email is also added to your GoHighLevel as a contact, tagged <strong>sharezpresso-page</strong> plus what they opened — build a follow-up workflow off that tag.'
            : 'Emails are saved here. To also send them into your own GoHighLevel, connect it on the <a href="/account">Account</a> page.'}
        </p>
        ${leads.length
          ? `<div class="pe-table-wrap"><table class="pe-leads"><thead><tr><th>Date</th><th>Name</th><th>Email</th><th>Opened</th><th>GoHighLevel</th></tr></thead><tbody>${leadRows}</tbody></table></div>
             <a class="btn btn-secondary" href="/page/leads.csv">⬇ Download all as a spreadsheet (CSV)</a>`
          : `<div class="recent-empty" style="padding:16px;">No emails yet. Tick “Ask for their email before it opens” on a block to start collecting.</div>`}
      </div>

      <style>${EDITOR_CSS}</style>
      <script src="/vendor/sortable.min.js" defer></script>
      <script>${REORDER_JS}</script>
      <script>${EDITOR_JS}</script>
    `;

    res.send(layout({ title: 'My page — ' + SITE_NAME, user: req.user, body }));
  });

  app.post('/page/profile', requireUser, express.urlencoded({ extended: false, limit: '32kb' }), (req, res) => {
    const page = ensurePage(udb.getById(req.user.id));
    const problem = pages.updateProfile(page, {
      handle: req.body.handle,
      display_name: req.body.display_name,
      bio: req.body.bio,
      theme: req.body.theme,
      published: req.body.published === '1',
    });
    if (problem) return res.redirect('/page?err=' + encodeURIComponent(problem));
    res.redirect('/page?saved=1');
  });

  app.post('/page/avatar', requireUser, upload.single('file'), (req, res) => {
    const file = req.file;
    try {
      if (!file) throw new Error('Pick a picture first.');
      const cls = classify.classify(file.originalname, file.mimetype);
      if (cls.kind !== 'image') throw new Error('That is not a picture — use a JPG, PNG or WebP.');
      if (file.size > 8 * 1024 * 1024) throw new Error('That picture is too big — keep it under 8 MB.');
      const owner = udb.getById(req.user.id);
      const page = ensurePage(owner);
      const cfg = users.effectiveGhlConfig(owner);
      const url = ghl.uploadToGhl(file.path, `page-avatar-${page.handle}-${Date.now()}.${cls.ghlExt}`, cls.ghlMime, cfg);
      const old = page.avatar_url;
      pages.setAvatar(page.id, url);
      if (old) ghl.tryDeleteFromGhl(old, cfg);
      res.redirect('/page?pic=1');
    } catch (err) {
      console.error('[page-avatar] upload failed:', err.message);
      const msg = /^\[GHL\]/.test(err.message) ? 'The picture could not be stored right now. Try again in a minute.' : err.message;
      res.redirect('/page?err=' + encodeURIComponent(msg));
    } finally {
      if (file) { try { fs.unlinkSync(file.path); } catch {} }
    }
  });

  app.post('/api/page/blocks', requireUser, express.json({ limit: '16kb' }), (req, res) => {
    const owner = udb.getById(req.user.id);
    const page = ensurePage(owner);
    const b = req.body || {};
    const kind = (b.kind || '').toString();
    if (!pages.KINDS.includes(kind)) return res.status(400).json({ ok: false, error: 'Pick what kind of block to add.' });
    if (pages.countBlocks(page.id) >= MAX_BLOCKS) return res.status(400).json({ ok: false, error: `A page can hold ${MAX_BLOCKS} blocks.` });

    const fields = { kind, gated: !!b.gated && kind !== 'heading' };
    if (kind === 'file' || kind === 'folder' || kind === 'chat') {
      fields.ref_slug = (b.ref_slug || '').toString();
      if (!resolveBlock({ kind, ref_slug: fields.ref_slug }, owner.id)) {
        return res.status(400).json({ ok: false, error: `Pick one of your own ${kind === 'chat' ? 'chat scrolls' : kind + 's'}.` });
      }
    } else if (kind === 'link') {
      let u = (b.url || '').toString().trim();
      if (u && !/^https?:\/\//i.test(u)) u = 'https://' + u;
      let parsed = null;
      try { parsed = new URL(u); } catch {}
      if (!parsed || !/^https?:$/.test(parsed.protocol) || !parsed.hostname.includes('.')) {
        return res.status(400).json({ ok: false, error: 'That link address does not look right — it should start with https://' });
      }
      fields.url = parsed.toString();
      fields.title = (b.title || '').toString().trim();
    } else if (kind === 'heading') {
      fields.title = (b.title || '').toString().trim();
      if (!fields.title) return res.status(400).json({ ok: false, error: 'Type the section title.' });
    }
    const created = pages.addBlock(page.id, fields);
    res.json({ ok: true, slug: created.slug });
  });

  function ownBlock(req, res) {
    const page = pages.getByUser(req.user.id);
    const b = page && pages.blockBySlug(req.params.slug);
    if (!b || b.page_id !== page.id) { res.status(404).json({ ok: false, error: 'Block not found — reload the page.' }); return null; }
    return b;
  }

  app.post('/api/page/blocks/reorder', requireUser, express.json({ limit: '64kb' }), (req, res) => {
    const page = pages.getByUser(req.user.id);
    if (!page) return res.status(404).json({ ok: false, error: 'No page yet.' });
    const slugs = Array.isArray(req.body && req.body.slugs) ? req.body.slugs : null;
    if (!slugs) return res.status(400).json({ ok: false, error: 'slugs array required' });
    res.json({ ok: true, updated: pages.reorderBlocks(page.id, slugs) });
  });

  app.post('/api/page/blocks/:slug', requireUser, express.json({ limit: '16kb' }), (req, res) => {
    const b = ownBlock(req, res);
    if (!b) return;
    const body = req.body || {};
    const fields = {
      title: body.title != null ? String(body.title).trim() : undefined,
      subtitle: body.subtitle != null ? String(body.subtitle).trim() : undefined,
      gated: body.gated != null ? !!body.gated && b.kind !== 'heading' : undefined,
      hidden: body.hidden != null ? !!body.hidden : undefined,
    };
    if (b.kind === 'link' && body.url != null) {
      let u = String(body.url).trim();
      if (u && !/^https?:\/\//i.test(u)) u = 'https://' + u;
      let parsed = null;
      try { parsed = new URL(u); } catch {}
      if (!parsed || !/^https?:$/.test(parsed.protocol) || !parsed.hostname.includes('.')) {
        return res.status(400).json({ ok: false, error: 'That link address does not look right.' });
      }
      fields.url = parsed.toString();
    }
    if (b.kind === 'heading' && fields.title === '') return res.status(400).json({ ok: false, error: 'A section title cannot be empty.' });
    pages.updateBlock(b, fields);
    res.json({ ok: true });
  });

  app.post('/api/page/blocks/:slug/delete', requireUser, (req, res) => {
    const b = ownBlock(req, res);
    if (!b) return;
    pages.deleteBlock(b);
    res.json({ ok: true });
  });

  app.get('/page/leads.csv', requireUser, (req, res) => {
    const page = pages.getByUser(req.user.id);
    if (!page) return res.status(404).send('No page yet.');
    // A cell that starts with = + - @ is run as a formula by Excel/Sheets;
    // a visitor controls the name field, so neutralise it.
    const cell = (v) => {
      let s = (v == null ? '' : String(v));
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const rows = [['date', 'name', 'email', 'opened', 'gohighlevel'].map(cell).join(',')];
    for (const l of pages.leads(page.id, 100000)) {
      rows.push([l.created_at, l.name, l.email, l.block_title, l.ghl_status].map(cell).join(','));
    }
    res.set('Content-Type', 'text/csv; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="page-emails-${page.handle}.csv"`);
    res.send('﻿' + rows.join('\r\n') + '\r\n');
  });

  app.get('/page/qr.svg', requireUser, async (req, res) => {
    const page = pages.getByUser(req.user.id);
    if (!page) return res.status(404).send('No page yet.');
    try {
      const svg = await QRCode.toString(pageUrl(page), { type: 'svg', margin: 2, width: 512, errorCorrectionLevel: 'M' });
      res.set('Content-Type', 'image/svg+xml');
      res.set('Cache-Control', 'private, max-age=300');
      if (req.query.download) res.set('Content-Disposition', `attachment; filename="qr-${page.handle}.svg"`);
      res.send(svg);
    } catch (err) {
      res.status(500).send('QR failed');
    }
  });
}

module.exports = { attach };

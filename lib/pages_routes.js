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
// After ./pages — it adds columns to the pages table that file creates.
const { autoresponders } = require('./autoresponders');
const vsl = require('./vsl');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const BOT_RE = /bot|crawl|spider|slurp|facebookexternalhit|whatsapp|telegram|slack|discord|preview|embedly|headless|lighthouse/i;
const MAX_BLOCKS = 60;

function attach(app, deps) {
  const {
    db: { users: udb, files: fdb, groups: gdb, messages: mdb, chats: cdb, raw },
    users, ghl, classify, upload, layout, escHtml, reorderBar, REORDER_JS,
    appStoreCta, APPSTORE_CSS, PUBLIC_ORIGIN, SITE_NAME, requireUser, requireApiToken, kindEmoji,
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

  // Hosts whose /f/<slug> links are this site's own shares.
  const OWN_HOSTS = [...new Set([PUBLIC_ORIGIN.replace(/^https?:\/\//, ''), 'share.99dfy.com', 'share.bizapp.club'])];
  const vslDeps = { getFile: (slug) => fdb.getBySlug(slug), ownHosts: OWN_HOSTS };

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
    /* Centred in whatever part of the screen is actually visible — never a
       bottom sheet. On a phone the browser's own toolbar sits over the bottom
       of the page and covered the "Open it" button. --vv-top / --vv-h follow
       the visual viewport (set in PAGE_JS), so the card also rises above the
       keyboard; the fallbacks are the plain window. The card scrolls inside
       itself if a very short screen can't fit it. */
    .pg-sheet { position: fixed; z-index: 100; left: 50%;
                top: calc(var(--vv-top, 0px) + var(--vv-h, 100dvh) / 2);
                transform: translate(-50%, -50%);
                width: min(440px, calc(100% - 28px));
                max-height: calc(var(--vv-h, 100dvh) - 28px); overflow-y: auto; overscroll-behavior: contain;
                background: #fff; color: #0f172a; border-radius: 18px;
                padding: 20px 18px 18px; box-shadow: 0 20px 60px rgba(15,23,42,.45); }
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

      // Keep the card in the middle of what can actually be seen: iOS shrinks
      // the visual viewport (not the layout one) when the keyboard opens.
      function fit() {
        var vv = window.visualViewport;
        if (!vv) return;
        sheet.style.setProperty('--vv-top', vv.offsetTop + 'px');
        sheet.style.setProperty('--vv-h', vv.height + 'px');
      }
      if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', fit);
        window.visualViewport.addEventListener('scroll', fit);
      }

      function open(card) {
        fit();
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

    const video = vsl.vslHtml(page, vsl.resolveVsl(page, vslDeps.getFile), escHtml);
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
  <style>${PAGE_CSS}${vsl.VSL_CSS}${APPSTORE_CSS}</style>
</head>
<body class="pg th-${escHtml(page.theme)}" data-handle="${escHtml(page.handle)}">
  ${isOwner ? `<div class="pg-owner-bar">${page.published ? 'This is your page — visitors see exactly this.' : '🙈 Your page is switched OFF — only you can see it.'} <a href="/pages/${page.id}">Edit it →</a></div>` : ''}
  <main class="pg-wrap">
    ${page.vsl_position === 'top' ? video : ''}
    <header class="pg-head">
      ${avatarHtml(page, 'pg-avatar')}
      <h1 class="pg-name">${escHtml(name)}</h1>
      <p class="pg-handle">@${escHtml(page.handle)}</p>
      ${page.bio ? `<p class="pg-bio">${escHtml(page.bio)}</p>` : ''}
    </header>
    ${page.vsl_position === 'top' ? '' : video}

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
      // The owner's own email-marketing tool (systeme.io, …), same rule:
      // never make the visitor wait for it.
      autoresponders.pushLead(owner.id, page, {
        id: lead.id, email, name, block_title: (b.title || r.autoTitle || '').slice(0, 120),
      }).catch((err) => console.warn('[autoresponder]', err.message));
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


  // ---------- shared by the web editor AND the iPhone app ----------
  //
  // One definition of every rule (what a block may point at, what a link must
  // look like, picture limits), so the website and the phone can never accept
  // different things.

  function normaliseUrl(raw) {
    let u = (raw || '').toString().trim();
    if (u && !/^https?:\/\//i.test(u)) u = 'https://' + u;
    let parsed = null;
    try { parsed = new URL(u); } catch {}
    if (!parsed || !/^https?:$/.test(parsed.protocol) || !parsed.hostname.includes('.')) return null;
    return parsed.toString();
  }

  /** { block } or { error } */
  function addBlockFor(owner, page, body) {
    const kind = (body.kind || '').toString();
    if (!pages.KINDS.includes(kind)) return { error: 'Pick what kind of block to add.' };
    if (pages.countBlocks(page.id) >= MAX_BLOCKS) return { error: `A page can hold ${MAX_BLOCKS} blocks.` };

    const fields = { kind, gated: !!body.gated && kind !== 'heading' };
    if (kind === 'file' || kind === 'folder' || kind === 'chat') {
      fields.ref_slug = (body.ref_slug || '').toString();
      if (!resolveBlock({ kind, ref_slug: fields.ref_slug }, owner.id)) {
        return { error: `Pick one of your own ${kind === 'chat' ? 'chat scrolls' : kind + 's'}.` };
      }
      fields.title = (body.title || '').toString().trim();
    } else if (kind === 'link') {
      fields.url = normaliseUrl(body.url);
      if (!fields.url) return { error: 'That link address does not look right — it should start with https://' };
      fields.title = (body.title || '').toString().trim();
    } else if (kind === 'heading') {
      fields.title = (body.title || '').toString().trim();
      if (!fields.title) return { error: 'Type the section title.' };
    }
    return { block: pages.addBlock(page.id, fields) };
  }

  /** { block } or { error } */
  function patchBlock(b, body) {
    const fields = {
      title: body.title != null ? String(body.title).trim() : undefined,
      subtitle: body.subtitle != null ? String(body.subtitle).trim() : undefined,
      gated: body.gated != null ? !!body.gated && b.kind !== 'heading' : undefined,
      hidden: body.hidden != null ? !!body.hidden : undefined,
    };
    if (b.kind === 'link' && body.url != null) {
      fields.url = normaliseUrl(body.url);
      if (!fields.url) return { error: 'That link address does not look right.' };
    }
    if (b.kind === 'heading' && fields.title === '') return { error: 'A section title cannot be empty.' };
    return { block: pages.updateBlock(b, fields) };
  }

  /** Throws an Error whose message is fit to show a person. Caller deletes the temp file. */
  function storeAvatar(owner, page, file) {
    if (!file) throw new Error('Pick a picture first.');
    const cls = classify.classify(file.originalname, file.mimetype);
    if (cls.kind !== 'image') throw new Error('That is not a picture — use a JPG, PNG or WebP.');
    if (file.size > 8 * 1024 * 1024) throw new Error('That picture is too big — keep it under 8 MB.');
    const cfg = users.effectiveGhlConfig(owner);
    let url;
    try {
      url = ghl.uploadToGhl(file.path, `page-avatar-${page.handle}-${Date.now()}.${cls.ghlExt}`, cls.ghlMime, cfg);
    } catch (err) {
      console.error('[page-avatar] upload failed:', err.message);
      throw new Error('The picture could not be stored right now. Try again in a minute.');
    }
    const old = page.avatar_url;
    pages.setAvatar(page.id, url);
    if (old) ghl.tryDeleteFromGhl(old, cfg);
  }

  function pageJSON(page) {
    return {
      id: page.id,
      handle: page.handle,
      display_name: page.display_name,
      bio: page.bio,
      theme: page.theme,
      published: !!page.published,
      public_url: pageUrl(page),
      avatar_url: page.avatar_url
        ? `${PUBLIC_ORIGIN}/pa/${page.handle}?v=${String(page.updated_at || '').replace(/\D/g, '')}`
        : null,
      vsl: {
        enabled: !!page.vsl_enabled,
        source: page.vsl_source || null,
        url: page.vsl_url || '',
        file_slug: page.vsl_ref || null,
        title: page.vsl_title || '',
        position: page.vsl_position || 'below_bio',
        playable: !!vsl.resolveVsl(page, vslDeps.getFile),
      },
    };
  }

  function blockJSON(b, owner, totals) {
    const r = resolveBlock(b, owner.id);
    const st = totals.blocks[b.id] || {};
    return {
      slug: b.slug,
      kind: b.kind,
      ref_slug: b.ref_slug,
      url: b.url,
      title: b.title,
      subtitle: b.subtitle,
      gated: !!b.gated,
      hidden: !!b.hidden,
      // What visitors actually see when title/subtitle are left blank, and
      // whether the thing it points at still exists.
      missing: !r,
      shown_title: r ? (b.title || r.autoTitle || '') : (b.title || ''),
      shown_subtitle: r ? (b.subtitle || r.autoSub || '') : '',
      emoji: r && r.icon ? r.icon : '',
      file_kind: r && r.kindLabel ? r.kindLabel : null,
      open_url: r && r.dest ? (r.external ? r.dest : PUBLIC_ORIGIN + r.dest) : null,
      clicks_30d: st.click || 0,
      leads_30d: st.lead || 0,
      top_copied: r && r.group
        ? pages.copiesInGroup(r.group.id, 30).filter(x => x.n > 0).slice(0, 3).map(x => ({ title: x.title || '', count: x.n }))
        : [],
    };
  }

  /** One row in the "My pages" list. */
  function pageSummaryJSON(page) {
    const totals = pages.totals(page.id, 30);
    return {
      ...pageJSON(page),
      views_30d: totals.page.view || 0,
      emails_total: pages.leadCount(page.id),
      block_count: pages.countBlocks(page.id),
    };
  }

  function listJSON(owner) {
    return { ok: true, pages: pages.listByUser(owner.id).map(pageSummaryJSON) };
  }

  function editorJSON(owner, page) {
    const totals = pages.totals(page.id, 30);
    const clicks = Object.values(totals.blocks).reduce((sum, x) => sum + (x.click || 0), 0);
    return {
      ok: true,
      page: pageJSON(page),
      themes: Object.entries(pages.THEMES).map(([key, t]) => ({ key, label: t.label })),
      blocks: pages.blocks(page.id).map(b => blockJSON(b, owner, totals)),
      stats: { views_30d: totals.page.view || 0, clicks_30d: clicks, emails_total: pages.leadCount(page.id) },
      ghl_connected: ghlStatusFor(owner).allowed,
      autoresponders: autoresponders.summary(owner.id, page).map(a => ({
        ...a,
        // Plain words for the phone, which can't show the website's markup.
        steps: (autoresponders.PROVIDERS[a.provider].steps || [])
          .map(x => x.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&')),
        help_url: autoresponders.PROVIDERS[a.provider].helpUrl,
      })),
      autoresponder_enabled: !!page.ar_enabled,
      autoresponder_tag: page.ar_tag || '',
      autoresponder_unsent: autoresponders.countUnsent(owner.id, page),
      leads: pages.leads(page.id, 200).map(l => ({
        email: l.email, name: l.name, opened: l.block_title, ghl_status: l.ghl_status, created_at: l.created_at,
        autoresponder_status: autoresponders.leadStatus(l),
      })),
    };
  }

  // ======================================================================
  // OWNER EDITOR
  // ======================================================================

  /** The account's first page, made on first use. */
  function ensurePage(user) {
    return pages.getByUser(user.id) || pages.create(user);
  }

  /** The page in :id if it belongs to the signed-in user, else answers 404 and returns null. */
  function ownPage(req, res, { json = false } = {}) {
    const page = pages.getOwned(req.params.id, req.user.id);
    if (!page) {
      if (json) res.status(404).json({ ok: false, error: 'That page is gone — reload.' });
      else res.status(404).send(notFoundPage(req, 'That page does not exist, or is not yours.'));
    }
    return page;
  }

  function deletePageAndPicture(owner, page) {
    if (page.avatar_url) ghl.tryDeleteFromGhl(page.avatar_url, users.effectiveGhlConfig(owner));
    pages.deletePage(page);
  }

  // ---------- email marketing (autoresponder) ----------
  //
  // The connection belongs to the ACCOUNT (one API key serves every page);
  // whether a page sends, and the extra tag it adds, belong to the PAGE.

  const resending = new Set(); // page ids with a resend running

  /** Only same-site paths may be returned to — never an outside URL. */
  function safeReturn(v, fallback) {
    const s = (v || '').toString();
    return /^\/pages(\/\d+)?(\?[\w=&-]*)?$/.test(s) ? s : fallback;
  }

  function withMsg(path, key, value) {
    return path + (path.includes('?') ? '&' : '?') + key + '=' + encodeURIComponent(value) + '#email-marketing';
  }

  function emailMarketingSection(owner, page, returnTo) {
    const conns = autoresponders.connections(owner.id);
    const cards = Object.values(autoresponders.PROVIDERS).map((p) => {
      const c = conns[p.id];
      if (!c) {
        return `
          <form class="card stack" method="POST" action="/integrations/${p.id}/connect">
            <input type="hidden" name="back" value="${escHtml(returnTo)}">
            <div><strong>Connect ${escHtml(p.label)}</strong>
              <span class="pill" style="background:#64748b1a;color:#64748b;border:1px solid #64748b55;margin-left:6px;">not connected</span></div>
            <p class="muted" style="margin:0; font-size:14px;">Every email someone gives on your pages goes straight into your ${escHtml(p.label)} contacts, tagged, so you can send them your emails and automations from there.</p>
            <ol class="am-steps">${p.steps.map(x => `<li>${x}</li>`).join('')}</ol>
            <div>
              <label for="ar-key-${p.id}">${escHtml(p.keyLabel)}</label>
              <input id="ar-key-${p.id}" name="api_key" type="password" required autocomplete="off" spellcheck="false" placeholder="${escHtml(p.keyPlaceholder)}">
            </div>
            <div class="row">
              <button type="submit" class="btn">🔌 Connect ${escHtml(p.label)}</button>
              <a class="btn btn-secondary" href="${escHtml(p.helpUrl)}" target="_blank" rel="noopener">${escHtml(p.helpLabel || `How to get your ${p.label} key ↗`)}</a>
            </div>
            <p class="muted" style="margin:0; font-size:12.5px;">We test the key before saving it. It connects all your pages at once.</p>
          </form>`;
      }
      const last = c.last_status || '';
      const lastHtml = !last
        ? '<span class="muted">No emails sent yet.</span>'
        : last === 'sent'
          ? `<span class="pe-ghl-ok">✓ Last email went in fine</span> <span class="muted">(${escHtml((c.last_at || '').slice(0, 16))} UTC)</span>`
          : `<span class="pe-ghl-bad">⚠️ Last try failed: ${escHtml(last.replace(/^failed — /, ''))}</span>`;
      const unsent = page ? autoresponders.countUnsent(owner.id, page) : 0;
      const pageBlock = page ? `
        <form class="stack am-page" method="POST" action="/pages/${page.id}/autoresponder">
          <label class="checkbox-row"><input type="checkbox" name="enabled" value="1"${page.ar_enabled ? ' checked' : ''}>
            <span>Send this page's emails to ${escHtml(p.label)}<span class="hint">Untick to keep this page's emails here only.</span></span></label>
          <div>
            <label for="ar-tag">Extra tag for this page <span style="font-weight:400;color:var(--muted);">(optional)</span></label>
            <input id="ar-tag" name="tag" type="text" maxlength="64" value="${escHtml(page.ar_tag || '')}" placeholder="e.g. prompt-pack-buyers">
            <p class="muted" style="margin:4px 0 0; font-size:12.5px;">Every contact gets the tags <code>sharezpresso</code>, <code>page-${escHtml(page.handle)}</code> and <code>opened: &lt;what they opened&gt;</code>${page.ar_tag ? `, plus <code>${escHtml(page.ar_tag)}</code>` : ''}. In ${escHtml(p.label)}, start an automation with the trigger <em>“Tag added”</em> to email them.</p>
          </div>
          <div class="row"><button type="submit" class="btn btn-secondary">Save</button></div>
        </form>
        ${unsent && page.ar_enabled ? `
          <form method="POST" action="/pages/${page.id}/autoresponder/resend" class="row" style="align-items:center;">
            <button type="submit" class="btn"${resending.has(page.id) ? ' disabled' : ''}>${resending.has(page.id) ? 'Sending…' : `📤 Send ${unsent} earlier email${unsent === 1 ? '' : 's'} to ${escHtml(p.label)}`}</button>
            <span class="muted" style="font-size:13px;">Emails this page collected before it was connected, or that failed.</span>
          </form>` : ''}` : '';
      return `
        <div class="card stack">
          <div class="row" style="align-items:center; justify-content:space-between;">
            <div><strong>${escHtml(p.label)}</strong>
              <span class="pill" style="background:#16a34a1a;color:#16a34a;border:1px solid #16a34a55;margin-left:6px;">connected</span>
              <span class="muted" style="font-size:13px;">key ${escHtml('••••' + c.api_key.slice(-4))}</span></div>
            <form method="POST" action="/integrations/${p.id}/disconnect" style="margin:0;">
              <input type="hidden" name="back" value="${escHtml(returnTo)}">
              <button type="submit" class="btn btn-secondary btn-sm">Disconnect</button>
            </form>
          </div>
          <div style="font-size:14px;">${lastHtml}</div>
          ${pageBlock}
        </div>`;
    }).join('');
    return `
      <h2 id="email-marketing">📬 Email marketing</h2>
      <p class="muted" style="margin-top:-6px;">Send the emails your pages collect into your own autoresponder.</p>
      ${cards}
      <style>
        .am-steps { margin: 0; padding-left: 20px; font-size: 14px; line-height: 1.7; }
        .am-page { border-top: 1px solid var(--border); padding-top: 12px; }
        .am-page code { font-size: 12px; background: #f1f5f9; padding: 1px 5px; border-radius: 5px; }
      </style>`;
  }

  // ---------- the page video (VSL) ----------

  function vslSection(page, myVideos) {
    const v = vsl.resolveVsl({ ...page, vsl_enabled: 1 }, vslDeps.getFile);
    const src = page.vsl_source || (myVideos.length ? 'file' : 'link');
    const broken = page.vsl_enabled && !vsl.resolveVsl(page, vslDeps.getFile);
    const chip = (key, label) => `<button type="button" class="chip-btn vsl-src${src === key ? ' is-active' : ''}" data-src="${key}">${label}</button>`;
    return `
      <h2 id="vsl">🎬 Video on your page <span class="muted" style="font-size:14px; font-weight:500;">(optional)</span></h2>
      <form class="card stack" method="POST" action="/pages/${page.id}/vsl" id="vsl-form">
        <label class="checkbox-row"><input type="checkbox" name="enabled" value="1" id="vsl-on"${page.vsl_enabled ? ' checked' : ''}>
          <span>Show a video (VSL) on my page<span class="hint">A sales or welcome video people watch before your blocks.</span></span></label>

        <div id="vsl-body" class="stack"${page.vsl_enabled ? '' : ' hidden'}>
          ${broken ? `<p class="err" style="margin:0;"><strong>⚠️ Visitors can't see your video right now — the video it pointed to was deleted or the link stopped working. Pick another below.</strong></p>` : ''}
          <input type="hidden" name="source" id="vsl-source" value="${src === 'file' ? 'file' : 'link'}">
          <div>
            <label>Where does the video come from?</label>
            <div class="pe-kinds" style="margin:0;">
              ${chip('link', '🔗 Paste a link')}
              <button type="button" class="chip-btn vsl-src" data-src="upload">⬆️ Upload a video</button>
              ${chip('file', '🎞️ One of my videos')}
            </div>
          </div>

          <div class="vsl-panel" data-src="link"${src === 'link' ? '' : ' hidden'}>
            <label for="vsl-url">Video link</label>
            <input id="vsl-url" name="url" type="text" inputmode="url" maxlength="2000" value="${escHtml(page.vsl_url || '')}" placeholder="https://www.youtube.com/watch?v=… or https://www.tella.tv/video/…">
            <p class="muted" style="margin:4px 0 0; font-size:12.5px;">Works with ${escHtml(vsl.HOSTS_SENTENCE)}. Google Drive videos must be shared as “Anyone with the link”.</p>
          </div>

          <div class="vsl-panel" data-src="upload" hidden>
            <label for="vsl-file">Pick a video from your computer or phone</label>
            <input id="vsl-file" type="file" accept="video/*">
            <div class="vsl-progress" id="vsl-progress" hidden><div class="vsl-bar"><span id="vsl-bar"></span></div><span id="vsl-pct" class="muted" style="font-size:13px;"></span></div>
            <p class="muted" style="margin:4px 0 0; font-size:12.5px;">It's saved with your other files (up to 500 MB) and set as this page's video straight away.</p>
          </div>

          <div class="vsl-panel" data-src="file"${src === 'file' ? '' : ' hidden'}>
            ${myVideos.length
              ? `<label for="vsl-ref">Pick one of your videos</label>
                 <select id="vsl-ref" name="ref_slug">${myVideos.map(f => `<option value="${escHtml(f.slug)}"${f.slug === page.vsl_ref ? ' selected' : ''}>🎞️ ${escHtml(f.title || f.original_filename)}</option>`).join('')}</select>`
              : `<p class="muted" style="margin:0;">You haven't uploaded any videos yet — use “Upload a video”.</p>`}
          </div>

          <div>
            <label for="vsl-title">Headline above the video <span style="font-weight:400;color:var(--muted);">(optional)</span></label>
            <input id="vsl-title" name="title" type="text" maxlength="140" value="${escHtml(page.vsl_title || '')}" placeholder="e.g. Watch this first (2 minutes)">
          </div>
          <div>
            <label>Where on the page?</label>
            <div class="pe-themes">
              <label class="pe-theme"><input type="radio" name="position" value="below_bio"${page.vsl_position !== 'top' ? ' checked' : ''}>Under my name &amp; bio (recommended)</label>
              <label class="pe-theme"><input type="radio" name="position" value="top"${page.vsl_position === 'top' ? ' checked' : ''}>At the very top</label>
            </div>
          </div>

          ${v ? `<div><label>Current video</label><div class="vsl-preview">${vsl.vslHtml({ ...page, vsl_title: '' }, v, escHtml)}</div></div>` : ''}
        </div>
        <button type="submit" class="btn btn-block" id="vsl-save">Save video</button>
      </form>
      <style>
        .vsl-panel[hidden], #vsl-body[hidden] { display: none; }
        .vsl-panel select { width: 100%; padding: 12px; font-size: 15px; border: 1px solid var(--border); border-radius: 10px; background: #fff; }
        .vsl-progress { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
        .vsl-bar { flex: 1; height: 10px; background: #e2e8f0; border-radius: 99px; overflow: hidden; }
        .vsl-bar span { display: block; height: 100%; width: 0; background: var(--brand); transition: width .2s; }
        .vsl-preview { --card-border: var(--border); }
        .vsl-preview .pg-vsl { margin: 0; }
        ${vsl.VSL_CSS}
      </style>
      <script>
        (function () {
          var form = document.getElementById('vsl-form');
          var on = document.getElementById('vsl-on');
          var body = document.getElementById('vsl-body');
          var source = document.getElementById('vsl-source');
          on.addEventListener('change', function () { body.hidden = !on.checked; });
          function show(src) {
            document.querySelectorAll('.vsl-src').forEach(function (b) { b.classList.toggle('is-active', b.dataset.src === src); });
            document.querySelectorAll('.vsl-panel').forEach(function (p) { p.hidden = p.dataset.src !== src; });
            if (src !== 'upload') source.value = src;
          }
          document.querySelectorAll('.vsl-src').forEach(function (b) {
            b.addEventListener('click', function () { show(b.dataset.src); });
          });

          var fileIn = document.getElementById('vsl-file');
          var save = document.getElementById('vsl-save');
          fileIn.addEventListener('change', function () {
            var f = fileIn.files[0];
            if (!f) return;
            var bar = document.getElementById('vsl-bar'), pct = document.getElementById('vsl-pct');
            document.getElementById('vsl-progress').hidden = false;
            save.disabled = true; fileIn.disabled = true;
            var fd = new FormData();
            fd.append('file', f);
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/upload');
            xhr.upload.onprogress = function (e) {
              if (!e.lengthComputable) return;
              var p = Math.round(e.loaded / e.total * 100);
              bar.style.width = p + '%';
              pct.textContent = p < 100 ? 'Uploading… ' + p + '%' : 'Saving the video… (big files take a minute)';
            };
            xhr.onload = function () {
              var data = {};
              try { data = JSON.parse(xhr.responseText); } catch (e) {}
              if (xhr.status === 200 && data.ok && data.kind === 'video') {
                pct.textContent = 'Uploaded ✓ — saving…';
                var ref = document.createElement('input');
                ref.type = 'hidden'; ref.name = 'ref_slug'; ref.value = data.slug;
                form.querySelectorAll('[name=ref_slug]').forEach(function (el) { el.disabled = true; });
                form.appendChild(ref);
                source.value = 'file';
                on.checked = true;
                form.submit();
              } else {
                pct.textContent = (data.ok && data.kind !== 'video') ? 'That file is not a video.' : (data.error || 'Upload failed — try again.');
                pct.style.color = 'var(--err)';
                save.disabled = false; fileIn.disabled = false; fileIn.value = '';
              }
            };
            xhr.onerror = function () {
              pct.textContent = 'Upload failed — check your connection and try again.';
              pct.style.color = 'var(--err)';
              save.disabled = false; fileIn.disabled = false;
            };
            xhr.send(fd);
          });
        })();
      </script>`;
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

      var root = document.getElementById('pe-root');
      var API = '/api/pages/' + (root ? root.dataset.page : '0');

      var list = document.getElementById('block-list');
      if (list && window.__initReorder) {
        window.__initReorder({ container: '#block-list', itemSelector: '.block-card', endpoint: API + '/blocks/reorder' });
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
            await post(API + '/blocks/' + encodeURIComponent(card.dataset.slug), body);
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
              try { await post(API + '/blocks/' + encodeURIComponent(c.dataset.slug) + '/delete'); c.remove(); toast('Removed'); }
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
          await post(API + '/blocks', body);
          window.location.href = '/pages/' + root.dataset.page + '?added=1#blocks';
        } catch (err) { toast(err.message, true); btn.disabled = false; }
      });

      var delPage = document.querySelector('.pe-delete-page');
      if (delPage) delPage.addEventListener('click', function () {
        window.__confirmDelete({
          title: 'Delete @' + delPage.dataset.handle + '?',
          message: 'The page, its blocks, its stats and the emails it collected are deleted, and the link stops working. Download the emails first if you want them. Your files, folders and chats are NOT deleted.',
          okText: 'Delete this page',
          then: async function () {
            try { await post(API + '/delete'); window.location.href = '/pages?deleted=1'; }
            catch (err) { toast(err.message, true); }
          },
        });
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

  // ---------- the list of pages ----------

  const LIST_CSS = `
    .pl-card { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
    .pl-main { flex: 1 1 220px; min-width: 0; }
    .pl-name { font-weight: 700; font-size: 17px; word-break: break-word; }
    .pl-meta { font-size: 13px; color: var(--muted); margin-top: 2px; }
    .pl-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .pl-actions .btn { padding: 10px 14px; font-size: 14px; min-height: 44px; }
    .pl-new .pe-handle { display: flex; align-items: stretch; }
    .pl-new .pe-handle span { display: inline-flex; align-items: center; padding: 0 10px; background: #f1f5f9; border: 1px solid var(--border); border-right: 0; border-radius: 10px 0 0 10px; color: var(--muted); font-size: 14px; white-space: nowrap; }
    .pl-new .pe-handle input { border-radius: 0 10px 10px 0 !important; }
    .pe-avatar { width: 56px; height: 56px; border-radius: 50%; object-fit: cover; flex: 0 0 auto; background: #e2e8f0; }
    .pe-avatar-initials { display: inline-flex; align-items: center; justify-content: center; font-weight: 800; font-size: 20px; color: #fff; background: #f97316; }
  `;

  // Where "➕ Add to my page" on a file / folder / chat lands. One page: go
  // straight to its editor. Several: let them pick which page gets it.
  app.get('/page', requireUser, (req, res) => {
    const owner = udb.getById(req.user.id);
    const list = pages.listByUser(owner.id);
    const q = new URLSearchParams();
    if (pages.KINDS.includes(req.query.add)) { q.set('add', req.query.add); q.set('ref', String(req.query.ref || '')); }
    const qs = q.toString() ? `?${q}` : '';
    if (list.length === 0) return res.redirect(`/pages/${ensurePage(owner).id}${qs}${qs ? '#add-form' : ''}`);
    if (list.length === 1) return res.redirect(`/pages/${list[0].id}${qs}${qs ? '#add-form' : ''}`);
    res.redirect(`/pages${qs}`);
  });

  app.get('/pages', requireUser, (req, res) => {
    const owner = udb.getById(req.user.id);
    const list = pages.listByUser(owner.id);
    const adding = pages.KINDS.includes(req.query.add) ? { kind: req.query.add, ref: String(req.query.ref || '') } : null;
    const addQs = adding ? `?add=${encodeURIComponent(adding.kind)}&ref=${encodeURIComponent(adding.ref)}#add-form` : '';
    const err = (req.query.err || '').toString().slice(0, 300);
    const host = PUBLIC_ORIGIN.replace(/^https?:\/\//, '');

    const cards = list.map((p) => {
      const sum = pageSummaryJSON(p);
      return `
        <div class="card pl-card">
          ${avatarHtml(p, 'pe-avatar')}
          <div class="pl-main">
            <div class="pl-name">${escHtml(p.display_name || p.handle)}</div>
            <div class="pl-meta">${escHtml(host)}/@${escHtml(p.handle)} · ${p.published ? '🟢 live' : '🙈 off'}</div>
            <div class="pl-meta">${sum.block_count} block${sum.block_count === 1 ? '' : 's'} · ${sum.views_30d} visit${sum.views_30d === 1 ? '' : 's'} in 30 days · ${sum.emails_total} email${sum.emails_total === 1 ? '' : 's'}</div>
          </div>
          <div class="pl-actions">
            ${adding
              ? `<a class="btn" href="/pages/${p.id}${addQs}">➕ Add it to this page</a>`
              : `<a class="btn" href="/pages/${p.id}">Edit</a>
                 <button type="button" class="btn btn-secondary pe-copy-link" data-url="${escHtml(pageUrl(p))}">Copy link</button>
                 <a class="btn btn-secondary" href="/@${escHtml(p.handle)}" target="_blank" rel="noopener">Open</a>`}
          </div>
        </div>`;
    }).join('');

    const body = `
      <h1>My pages</h1>
      <p class="muted">Make as many as you like — one per offer, per audience, per language. Each page has its own link, blocks, stats and emails.</p>
      ${req.query.deleted ? '<p class="ok"><strong>✓ Page deleted.</strong></p>' : ''}
      ${err ? `<p class="err"><strong>${escHtml(err)}</strong></p>` : ''}
      ${req.query.ar_ok ? `<p class="ok"><strong>✓ ${escHtml(String(req.query.ar_ok).slice(0, 300))}</strong></p>` : ''}
      ${adding ? `<div class="card" style="border-left:4px solid var(--brand);"><strong>Which page should it go on?</strong></div>` : ''}
      ${cards || '<div class="recent-empty">No pages yet — make your first one below.</div>'}

      ${emailMarketingSection(owner, null, '/pages')}

      <h2 id="new">➕ New page</h2>
      <form class="card stack pl-new" method="POST" action="/pages">
        <div>
          <label for="pl-name">Name on the page</label>
          <input id="pl-name" name="display_name" type="text" maxlength="80" placeholder="${escHtml(owner.name || 'Your name')}">
        </div>
        <div>
          <label for="pl-h">Page address</label>
          <div class="pe-handle"><span>${escHtml(host)}/@</span>
            <input id="pl-h" name="handle" type="text" maxlength="30" placeholder="e.g. prompts" autocapitalize="none" autocorrect="off" spellcheck="false"></div>
          <div class="muted" style="font-size:12.5px; margin-top:4px;">Leave it empty and we'll pick one from the name. You can change it later.</div>
        </div>
        <button type="submit" class="btn btn-block">Make the page</button>
      </form>
      <style>${LIST_CSS}</style>
      <script>
        document.addEventListener('click', async function (e) {
          var b = e.target.closest('.pe-copy-link');
          if (!b) return;
          try { await navigator.clipboard.writeText(b.dataset.url); b.textContent = 'Copied!'; }
          catch (err) { b.textContent = 'Copy failed'; }
          setTimeout(function () { b.textContent = 'Copy link'; }, 1500);
        });
      </script>
    `;
    res.send(layout({ title: 'My pages — ' + SITE_NAME, user: req.user, body }));
  });

  app.post('/pages', requireUser, express.urlencoded({ extended: false, limit: '8kb' }), (req, res) => {
    const owner = udb.getById(req.user.id);
    const out = pages.createNamed(owner, { handle: req.body.handle, display_name: req.body.display_name });
    if (out.error) return res.redirect('/pages?err=' + encodeURIComponent(out.error));
    res.redirect(`/pages/${out.page.id}?created=1`);
  });

  const formBody = express.urlencoded({ extended: false, limit: '8kb' });

  app.post('/integrations/:provider/connect', requireUser, formBody, async (req, res) => {
    const p = autoresponders.PROVIDERS[req.params.provider];
    const back = safeReturn(req.body.back, '/pages');
    if (!p) return res.redirect(withMsg(back, 'err', 'Unknown integration.'));
    const problem = await autoresponders.connect(req.user.id, p.id, req.body.api_key);
    if (problem) return res.redirect(withMsg(back, 'err', problem));
    res.redirect(withMsg(back, 'ar_ok', `${p.label} is connected. New emails from your pages now go straight into it.`));
  });

  app.post('/integrations/:provider/disconnect', requireUser, formBody, (req, res) => {
    const p = autoresponders.PROVIDERS[req.params.provider];
    const back = safeReturn(req.body.back, '/pages');
    if (p) autoresponders.disconnect(req.user.id, p.id);
    res.redirect(withMsg(back, 'ar_ok', `${p ? p.label : 'Integration'} disconnected. Emails are still saved here.`));
  });

  app.post('/pages/:id/vsl', requireUser, formBody, (req, res) => {
    const page = ownPage(req, res);
    if (!page) return;
    const problem = vsl.saveVsl(page, req.body || {}, vslDeps);
    if (problem) return res.redirect(`/pages/${page.id}?err=${encodeURIComponent(problem)}#vsl`);
    res.redirect(`/pages/${page.id}?vsl=1#vsl`);
  });

  app.post('/pages/:id/autoresponder', requireUser, formBody, (req, res) => {
    const page = ownPage(req, res);
    if (!page) return;
    autoresponders.setPageSettings(page, { enabled: req.body.enabled === '1', tag: req.body.tag });
    res.redirect(withMsg(`/pages/${page.id}`, 'ar_ok', 'Email marketing settings saved.'));
  });

  app.post('/pages/:id/autoresponder/resend', requireUser, (req, res) => {
    const page = ownPage(req, res);
    if (!page) return;
    const n = autoresponders.countUnsent(req.user.id, page);
    if (n && !resending.has(page.id)) {
      // Runs in the background, one contact at a time, so a long list never
      // holds this request open or floods the provider's rate limit.
      resending.add(page.id);
      autoresponders.resendPage(req.user.id, page)
        .then((out) => console.log(`[autoresponder] resend page ${page.handle}: ${JSON.stringify(out)}`))
        .catch((err) => console.warn('[autoresponder] resend failed', err.message))
        .finally(() => resending.delete(page.id));
    }
    res.redirect(withMsg(`/pages/${page.id}`, 'ar_ok', n ? `Sending ${n} email${n === 1 ? '' : 's'} now — reload in a minute to see each one's result below.` : 'Nothing left to send.'));
  });

  app.post('/api/pages/:id/delete', requireUser, (req, res) => {
    const page = ownPage(req, res, { json: true });
    if (!page) return;
    deletePageAndPicture(udb.getById(req.user.id), page);
    res.json({ ok: true });
  });

  // ---------- one page's editor ----------

  app.get('/pages/:id', requireUser, (req, res) => {
    const owner = udb.getById(req.user.id);
    const page = ownPage(req, res);
    if (!page) return;
    const pageCount = pages.countByUser(owner.id);
    const blocks = pages.blocks(page.id);
    const totals = pages.totals(page.id, 30);
    const url = pageUrl(page);
    const clicks = Object.values(totals.blocks).reduce((s, x) => s + (x.click || 0), 0);
    const leads = pages.leads(page.id, 100);
    const leadCount = pages.leadCount(page.id);
    const { allowed: ghlOn } = ghlStatusFor(owner);

    const err = (req.query.err || '').toString().slice(0, 300);
    const ok = req.query.created ? 'Your new page is ready — add blocks below.' : req.query.saved ? 'Saved.' : req.query.pic ? 'New picture is up.' : req.query.added ? 'Block added to the bottom of your page.'
      : req.query.vsl ? 'Video saved.' : (req.query.ar_ok || '').toString().slice(0, 300);
    const arProviders = Object.values(autoresponders.PROVIDERS).filter(p => autoresponders.connection(owner.id, p.id));

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
      const st = autoresponders.leadStatus(l);
      const arCells = arProviders.map((p) => {
        const v = st[p.id] || '';
        const cls = v === 'sent' ? 'pe-ghl-ok' : v.startsWith('failed') ? 'pe-ghl-bad' : 'muted';
        return `<td class="${cls}" style="font-size:12.5px;">${escHtml(v || 'not sent')}</td>`;
      }).join('');
      return `<tr>
        <td style="white-space:nowrap;">${escHtml((l.created_at || '').slice(0, 10))}</td>
        <td>${escHtml(l.name || '—')}</td>
        <td style="word-break:break-all;">${escHtml(l.email)}</td>
        <td>${escHtml(l.block_title || '—')}</td>
        <td class="${gCls}" style="font-size:12.5px;">${escHtml(g || '—')}</td>
        ${arCells}
      </tr>`;
    }).join('');

    const body = `
      <div class="pe-head" id="pe-root" data-page="${page.id}">
        <p style="margin:0 0 6px;"><a href="/pages">← ${pageCount > 1 ? `All my pages (${pageCount})` : 'My pages'}</a> · <a href="/pages#new">➕ New page</a></p>
        <h1>@${escHtml(page.handle)}</h1>
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
          <img src="/pages/${page.id}/qr.svg?h=${escHtml(page.handle)}" alt="QR code for your page" width="132" height="132">
          <a href="/pages/${page.id}/qr.svg?h=${escHtml(page.handle)}&download=1">Download QR</a>
        </div>
      </div>

      <div class="pe-stats">
        <div class="pe-stat"><b>${totals.page.view || 0}</b><span>visits · 30 days</span></div>
        <div class="pe-stat"><b>${clicks}</b><span>taps · 30 days</span></div>
        <div class="pe-stat"><b>${leadCount}</b><span>emails collected</span></div>
      </div>

      <h2>Your profile</h2>
      <form class="card stack" method="POST" action="/pages/${page.id}/avatar" enctype="multipart/form-data">
        <div class="pe-avatar-row">
          ${avatarHtml(page, 'pe-avatar')}
          <div>
            <label for="avatar-input" class="btn btn-secondary btn-sm" style="margin:0; display:inline-block;">${page.avatar_url ? 'Change picture' : 'Add a picture'}</label>
            <input id="avatar-input" type="file" name="file" accept="image/*" hidden>
            <div class="muted" style="font-size:12.5px; margin-top:4px;">A square photo of your face works best.</div>
          </div>
        </div>
      </form>
      <form class="card stack" method="POST" action="/pages/${page.id}/profile">
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

      ${vslSection(page, myFiles.filter(f => f.kind === 'video'))}

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

      ${emailMarketingSection(owner, page, `/pages/${page.id}`)}

      <h2 id="leads">Emails collected</h2>
      <div class="card stack">
        <p class="muted" style="margin:0; font-size:14px;">
          ${ghlOn
            ? 'Every new email is also added to your GoHighLevel as a contact, tagged <strong>sharezpresso-page</strong> plus what they opened — build a follow-up workflow off that tag.'
            : 'Emails are saved here. To also send them into your own GoHighLevel, connect it on the <a href="/account">Account</a> page.'}
        </p>
        ${leads.length
          ? `<div class="pe-table-wrap"><table class="pe-leads"><thead><tr><th>Date</th><th>Name</th><th>Email</th><th>Opened</th><th>GoHighLevel</th>${arProviders.map(p => `<th>${escHtml(p.label)}</th>`).join('')}</tr></thead><tbody>${leadRows}</tbody></table></div>
             <a class="btn btn-secondary" href="/pages/${page.id}/leads.csv">⬇ Download all as a spreadsheet (CSV)</a>`
          : `<div class="recent-empty" style="padding:16px;">No emails yet. Tick “Ask for their email before it opens” on a block to start collecting.</div>`}
      </div>

      <h2>Delete this page</h2>
      <div class="card">
        <p class="muted" style="margin:0 0 10px; font-size:14px;">Deletes the page, its blocks, stats and collected emails. Your files, folders and chats stay.</p>
        <button type="button" class="btn btn-danger pe-delete-page" data-handle="${escHtml(page.handle)}">Delete @${escHtml(page.handle)}</button>
      </div>

      <style>${EDITOR_CSS}</style>
      <script src="/vendor/sortable.min.js" defer></script>
      <script>${REORDER_JS}</script>
      <script>${EDITOR_JS}</script>
    `;

    res.send(layout({ title: `@${page.handle} — ${SITE_NAME}`, user: req.user, body }));
  });

  app.post('/pages/:id/profile', requireUser, express.urlencoded({ extended: false, limit: '32kb' }), (req, res) => {
    const page = ownPage(req, res);
    if (!page) return;
    const problem = pages.updateProfile(page, {
      handle: req.body.handle,
      display_name: req.body.display_name,
      bio: req.body.bio,
      theme: req.body.theme,
      published: req.body.published === '1',
    });
    if (problem) return res.redirect(`/pages/${page.id}?err=` + encodeURIComponent(problem));
    res.redirect(`/pages/${page.id}?saved=1`);
  });

  app.post('/pages/:id/avatar', requireUser, upload.single('file'), (req, res) => {
    try {
      const page = ownPage(req, res);
      if (!page) return;
      try {
        storeAvatar(udb.getById(req.user.id), page, req.file);
        res.redirect(`/pages/${page.id}?pic=1`);
      } catch (err) {
        res.redirect(`/pages/${page.id}?err=` + encodeURIComponent(err.message));
      }
    } finally {
      if (req.file) { try { fs.unlinkSync(req.file.path); } catch {} }
    }
  });

  app.post('/api/pages/:id/blocks', requireUser, express.json({ limit: '16kb' }), (req, res) => {
    const page = ownPage(req, res, { json: true });
    if (!page) return;
    const out = addBlockFor(udb.getById(req.user.id), page, req.body || {});
    if (out.error) return res.status(400).json({ ok: false, error: out.error });
    res.json({ ok: true, slug: out.block.slug });
  });

  function ownBlock(req, res, page) {
    const b = pages.blockBySlug(req.params.slug);
    if (!b || b.page_id !== page.id) { res.status(404).json({ ok: false, error: 'Block not found — reload the page.' }); return null; }
    return b;
  }

  app.post('/api/pages/:id/blocks/reorder', requireUser, express.json({ limit: '64kb' }), (req, res) => {
    const page = ownPage(req, res, { json: true });
    if (!page) return;
    const slugs = Array.isArray(req.body && req.body.slugs) ? req.body.slugs : null;
    if (!slugs) return res.status(400).json({ ok: false, error: 'slugs array required' });
    res.json({ ok: true, updated: pages.reorderBlocks(page.id, slugs) });
  });

  app.post('/api/pages/:id/blocks/:slug', requireUser, express.json({ limit: '16kb' }), (req, res) => {
    const page = ownPage(req, res, { json: true });
    if (!page) return;
    const b = ownBlock(req, res, page);
    if (!b) return;
    const out = patchBlock(b, req.body || {});
    if (out.error) return res.status(400).json({ ok: false, error: out.error });
    res.json({ ok: true });
  });

  app.post('/api/pages/:id/blocks/:slug/delete', requireUser, (req, res) => {
    const page = ownPage(req, res, { json: true });
    if (!page) return;
    const b = ownBlock(req, res, page);
    if (!b) return;
    pages.deleteBlock(b);
    res.json({ ok: true });
  });

  app.get('/pages/:id/leads.csv', requireUser, (req, res) => {
    const page = ownPage(req, res);
    if (!page) return;
    // A cell that starts with = + - @ is run as a formula by Excel/Sheets;
    // a visitor controls the name field, so neutralise it.
    const cell = (v) => {
      let s = (v == null ? '' : String(v));
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const provs = Object.values(autoresponders.PROVIDERS);
    const rows = [['date', 'name', 'email', 'opened', 'gohighlevel', ...provs.map(p => p.label)].map(cell).join(',')];
    for (const l of pages.leads(page.id, 100000)) {
      const st = autoresponders.leadStatus(l);
      rows.push([l.created_at, l.name, l.email, l.block_title, l.ghl_status, ...provs.map(p => st[p.id] || '')].map(cell).join(','));
    }
    res.set('Content-Type', 'text/csv; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="page-emails-${page.handle}.csv"`);
    res.send('﻿' + rows.join('\r\n') + '\r\n');
  });

  app.get('/pages/:id/qr.svg', requireUser, async (req, res) => {
    const page = ownPage(req, res);
    if (!page) return;
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

  // ======================================================================
  // iPHONE APP  (/api/v1/page/*, bearer token)
  // ======================================================================

  if (requireApiToken) {
    const router = express.Router();
    const json = express.json({ limit: '32kb' });
    const me = (req) => udb.getById(req.user.id);

    // ---- shared handlers: `pick(req, res, owner)` finds the page ----

    function mountEditor(base, pick) {
      router.get(base, requireApiToken, (req, res) => {
        const owner = me(req);
        const page = pick(req, res, owner);
        if (page) res.json(editorJSON(owner, page));
      });

      router.patch(base, requireApiToken, json, (req, res) => {
        const owner = me(req);
        const page = pick(req, res, owner);
        if (!page) return;
        const b = req.body || {};
        if (b.autoresponder && typeof b.autoresponder === 'object') {
          autoresponders.setPageSettings(page, {
            enabled: b.autoresponder.enabled != null ? !!b.autoresponder.enabled : !!page.ar_enabled,
            tag: b.autoresponder.tag != null ? b.autoresponder.tag : page.ar_tag,
          });
        }
        if (b.vsl && typeof b.vsl === 'object') {
          const vProblem = vsl.saveVsl(page, b.vsl, vslDeps);
          if (vProblem) return res.status(400).json({ ok: false, error: vProblem });
        }
        const problem = pages.updateProfile(page, {
          handle: b.handle != null ? b.handle : page.handle,
          display_name: b.display_name != null ? b.display_name : page.display_name,
          bio: b.bio != null ? b.bio : page.bio,
          theme: b.theme != null ? b.theme : page.theme,
          published: b.published != null ? !!b.published : !!page.published,
        });
        if (problem) return res.status(400).json({ ok: false, error: problem });
        res.json(editorJSON(owner, pages.getById(page.id)));
      });

      router.post(`${base}/avatar`, requireApiToken, upload.single('file'), (req, res) => {
        try {
          const owner = me(req);
          const page = pick(req, res, owner);
          if (!page) return;
          try {
            storeAvatar(owner, page, req.file);
            res.json(editorJSON(owner, pages.getById(page.id)));
          } catch (err) {
            res.status(400).json({ ok: false, error: err.message });
          }
        } finally {
          if (req.file) { try { fs.unlinkSync(req.file.path); } catch {} }
        }
      });

      router.post(`${base}/blocks`, requireApiToken, json, (req, res) => {
        const owner = me(req);
        const page = pick(req, res, owner);
        if (!page) return;
        const out = addBlockFor(owner, page, req.body || {});
        if (out.error) return res.status(400).json({ ok: false, error: out.error });
        res.json(editorJSON(owner, page));
      });

      // Registered before `${base}/blocks/:slug` so "reorder" is never read as a slug.
      router.post(`${base}/blocks/reorder`, requireApiToken, json, (req, res) => {
        const owner = me(req);
        const page = pick(req, res, owner);
        if (!page) return;
        const order = Array.isArray(req.body && req.body.order) ? req.body.order : null;
        if (!order) return res.status(400).json({ ok: false, error: 'order array required' });
        pages.reorderBlocks(page.id, order);
        res.json(editorJSON(owner, page));
      });

      function blockOf(req, res, page) {
        const b = pages.blockBySlug(req.params.slug);
        if (!b || b.page_id !== page.id) { res.status(404).json({ ok: false, error: 'That block is gone — pull down to refresh.' }); return null; }
        return b;
      }

      router.patch(`${base}/blocks/:slug`, requireApiToken, json, (req, res) => {
        const owner = me(req);
        const page = pick(req, res, owner);
        if (!page) return;
        const b = blockOf(req, res, page);
        if (!b) return;
        const out = patchBlock(b, req.body || {});
        if (out.error) return res.status(400).json({ ok: false, error: out.error });
        res.json(editorJSON(owner, page));
      });

      router.post(`${base}/autoresponder/resend`, requireApiToken, (req, res) => {
        const owner = me(req);
        const page = pick(req, res, owner);
        if (!page) return;
        const n = autoresponders.countUnsent(owner.id, page);
        if (n && !resending.has(page.id)) {
          resending.add(page.id);
          autoresponders.resendPage(owner.id, page)
            .then((out) => console.log(`[autoresponder] resend page ${page.handle} (app): ${JSON.stringify(out)}`))
            .catch((err) => console.warn('[autoresponder] resend failed', err.message))
            .finally(() => resending.delete(page.id));
        }
        res.json({ ...editorJSON(owner, pages.getById(page.id)), resend_started: n });
      });

      router.delete(`${base}/blocks/:slug`, requireApiToken, (req, res) => {
        const owner = me(req);
        const page = pick(req, res, owner);
        if (!page) return;
        const b = blockOf(req, res, page);
        if (!b) return;
        pages.deleteBlock(b);
        res.json(editorJSON(owner, page));
      });
    }

    // What the "Add a block" sheet can pick from — only the caller's own things.
    function choices(req, res) {
      const owner = me(req);
      res.json({
        ok: true,
        files: allFilesStmt.all(owner.id).map(f => ({ slug: f.slug, title: f.title || f.original_filename || 'File', kind: f.kind })),
        folders: gdb.listForUser(owner.id, { limit: 200 }).map(g => ({
          slug: g.slug, title: g.title || 'Untitled folder', count: mdb.listInGroup(g.id, owner.id).length,
        })),
        chats: cdb.listByUser(owner.id, { limit: 100 }).map(c => ({ slug: c.slug, title: c.title || 'Untitled chat', count: c.item_count })),
      });
    }
    router.get('/page/choices', requireApiToken, choices);

    // Email-marketing connections belong to the account, not to one page.
    router.post('/integrations/:provider', requireApiToken, json, async (req, res) => {
      const p = autoresponders.PROVIDERS[req.params.provider];
      if (!p) return res.status(404).json({ ok: false, error: 'Unknown integration.' });
      const problem = await autoresponders.connect(req.user.id, p.id, req.body && req.body.api_key);
      if (problem) return res.status(400).json({ ok: false, error: problem });
      res.json({ ok: true, connected: true });
    });
    router.delete('/integrations/:provider', requireApiToken, (req, res) => {
      const p = autoresponders.PROVIDERS[req.params.provider];
      if (!p) return res.status(404).json({ ok: false, error: 'Unknown integration.' });
      autoresponders.disconnect(req.user.id, p.id);
      res.json({ ok: true, connected: false });
    });
    router.get('/pages/choices', requireApiToken, choices);

    // 1.8.0 of the app knows one page: it keeps editing the account's first.
    mountEditor('/page', (req, res, owner) => ensurePage(owner));

    // Many pages (1.8.1+).
    router.get('/pages', requireApiToken, (req, res) => res.json(listJSON(me(req))));

    router.post('/pages', requireApiToken, json, (req, res) => {
      const owner = me(req);
      const out = pages.createNamed(owner, { handle: req.body && req.body.handle, display_name: req.body && req.body.display_name });
      if (out.error) return res.status(400).json({ ok: false, error: out.error });
      res.json(editorJSON(owner, out.page));
    });

    router.delete('/pages/:id(\\d+)', requireApiToken, (req, res) => {
      const owner = me(req);
      const page = pages.getOwned(req.params.id, owner.id);
      if (!page) return res.status(404).json({ ok: false, error: 'That page is gone — pull down to refresh.' });
      deletePageAndPicture(owner, page);
      res.json(listJSON(owner));
    });

    mountEditor('/pages/:id(\\d+)', (req, res, owner) => {
      const page = pages.getOwned(req.params.id, owner.id);
      if (!page) res.status(404).json({ ok: false, error: 'That page is gone — pull down to refresh.' });
      return page;
    });

    app.use('/api/v1', router);
  }
}

module.exports = { attach };

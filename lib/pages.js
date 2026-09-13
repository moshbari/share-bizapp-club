// "My page" — one public page per person at /@<handle>, like a link-in-bio,
// except the blocks are the person's OWN shares (files, folders, chat
// scrolls) that open right here, not just links out to somewhere else.
//
//   pages        — one row per user: handle, name, bio, picture, theme.
//   page_blocks  — the ordered cards on the page. `kind` says what a block
//                  points at; `ref_slug` is the file/folder/chat slug, `url`
//                  is for a plain link. `gated` = ask for an email first.
//   page_leads   — every email a visitor gave to open a gated block. This
//                  table is the source of truth; GoHighLevel is a copy.
//   page_stats   — per-day counters (page view, block click, email given).
//   note_copies  — per-day Copy counts for notes on folder pages, so the
//                  owner can see which prompt people actually take.
//
// Counters are rolled up per day rather than logged per hit: the owner only
// ever asks "how many in the last 30 days", and a row per view would grow
// without bound for no extra answer.

const { execFile } = require('node:child_process');
const { nanoid } = require('nanoid');
const { raw: db } = require('./db');

db.exec(`
  CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    handle TEXT UNIQUE NOT NULL COLLATE NOCASE,
    display_name TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    theme TEXT NOT NULL DEFAULT 'sunrise',
    published INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS page_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    ref_slug TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    subtitle TEXT NOT NULL DEFAULT '',
    gated INTEGER NOT NULL DEFAULT 0,
    hidden INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_page_blocks_page ON page_blocks(page_id, sort_order DESC);

  CREATE TABLE IF NOT EXISTS page_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    block_id INTEGER REFERENCES page_blocks(id) ON DELETE SET NULL,
    block_title TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    ghl_status TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_page_leads_page ON page_leads(page_id, id DESC);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_page_leads_unique ON page_leads(page_id, block_id, email);

  CREATE TABLE IF NOT EXISTS page_stats (
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    block_id INTEGER NOT NULL DEFAULT 0,
    event TEXT NOT NULL,
    day TEXT NOT NULL,
    n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (page_id, block_id, event, day)
  );

  CREATE TABLE IF NOT EXISTS note_copies (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    day TEXT NOT NULL,
    n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (message_id, day)
  );
`);

// ---- one page per user → many pages per user ----
//
// The first version put UNIQUE on pages.user_id. SQLite can't drop a
// constraint, so the table is rebuilt once: copy, drop, rename. Foreign keys
// are switched OFF around it, because dropping a parent table with them on
// runs an implicit DELETE — and ON DELETE CASCADE would wipe every block,
// lead and stat of every page on the way.
(function allowManyPagesPerUser() {
  const uniqueOnUser = db.prepare(`PRAGMA index_list(pages)`).all().some((ix) => {
    if (!ix.unique) return false;
    const cols = db.prepare(`PRAGMA index_info("${ix.name.replace(/"/g, '""')}")`).all();
    return cols.length === 1 && cols[0].name === 'user_id';
  });
  if (!uniqueOnUser) return;
  const before = db.prepare(`SELECT COUNT(*) AS c FROM pages`).get().c;
  db.pragma('foreign_keys = OFF');
  try {
    db.transaction(() => {
      db.exec(`
        CREATE TABLE pages_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          handle TEXT UNIQUE NOT NULL COLLATE NOCASE,
          display_name TEXT NOT NULL DEFAULT '',
          bio TEXT NOT NULL DEFAULT '',
          avatar_url TEXT NOT NULL DEFAULT '',
          theme TEXT NOT NULL DEFAULT 'sunrise',
          published INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO pages_new (id, user_id, handle, display_name, bio, avatar_url, theme, published, created_at, updated_at)
          SELECT id, user_id, handle, display_name, bio, avatar_url, theme, published, created_at, updated_at FROM pages;
        DROP TABLE pages;
        ALTER TABLE pages_new RENAME TO pages;
      `);
      const after = db.prepare(`SELECT COUNT(*) AS c FROM pages`).get().c;
      if (after !== before) throw new Error(`page migration copied ${after} of ${before} rows`);
      const bad = db.prepare(`PRAGMA foreign_key_check`).all();
      if (bad.length) throw new Error(`page migration left ${bad.length} broken references`);
    })();
    console.log(`[pages] now allows many pages per account (${before} page(s) kept)`);
  } finally {
    db.pragma('foreign_keys = ON');
  }
})();
db.exec(`CREATE INDEX IF NOT EXISTS idx_pages_user ON pages(user_id, id)`);

const KINDS = ['file', 'folder', 'chat', 'link', 'heading'];
// A safety net against runaway scripts, not a plan limit.
const MAX_PAGES_PER_USER = 200;
const THEMES = {
  sunrise:  { label: 'Sunrise (orange + teal)' },
  midnight: { label: 'Midnight (dark)' },
  mint:     { label: 'Mint (fresh green)' },
  mono:     { label: 'Paper (black + white)' },
};

// Words that would collide with a route, or read as official.
const RESERVED = new Set([
  'admin', 'api', 'app', 'account', 'chats', 'upload', 'messages', 'groups', 'login', 'logout',
  'signup', 'support', 'privacy', 'help', 'page', 'pages', 'settings', 'sharezpresso', 'share',
  'root', 'www', 'mail', 'about', 'terms', 'official', 'staff', 'team', 'null', 'undefined',
]);
const HANDLE_RE = /^[a-z0-9](?:[a-z0-9_-]{1,28})[a-z0-9]$/;

/** Returns an error sentence, or '' when the handle is usable. */
function handleProblem(handle) {
  const h = (handle || '').toString().trim().toLowerCase();
  if (!HANDLE_RE.test(h)) return 'Use 3–30 letters, numbers, - or _ (start and end with a letter or number).';
  if (RESERVED.has(h)) return 'That name is reserved — pick another.';
  return '';
}

/** Turn a person's name into a handle suggestion ("Mosh Bari" → "moshbari"). */
function suggestHandle(name, email) {
  const base = (name || (email || '').split('@')[0] || 'me')
    .toString().toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '').slice(0, 24);
  let h = base.length >= 3 ? base : (base + 'page').slice(0, 24);
  if (RESERVED.has(h)) h += 'page';
  if (!P.getByHandle.get(h)) return h;
  for (let i = 2; i < 500; i++) {
    const c = `${h}${i}`;
    if (!P.getByHandle.get(c)) return c;
  }
  return h + nanoid(4).toLowerCase().replace(/[^a-z0-9]/g, 'x');
}

const P = {
  // The account's first page — what the 1.8.0 iPhone app (which knew only
  // one page) keeps editing.
  getByUser: db.prepare(`SELECT * FROM pages WHERE user_id = ? ORDER BY id ASC LIMIT 1`),
  listByUser: db.prepare(`SELECT * FROM pages WHERE user_id = ? ORDER BY id ASC`),
  getById: db.prepare(`SELECT * FROM pages WHERE id = ?`),
  countByUser: db.prepare(`SELECT COUNT(*) AS c FROM pages WHERE user_id = ?`),
  delete: db.prepare(`DELETE FROM pages WHERE id = ?`),
  getByHandle: db.prepare(`SELECT * FROM pages WHERE handle = ? COLLATE NOCASE`),
  insert: db.prepare(`
    INSERT INTO pages (user_id, handle, display_name, bio, theme)
    VALUES (@user_id, @handle, @display_name, @bio, @theme)
  `),
  update: db.prepare(`
    UPDATE pages SET handle = @handle, display_name = @display_name, bio = @bio,
                     theme = @theme, published = @published, updated_at = CURRENT_TIMESTAMP
    WHERE id = @id
  `),
  setAvatar: db.prepare(`UPDATE pages SET avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`),
};

const B = {
  list: db.prepare(`SELECT * FROM page_blocks WHERE page_id = ? ORDER BY sort_order DESC, id DESC`),
  getBySlug: db.prepare(`SELECT * FROM page_blocks WHERE slug = ?`),
  // New blocks go to the BOTTOM of the page (lowest sort_order): a page is
  // read top to bottom, and the owner builds it in that order.
  insert: db.prepare(`
    INSERT INTO page_blocks (slug, page_id, kind, ref_slug, url, title, subtitle, gated, sort_order)
    VALUES (@slug, @page_id, @kind, @ref_slug, @url, @title, @subtitle, @gated,
            COALESCE((SELECT MIN(sort_order) FROM page_blocks WHERE page_id = @page_id), 1000000) - 1)
  `),
  update: db.prepare(`
    UPDATE page_blocks SET title = @title, subtitle = @subtitle, url = @url, gated = @gated, hidden = @hidden
    WHERE id = @id
  `),
  delete: db.prepare(`DELETE FROM page_blocks WHERE id = ?`),
  setSort: db.prepare(`UPDATE page_blocks SET sort_order = ? WHERE id = ? AND page_id = ?`),
  count: db.prepare(`SELECT COUNT(*) AS c FROM page_blocks WHERE page_id = ?`),
};

const L = {
  insert: db.prepare(`
    INSERT OR IGNORE INTO page_leads (page_id, block_id, block_title, email, name)
    VALUES (?, ?, ?, ?, ?)
  `),
  setGhl: db.prepare(`UPDATE page_leads SET ghl_status = ? WHERE id = ?`),
  list: db.prepare(`SELECT * FROM page_leads WHERE page_id = ? ORDER BY id DESC LIMIT ?`),
  count: db.prepare(`SELECT COUNT(*) AS c FROM page_leads WHERE page_id = ?`),
  countDistinct: db.prepare(`SELECT COUNT(DISTINCT email) AS c FROM page_leads WHERE page_id = ?`),
};

const S = {
  bump: db.prepare(`
    INSERT INTO page_stats (page_id, block_id, event, day, n) VALUES (?, ?, ?, date('now'), 1)
    ON CONFLICT(page_id, block_id, event, day) DO UPDATE SET n = n + 1
  `),
  totals: db.prepare(`
    SELECT block_id, event, SUM(n) AS n FROM page_stats
    WHERE page_id = ? AND day >= date('now', ?)
    GROUP BY block_id, event
  `),
  copyBump: db.prepare(`
    INSERT INTO note_copies (message_id, day, n) VALUES (?, date('now'), 1)
    ON CONFLICT(message_id, day) DO UPDATE SET n = n + 1
  `),
  // Copies of every note inside a folder, last N days, one row per note.
  copiesInGroup: db.prepare(`
    SELECT m.slug, m.title, COALESCE(SUM(c.n), 0) AS n
    FROM messages m
    LEFT JOIN note_copies c ON c.message_id = m.id AND c.day >= date('now', ?)
    WHERE m.group_id = ?
    GROUP BY m.id
    ORDER BY n DESC, m.group_position DESC
  `),
};

const pages = {
  KINDS, THEMES, MAX_PAGES_PER_USER,
  handleProblem, suggestHandle,

  getByUser(userId) { return P.getByUser.get(userId) || null; },
  listByUser(userId) { return P.listByUser.all(userId); },
  getById(id) { return P.getById.get(Number(id) || 0) || null; },
  /** A page only if it belongs to this user — the one lookup every owner route uses. */
  getOwned(id, userId) {
    const p = P.getById.get(Number(id) || 0);
    return p && p.user_id === userId ? p : null;
  },
  countByUser(userId) { return P.countByUser.get(userId).c; },
  deletePage(page) { P.delete.run(page.id); },
  getByHandle(handle) { return P.getByHandle.get((handle || '').toString()) || null; },

  /** The first page, made automatically with a suggested address. */
  create(user) {
    return pages.createNamed(user, {}).page;
  },

  /**
   * A new page. `handle` is optional — left blank, one is suggested from the
   * name. Returns { page } or { error }.
   */
  createNamed(user, { handle, display_name } = {}) {
    if (P.countByUser.get(user.id).c >= MAX_PAGES_PER_USER) {
      return { error: `You already have ${MAX_PAGES_PER_USER} pages.` };
    }
    const name = (display_name || user.name || '').toString().trim().slice(0, 80);
    let h = (handle || '').toString().trim().toLowerCase().replace(/^@/, '');
    if (h) {
      const problem = handleProblem(h);
      if (problem) return { error: problem };
      if (P.getByHandle.get(h)) return { error: `@${h} is already taken — try another.` };
    } else {
      h = suggestHandle(name || user.name, user.email);
    }
    const res = P.insert.run({ user_id: user.id, handle: h, display_name: name, bio: '', theme: 'sunrise' });
    return { page: P.getById.get(res.lastInsertRowid) };
  },

  /** Returns '' on success or a sentence saying what's wrong. */
  updateProfile(page, { handle, display_name, bio, theme, published }) {
    const h = (handle || '').toString().trim().toLowerCase();
    const problem = handleProblem(h);
    if (problem) return problem;
    const taken = P.getByHandle.get(h);
    if (taken && taken.id !== page.id) return `@${h} is already taken — try another.`;
    P.update.run({
      id: page.id,
      handle: h,
      display_name: (display_name || '').toString().trim().slice(0, 80),
      bio: (bio || '').toString().trim().slice(0, 300),
      theme: THEMES[theme] ? theme : 'sunrise',
      published: published ? 1 : 0,
    });
    return '';
  },

  setAvatar(pageId, url) { P.setAvatar.run(url || '', pageId); },

  blocks(pageId) { return B.list.all(pageId); },
  blockBySlug(slug) { return B.getBySlug.get((slug || '').toString()) || null; },
  countBlocks(pageId) { return B.count.get(pageId).c; },

  addBlock(pageId, { kind, ref_slug = '', url = '', title = '', subtitle = '', gated = false }) {
    const slug = nanoid(10);
    B.insert.run({
      slug, page_id: pageId, kind,
      ref_slug: (ref_slug || '').toString().slice(0, 64),
      url: (url || '').toString().slice(0, 2000),
      title: (title || '').toString().slice(0, 120),
      subtitle: (subtitle || '').toString().slice(0, 200),
      gated: gated ? 1 : 0,
    });
    return B.getBySlug.get(slug);
  },

  updateBlock(block, fields) {
    B.update.run({
      id: block.id,
      title: (fields.title ?? block.title).toString().slice(0, 120),
      subtitle: (fields.subtitle ?? block.subtitle).toString().slice(0, 200),
      url: (fields.url ?? block.url).toString().slice(0, 2000),
      gated: (fields.gated ?? block.gated) ? 1 : 0,
      hidden: (fields.hidden ?? block.hidden) ? 1 : 0,
    });
    return B.getBySlug.get(block.slug);
  },

  deleteBlock(block) { B.delete.run(block.id); },

  /** slugs top-to-bottom. Blocks of other pages are ignored. */
  reorderBlocks(pageId, slugs) {
    if (!Array.isArray(slugs)) return 0;
    const own = new Map(B.list.all(pageId).map(b => [b.slug, b]));
    const ordered = [];
    for (const s of slugs.slice(0, 500)) {
      const b = own.get(String(s));
      if (b && !ordered.includes(b)) ordered.push(b);
    }
    // Anything the client didn't send keeps its place below the sent ones.
    for (const b of own.values()) if (!ordered.includes(b)) ordered.push(b);
    const total = ordered.length;
    db.transaction(() => {
      ordered.forEach((b, i) => B.setSort.run(total - i, b.id, pageId));
    })();
    return total;
  },

  /** Returns the new lead row, or null when this email already had it. */
  addLead(page, block, { email, name, title }) {
    const res = L.insert.run(page.id, block ? block.id : null, (title || (block && block.title) || '').toString().slice(0, 120),
      email.toLowerCase().trim().slice(0, 200), (name || '').toString().trim().slice(0, 80));
    if (!res.changes) return null;
    return { id: res.lastInsertRowid };
  },
  setLeadGhlStatus(leadId, status) { L.setGhl.run((status || '').slice(0, 300), leadId); },
  leads(pageId, limit = 200) { return L.list.all(pageId, Math.max(1, Math.min(100000, limit | 0))); },
  leadCount(pageId) { return L.countDistinct.get(pageId).c; },

  bump(pageId, blockId, event) {
    try { S.bump.run(pageId, blockId || 0, event); } catch (e) { console.warn('[page-stats]', e.message); }
  },
  /** { page: {view}, blocks: { [blockId]: {click, lead} } } over the last `days`. */
  totals(pageId, days = 30) {
    const out = { page: {}, blocks: {} };
    for (const r of S.totals.all(pageId, `-${Math.max(1, days | 0) - 1} days`)) {
      if (!r.block_id) out.page[r.event] = r.n;
      else (out.blocks[r.block_id] = out.blocks[r.block_id] || {})[r.event] = r.n;
    }
    return out;
  },

  bumpNoteCopy(messageId) {
    try { S.copyBump.run(messageId); } catch (e) { console.warn('[note-copies]', e.message); }
  },
  copiesInGroup(groupId, days = 30) {
    return S.copiesInGroup.all(`-${Math.max(1, days | 0) - 1} days`, groupId);
  },
};

// ---------- GoHighLevel contact push ----------
//
// Best-effort copy of a lead into the page owner's GHL sub-account, tagged so
// they can build a workflow off it. It runs with `execFile` (async) rather
// than the execFileSync the media upload uses: a visitor is waiting on this
// request, and one slow GHL call must not freeze every other page view.

function upsertGhlContact(cfg, { email, name, tags, source }) {
  return new Promise((resolve) => {
    if (!cfg || !cfg.apiKey || !cfg.locationId) return resolve({ ok: false, error: 'GHL not connected' });
    const parts = (name || '').trim().split(/\s+/).filter(Boolean);
    const body = JSON.stringify({
      locationId: cfg.locationId,
      email,
      firstName: parts[0] || undefined,
      lastName: parts.slice(1).join(' ') || undefined,
      tags,
      source,
    });
    execFile('curl', [
      '-s', '-S', '--max-time', '15',
      '-w', '\n%{http_code}',
      '-X', 'POST', 'https://services.leadconnectorhq.com/contacts/upsert',
      '-H', `Authorization: Bearer ${cfg.apiKey}`,
      '-H', 'Version: 2021-07-28',
      '-H', 'Content-Type: application/json',
      '--data-binary', body,
    ], { encoding: 'utf8', maxBuffer: 1024 * 1024 }, (err, stdout) => {
      if (err && !stdout) return resolve({ ok: false, error: `network: ${(err.message || '').slice(0, 120)}` });
      const out = (stdout || '').trimEnd();
      const code = parseInt(out.slice(out.lastIndexOf('\n') + 1), 10);
      const text = out.slice(0, out.lastIndexOf('\n'));
      if (code >= 200 && code < 300) return resolve({ ok: true });
      let msg = text.slice(0, 160);
      try { const j = JSON.parse(text); msg = j.message || j.msg || msg; } catch {}
      if (code === 401 || code === 403) msg = `GHL refused (${code}) — the token needs the contacts.write scope. ${msg}`;
      resolve({ ok: false, error: `HTTP ${code}: ${String(msg).slice(0, 200)}` });
    });
  });
}

module.exports = { pages, upsertGhlContact };

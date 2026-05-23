// SQLite wrapper. Two tables now that we've gone multi-tenant:
//
//   users — one row per account. `status` drives the upload cap in lib/users.js:
//       trial       → one file per kind (image/video/audio/pdf/text)
//       regular     → unlimited uploads
//       deactivated → cannot log in, cannot upload
//
//   files — one row per uploaded file, owned by a user via `user_id`.
//
// We don't use a migration framework; schema changes happen idempotently at
// boot. `maybeAddColumn` is the SQLite equivalent of `ADD COLUMN IF NOT EXISTS`
// — ALTER TABLE ADD COLUMN without a pre-check errors on a column that
// already exists, which would kill the container after the first deploy.

const Database = require('better-sqlite3');
const path = require('node:path');
const fs = require('node:fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'share.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'trial',
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    original_filename TEXT NOT NULL,
    kind TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    download_allowed INTEGER NOT NULL DEFAULT 1,
    ghl_url TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_files_slug ON files(slug);
`);

function maybeAddColumn(table, column, decl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (cols.some(c => c.name === column)) return false;
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
  return true;
}

// files.user_id is added post-hoc because the single-user prototype didn't
// have one. New deployments get it right away via the CREATE TABLE; existing
// deployments (listen-clone-shaped) pick it up here.
maybeAddColumn('files', 'user_id', 'INTEGER REFERENCES users(id) ON DELETE CASCADE');
db.exec(`CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);`);

// Per-user GHL config. All four columns are nullable — a NULL means "fall
// back to the shared env vars". ghl_folder_name is kept for display only;
// the ghl_folder_id is what actually targets the upload.
maybeAddColumn('users', 'ghl_api_key',     'TEXT');
maybeAddColumn('users', 'ghl_location_id', 'TEXT');
maybeAddColumn('users', 'ghl_folder_id',   'TEXT');
maybeAddColumn('users', 'ghl_folder_name', 'TEXT');

// Password reset tokens. We store the SHA-256 hash of the token, not the
// token itself — a leak of the DB doesn't grant anyone a working reset
// link. Single-use: once used_at is set, the token is dead.
db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_password_resets_hash ON password_resets(token_hash);
  CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
`);

// Progressive-signup support: guests can upload a file before providing
// an email. `activated=0` means the file isn't publicly viewable yet —
// /f/:slug shows a "waiting for activation" page. `guest_id` is a signed
// cookie value so a user can claim their own uploads when they click a
// magic link. `pending_email` stores the email they entered (for admin
// visibility and logs).
maybeAddColumn('files', 'activated',     'INTEGER NOT NULL DEFAULT 1');
maybeAddColumn('files', 'guest_id',      'TEXT');
maybeAddColumn('files', 'pending_email', 'TEXT');

db.exec(`
  CREATE TABLE IF NOT EXISTS magic_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    guest_id TEXT,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_magic_links_hash ON magic_links(token_hash);

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id);
  CREATE INDEX IF NOT EXISTS idx_messages_slug ON messages(slug);
`);

// Reorderable message ranking. Higher sort_order = higher in the list.
// Backfill any existing rows with sort_order = id so current visual
// order is preserved on first deploy of this feature.
maybeAddColumn('messages', 'sort_order', 'INTEGER NOT NULL DEFAULT 0');
db.prepare(`UPDATE messages SET sort_order = id WHERE sort_order = 0`).run();
db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_user_sort ON messages(user_id, sort_order DESC)`);

// Groups: a message belongs to AT MOST one group (1:1 for v1; if we
// ever need many-to-many we'd add a join table). Deleting a group
// orphans its children back to standalone via ON DELETE SET NULL.
db.exec(`
  CREATE TABLE IF NOT EXISTS message_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_message_groups_user_sort ON message_groups(user_id, sort_order DESC);
  CREATE INDEX IF NOT EXISTS idx_message_groups_slug ON message_groups(slug);
`);
maybeAddColumn('messages', 'group_id', 'INTEGER REFERENCES message_groups(id) ON DELETE SET NULL');
maybeAddColumn('messages', 'group_position', 'INTEGER NOT NULL DEFAULT 0');
db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id, group_position DESC)`);

// ---------- prepared statements ----------

const U = {
  insert: db.prepare(`
    INSERT INTO users (email, name, password_hash, status, is_admin)
    VALUES (@email, @name, @password_hash, @status, @is_admin)
  `),
  getById: db.prepare(`SELECT * FROM users WHERE id = ?`),
  getByEmail: db.prepare(`SELECT * FROM users WHERE email = ? COLLATE NOCASE`),
  list: db.prepare(`SELECT * FROM users ORDER BY id DESC`),
  updatePassword: db.prepare(`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`),
  updateStatus: db.prepare(`UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`),
  updateProfile: db.prepare(`UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`),
  setAdmin: db.prepare(`UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`),
  setGhlConfig: db.prepare(`
    UPDATE users SET
      ghl_api_key = ?, ghl_location_id = ?, ghl_folder_id = ?, ghl_folder_name = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `),
  deleteById: db.prepare(`DELETE FROM users WHERE id = ?`),
  countByStatus: db.prepare(`SELECT status, COUNT(*) AS c FROM users GROUP BY status`),
};

const F = {
  insert: db.prepare(`
    INSERT INTO files (slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, user_id, activated, guest_id, pending_email)
    VALUES (@slug, @title, @original_filename, @kind, @mime_type, @size_bytes, @download_allowed, @ghl_url, @user_id, @activated, @guest_id, @pending_email)
  `),
  listPendingByGuest: db.prepare(`
    SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, ghl_url, activated
    FROM files WHERE guest_id = ? AND activated = 0 ORDER BY id ASC
  `),
  claimPendingForGuest: db.prepare(`
    UPDATE files
    SET user_id = ?, activated = 1, guest_id = NULL, pending_email = NULL
    WHERE activated = 0 AND (guest_id = ? OR pending_email = ?)
  `),
  countPendingForGuest: db.prepare(`
    SELECT COUNT(*) AS c FROM files
    WHERE activated = 0 AND (guest_id = ? OR pending_email = ?)
  `),
  listPendingByGuestOrEmail: db.prepare(`
    SELECT id, slug, kind, ghl_url FROM files
    WHERE activated = 0 AND (guest_id = ? OR pending_email = ?)
    ORDER BY id ASC
  `),
  activateByIds: (ids, userId) => {
    if (!ids.length) return 0;
    const placeholders = ids.map(() => '?').join(',');
    const stmt = db.prepare(`
      UPDATE files
      SET user_id = ?, activated = 1, guest_id = NULL, pending_email = NULL
      WHERE id IN (${placeholders}) AND activated = 0
    `);
    return stmt.run(userId, ...ids).changes;
  },
  deleteByIds: (ids) => {
    if (!ids.length) return 0;
    const placeholders = ids.map(() => '?').join(',');
    return db.prepare(`DELETE FROM files WHERE id IN (${placeholders})`).run(...ids).changes;
  },
  setPendingEmailForGuest: db.prepare(`
    UPDATE files SET pending_email = ? WHERE guest_id = ? AND activated = 0
  `),
  listExpiredPending: db.prepare(`
    SELECT id, slug, ghl_url FROM files
    WHERE activated = 0 AND created_at < datetime('now','-24 hours')
  `),
  deleteById: db.prepare(`DELETE FROM files WHERE id = ?`),
  getBySlug: db.prepare(`
    SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at, user_id,
           activated, guest_id, pending_email
    FROM files WHERE slug = ?
  `),
  listPageByUser: db.prepare(`
    SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at, user_id
    FROM files WHERE user_id = ? AND activated = 1 AND id < ?
    ORDER BY id DESC LIMIT ?
  `),
  countByUserAndKind: db.prepare(`SELECT COUNT(*) AS c FROM files WHERE user_id = ? AND activated = 1 AND kind = ?`),
  countByUser: db.prepare(`SELECT COUNT(*) AS c FROM files WHERE user_id = ? AND activated = 1`),
  listByUser: db.prepare(`SELECT ghl_url FROM files WHERE user_id = ?`),
  updateTitle: db.prepare(`UPDATE files SET title = ? WHERE slug = ? AND user_id = ?`),
  updateDownloadFlag: db.prepare(`UPDATE files SET download_allowed = ? WHERE slug = ? AND user_id = ?`),
  deleteBySlugForUser: db.prepare(`DELETE FROM files WHERE slug = ? AND user_id = ?`),
  deleteByUserId: db.prepare(`DELETE FROM files WHERE user_id = ?`),
  // Admin list (not filtered by user) — for the future all-users view if wanted
  listPageAll: db.prepare(`
    SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at, user_id
    FROM files WHERE id < ?
    ORDER BY id DESC LIMIT ?
  `),
  backfillNullUser: db.prepare(`UPDATE files SET user_id = ? WHERE user_id IS NULL`),
};

const FIRST_PAGE_CURSOR = Number.MAX_SAFE_INTEGER;

// ---------- user API ----------

const users = {
  insert(row) {
    const res = U.insert.run({
      email: (row.email || '').toLowerCase().trim(),
      name: (row.name || '').trim(),
      password_hash: row.password_hash,
      status: row.status || 'trial',
      is_admin: row.is_admin ? 1 : 0,
    });
    return res.lastInsertRowid;
  },
  getById(id) { return U.getById.get(id) || null; },
  getByEmail(email) {
    if (!email) return null;
    return U.getByEmail.get(email.trim()) || null;
  },
  list() { return U.list.all(); },
  setPasswordHash(id, hash) { return U.updatePassword.run(hash, id).changes > 0; },
  setStatus(id, status) {
    if (!['trial', 'regular', 'deactivated'].includes(status)) {
      throw new Error(`invalid status: ${status}`);
    }
    return U.updateStatus.run(status, id).changes > 0;
  },
  updateProfile(id, { name }) {
    return U.updateProfile.run((name || '').trim(), id).changes > 0;
  },
  setAdmin(id, flag) { return U.setAdmin.run(flag ? 1 : 0, id).changes > 0; },
  /**
   * Set all four GHL config columns at once. Pass `null` for every field
   * to clear the user's custom config and fall back to the shared env.
   */
  setGhlConfig(id, { apiKey, locationId, folderId, folderName } = {}) {
    return U.setGhlConfig.run(
      apiKey || null,
      locationId || null,
      folderId || null,
      folderName || null,
      id,
    ).changes > 0;
  },
  deleteById(id) { return U.deleteById.run(id).changes > 0; },
  countByStatus() {
    const rows = U.countByStatus.all();
    return rows.reduce((acc, r) => { acc[r.status] = r.c; return acc; }, {});
  },
};

// ---------- file API (scoped to owner) ----------

const files = {
  insert(row) {
    F.insert.run({
      slug: row.slug,
      title: row.title || '',
      original_filename: row.original_filename || '',
      kind: row.kind,
      mime_type: row.mime_type || 'application/octet-stream',
      size_bytes: row.size_bytes || 0,
      download_allowed: row.download_allowed ? 1 : 0,
      ghl_url: row.ghl_url || '',
      user_id: row.user_id != null ? row.user_id : null,
      // Authed uploads default to activated=1. Guest uploads pass
      // activated=0 explicitly so they stay hidden until the magic
      // link is clicked.
      activated: row.activated != null ? (row.activated ? 1 : 0) : 1,
      guest_id: row.guest_id || null,
      pending_email: row.pending_email || null,
    });
  },
  listPendingByGuest(guestId) {
    return F.listPendingByGuest.all(guestId);
  },
  /**
   * Claim all pending files that match EITHER guestId (cookie-based) OR
   * email (magic-link-based). Matching by email is the fallback when the
   * user's guest cookie is lost or invalidated between upload and
   * activation — a surprisingly common scenario across deploys, browser
   * changes, or cookie-clearing. Returns the number of rows activated.
   */
  claimPendingForGuest(userId, guestId, email) {
    return F.claimPendingForGuest.run(userId, guestId || '', email || '').changes;
  },
  countPendingMatching(guestId, email) {
    return F.countPendingForGuest.get(guestId || '', email || '').c;
  },
  listPendingMatching(guestId, email) {
    return F.listPendingByGuestOrEmail.all(guestId || '', email || '');
  },
  activateByIds(ids, userId) { return F.activateByIds(ids, userId); },
  deleteByIds(ids) { return F.deleteByIds(ids); },
  setPendingEmailForGuest(guestId, emailAddr) {
    return F.setPendingEmailForGuest.run(emailAddr, guestId).changes;
  },
  /**
   * Return + delete expired pending rows. Caller fires GHL deletes.
   */
  listAndDeleteExpiredPending() {
    const rows = F.listExpiredPending.all();
    for (const r of rows) F.deleteById.run(r.id);
    return rows;
  },
  getBySlug(slug) { return F.getBySlug.get(slug) || null; },
  listRecentByUser(userId, { before, limit = 10 } = {}) {
    const cursor = Number.isFinite(before) ? before : FIRST_PAGE_CURSOR;
    const cap = Math.max(1, Math.min(50, limit | 0 || 10));
    return F.listPageByUser.all(userId, cursor, cap);
  },
  /**
   * Filtered variant of listRecentByUser. Supports optional kind, title/
   * filename search (LIKE), and date range on created_at.
   *
   * Built as a dynamic query because the active filter combos vary —
   * better-sqlite3 caches prepared statements by SQL text so repeated
   * combos reuse the same prepared statement, so this stays fast.
   */
  listRecentFilteredByUser(userId, { before, limit = 10, kind, q, from, to } = {}) {
    const conds = ['user_id = ?', 'activated = 1'];
    const params = [userId];
    if (Number.isFinite(before) && before > 0) {
      conds.push('id < ?');
      params.push(before);
    }
    if (kind) {
      conds.push('kind = ?');
      params.push(kind);
    }
    if (q) {
      // Matches the search text anywhere in title or original_filename,
      // case-insensitive via SQLite's LIKE default (ASCII case fold).
      conds.push('(title LIKE ? OR original_filename LIKE ?)');
      const like = '%' + q + '%';
      params.push(like, like);
    }
    if (from) {
      conds.push('date(created_at) >= date(?)');
      params.push(from);
    }
    if (to) {
      conds.push('date(created_at) <= date(?)');
      params.push(to);
    }
    const cap = Math.max(1, Math.min(50, limit | 0 || 10));
    params.push(cap);
    const sql = `
      SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at, user_id
      FROM files
      WHERE ${conds.join(' AND ')}
      ORDER BY id DESC
      LIMIT ?
    `;
    return db.prepare(sql).all(...params);
  },
  countByUserAndKind(userId, kind) {
    return F.countByUserAndKind.get(userId, kind).c;
  },
  countByUser(userId) { return F.countByUser.get(userId).c; },
  listByUser(userId) { return F.listByUser.all(userId); },
  updateTitle(slug, userId, title) {
    return F.updateTitle.run((title || '').toString().slice(0, 200), slug, userId).changes > 0;
  },
  setDownloadAllowed(slug, userId, allowed) {
    return F.updateDownloadFlag.run(allowed ? 1 : 0, slug, userId).changes > 0;
  },
  /** Delete by slug for a given owner. Returns the ghl_url for cleanup. */
  deleteBySlugForUser(slug, userId) {
    const row = F.getBySlug.get(slug);
    if (!row || row.user_id !== userId) return null;
    F.deleteBySlugForUser.run(slug, userId);
    return row.ghl_url;
  },
  /** Delete all files belonging to a user. Returns the list of ghl_urls. */
  deleteAllByUser(userId) {
    const rows = F.listByUser.all(userId);
    F.deleteByUserId.run(userId);
    return rows.map(r => r.ghl_url);
  },
  /** Backfill: any NULL user_ids get pinned to the given admin id. */
  backfillNullUserTo(userId) {
    return F.backfillNullUser.run(userId).changes;
  },
};

// ---------- password reset statements ----------

const PR = {
  insert: db.prepare(`
    INSERT INTO password_resets (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `),
  getByHash: db.prepare(`
    SELECT id, user_id, token_hash, expires_at, used_at, created_at
    FROM password_resets WHERE token_hash = ?
  `),
  markUsed: db.prepare(`
    UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?
  `),
  // Delete anything expired or older than 30 days — prevents the table
  // growing unbounded if the sweep cron isn't set up.
  sweep: db.prepare(`
    DELETE FROM password_resets
    WHERE (used_at IS NOT NULL AND used_at < datetime('now','-7 days'))
       OR expires_at < datetime('now','-1 day')
  `),
  // Invalidate any outstanding tokens for a user when a new one is issued
  // (or when they log in successfully / change password).
  invalidateForUser: db.prepare(`
    UPDATE password_resets SET used_at = CURRENT_TIMESTAMP
    WHERE user_id = ? AND used_at IS NULL
  `),
};

const passwordResets = {
  create({ userId, tokenHash, expiresAt }) {
    PR.insert.run(userId, tokenHash, expiresAt);
  },
  getByHash(tokenHash) {
    return PR.getByHash.get(tokenHash) || null;
  },
  markUsed(tokenHash) {
    return PR.markUsed.run(tokenHash).changes > 0;
  },
  sweep() {
    return PR.sweep.run().changes;
  },
  invalidateForUser(userId) {
    return PR.invalidateForUser.run(userId).changes;
  },
};

// ---------- magic link statements ----------

const ML = {
  insert: db.prepare(`
    INSERT INTO magic_links (token_hash, email, guest_id, expires_at)
    VALUES (?, ?, ?, ?)
  `),
  getByHash: db.prepare(`
    SELECT id, token_hash, email, guest_id, expires_at, used_at, created_at
    FROM magic_links WHERE token_hash = ?
  `),
  markUsed: db.prepare(`UPDATE magic_links SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?`),
  sweep: db.prepare(`
    DELETE FROM magic_links
    WHERE (used_at IS NOT NULL AND used_at < datetime('now','-1 day'))
       OR expires_at < datetime('now','-1 day')
  `),
};

const magicLinks = {
  create({ tokenHash, email, guestId, expiresAt }) {
    ML.insert.run(tokenHash, email, guestId || null, expiresAt);
  },
  getByHash(tokenHash) { return ML.getByHash.get(tokenHash) || null; },
  markUsed(tokenHash) { return ML.markUsed.run(tokenHash).changes > 0; },
  sweep() { return ML.sweep.run().changes; },
};

// ---------- messages (DM/snippet library) ----------
//
// Plain-text formatted messages users save for re-pasting into
// Instagram, WhatsApp, Facebook DMs, etc. Body preserves whitespace,
// line breaks and emojis verbatim — the whole point is exact-format
// copy/paste. Slug is public via /m/<slug>; the list page is private
// to the owner.

const M = {
  // sort_order on insert = current MAX for this user + 1, so a new
  // message always lands at the top. COALESCE handles empty-list (1).
  insert: db.prepare(`
    INSERT INTO messages (slug, user_id, title, body, sort_order)
    VALUES (?, ?, ?, ?,
      COALESCE((SELECT MAX(sort_order) FROM messages WHERE user_id = ?), 0) + 1
    )
  `),
  getBySlug: db.prepare(`
    SELECT id, slug, user_id, title, body, sort_order, created_at, updated_at
    FROM messages WHERE slug = ?
  `),
  getByIdForUser: db.prepare(`
    SELECT id, slug, user_id, title, body, sort_order, created_at, updated_at
    FROM messages WHERE id = ? AND user_id = ?
  `),
  getBySlugForUser: db.prepare(`
    SELECT id, slug, user_id, title, body, sort_order, created_at, updated_at
    FROM messages WHERE slug = ? AND user_id = ?
  `),
  // Cursor-based pagination ordered by sort_order DESC. The cursor is
  // the lowest sort_order from the previous page so the next fetch
  // picks up cleanly from where we left off. Filters out grouped
  // messages — those render inside their group card, not the top-level feed.
  listFiltered: db.prepare(`
    SELECT id, slug, title, body, sort_order, group_id, created_at, updated_at
    FROM messages
    WHERE user_id = ? AND group_id IS NULL AND sort_order < ?
      AND (? = '' OR title LIKE ? OR body LIKE ?)
    ORDER BY sort_order DESC
    LIMIT ?
  `),
  // All messages inside a group, ordered by group_position DESC.
  listInGroup: db.prepare(`
    SELECT id, slug, title, body, group_position, created_at
    FROM messages
    WHERE group_id = ? AND user_id = ?
    ORDER BY group_position DESC, id DESC
  `),
  // Move a message into a group (or out of one with NULL).
  setGroup: db.prepare(`
    UPDATE messages
    SET group_id = ?, group_position = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND user_id = ?
  `),
  maxGroupPosition: db.prepare(`
    SELECT COALESCE(MAX(group_position), 0) AS m
    FROM messages WHERE group_id = ?
  `),
  countByUser: db.prepare(`SELECT COUNT(*) AS c FROM messages WHERE user_id = ?`),
  update: db.prepare(`
    UPDATE messages SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND user_id = ?
  `),
  // Rewrite group_position for an ordered list of slugs inside one
  // group, in a single transaction. The first slug in `slugs` ends up
  // at the top (highest group_position, because listInGroup orders by
  // group_position DESC). Slugs that don't belong to (groupId, userId)
  // are silently skipped — the API layer validates ownership first
  // but this is defensive too.
  reorderTilesInGroup: function ({ groupId, userId, slugs }) {
    if (!Array.isArray(slugs) || slugs.length === 0) return { ok: true, updated: 0 };
    const update = db.prepare(
      'UPDATE messages SET group_position = ? WHERE slug = ? AND user_id = ? AND group_id = ?'
    );
    let updated = 0;
    const total = slugs.length;
    db.transaction(() => {
      slugs.forEach((slug, idx) => {
        // Highest position for index 0 so it sorts to the top.
        const pos = total - idx;
        const info = update.run(pos, slug, userId, groupId);
        if (info.changes > 0) updated += 1;
      });
    })();
    return { ok: true, updated };
  },
    deleteByIdForUser: db.prepare(`DELETE FROM messages WHERE id = ? AND user_id = ?`),
  // Find the row with next-higher / next-lower sort_order in the
  // user's list — used for "move up" / "move down".
  findAboveForUser: db.prepare(`
    SELECT id, sort_order FROM messages
    WHERE user_id = ? AND sort_order > ?
    ORDER BY sort_order ASC LIMIT 1
  `),
  findBelowForUser: db.prepare(`
    SELECT id, sort_order FROM messages
    WHERE user_id = ? AND sort_order < ?
    ORDER BY sort_order DESC LIMIT 1
  `),
  setSortOrder: db.prepare(`UPDATE messages SET sort_order = ? WHERE id = ?`),
};

const messages = {
  insert({ slug, userId, title, body }) {
    // userId appears twice — once as the FK and once inside the
    // MAX(sort_order) subquery so the new row goes to the top of
    // *this user's* list, not globally.
    M.insert.run(slug, userId, (title || '').slice(0, 200), body || '', userId);
  },
  getBySlug(slug) { return M.getBySlug.get(slug) || null; },
  getBySlugForUser(slug, userId) { return M.getBySlugForUser.get(slug, userId) || null; },
  /**
   * Return a page of the user's messages, optionally filtered by a
   * search string that matches title OR body. `before` is the lowest
   * sort_order from the previous page (cursor).
   */
  listRecentByUser(userId, { before, limit = 20, q } = {}) {
    const cursor = Number.isFinite(before) ? before : Number.MAX_SAFE_INTEGER;
    const cap = Math.max(1, Math.min(100, limit | 0 || 20));
    const needle = q ? '%' + q + '%' : '';
    const qParam = q || '';
    return M.listFiltered.all(userId, cursor, qParam, needle, needle, cap);
  },
  countByUser(userId) { return M.countByUser.get(userId).c; },
  update(id, userId, { title, body }) {
    return M.update.run((title || '').slice(0, 200), body || '', id, userId).changes > 0;
  },
  deleteByIdForUser(id, userId) {
    return M.deleteByIdForUser.run(id, userId).changes > 0;
  },
  /** Children of a group, newest first. Belongs-to-user enforced. */
  listInGroup(groupId, userId) {
    return M.listInGroup.all(groupId, userId);
  },
  /**
   * Move a message into a group (or back to standalone via groupId=null).
   * When entering a group, group_position becomes MAX+1 so the new
   * tile lands at the top of that group.
   */
  moveToGroup(slug, userId, groupId) {
    const cur = M.getBySlugForUser.get(slug, userId);
    if (!cur) return { ok: false, reason: 'not found' };
    let pos = 0;
    if (groupId) {
      pos = (M.maxGroupPosition.get(groupId).m || 0) + 1;
    }
    M.setGroup.run(groupId || null, pos, cur.id, userId);
    return { ok: true };
  },
  /**
   * Swap sort_order with the adjacent message in this user's list.
   * direction: 'up' (move higher) or 'down' (move lower).
   * Returns { ok, swappedSlug? , reason? }.
   */
  move(slug, userId, direction) {
    const cur = M.getBySlugForUser.get(slug, userId);
    if (!cur) return { ok: false, reason: 'not found' };
    const adj = direction === 'up'
      ? M.findAboveForUser.get(userId, cur.sort_order)
      : M.findBelowForUser.get(userId, cur.sort_order);
    if (!adj) {
      return { ok: false, reason: direction === 'up' ? 'already at top' : 'already at bottom' };
    }
    // Swap sort_order in a transaction so a crash mid-swap can't
    // leave two rows with the same sort_order.
    db.transaction(() => {
      M.setSortOrder.run(adj.sort_order, cur.id);
      M.setSortOrder.run(cur.sort_order, adj.id);
    })();
    return { ok: true };
  },
};

// ---------- message_groups (matrix-tile collections) ----------

const MG = {
  // sort_order on insert = current MAX for this user + 1
  insert: db.prepare(`
    INSERT INTO message_groups (slug, user_id, title, sort_order)
    VALUES (?, ?, ?,
      COALESCE((SELECT MAX(sort_order) FROM message_groups WHERE user_id = ?), 0) + 1
    )
  `),
  getBySlugForUser: db.prepare(`
    SELECT id, slug, user_id, title, sort_order, created_at, updated_at
    FROM message_groups WHERE slug = ? AND user_id = ?
  `),
  getById: db.prepare(`SELECT * FROM message_groups WHERE id = ?`),
  listForUser: db.prepare(`
    SELECT id, slug, title, sort_order, created_at, updated_at
    FROM message_groups
    WHERE user_id = ? AND sort_order < ?
    ORDER BY sort_order DESC
    LIMIT ?
  `),
  rename: db.prepare(`
    UPDATE message_groups SET title = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND user_id = ?
  `),
  setSortOrder: db.prepare(`UPDATE message_groups SET sort_order = ? WHERE id = ?`),
  findAboveForUser: db.prepare(`
    SELECT id, sort_order FROM message_groups
    WHERE user_id = ? AND sort_order > ?
    ORDER BY sort_order ASC LIMIT 1
  `),
  findBelowForUser: db.prepare(`
    SELECT id, sort_order FROM message_groups
    WHERE user_id = ? AND sort_order < ?
    ORDER BY sort_order DESC LIMIT 1
  `),
  deleteByIdForUser: db.prepare(`DELETE FROM message_groups WHERE id = ? AND user_id = ?`),
  countForUser: db.prepare(`SELECT COUNT(*) AS c FROM message_groups WHERE user_id = ?`),
};

const groups = {
  insert({ slug, userId, title }) {
    MG.insert.run(slug, userId, (title || '').slice(0, 200), userId);
  },
  getBySlugForUser(slug, userId) { return MG.getBySlugForUser.get(slug, userId) || null; },
  listForUser(userId, { before, limit = 50 } = {}) {
    const cursor = Number.isFinite(before) ? before : Number.MAX_SAFE_INTEGER;
    const cap = Math.max(1, Math.min(200, limit | 0 || 50));
    return MG.listForUser.all(userId, cursor, cap);
  },
  rename(id, userId, title) {
    return MG.rename.run((title || '').slice(0, 200), id, userId).changes > 0;
  },
  /** Swap sort_order with the adjacent group in the user's top-level feed. */
  move(slug, userId, direction) {
    const cur = MG.getBySlugForUser.get(slug, userId);
    if (!cur) return { ok: false, reason: 'not found' };
    const adj = direction === 'up'
      ? MG.findAboveForUser.get(userId, cur.sort_order)
      : MG.findBelowForUser.get(userId, cur.sort_order);
    if (!adj) {
      return { ok: false, reason: direction === 'up' ? 'already at top' : 'already at bottom' };
    }
    db.transaction(() => {
      MG.setSortOrder.run(adj.sort_order, cur.id);
      MG.setSortOrder.run(cur.sort_order, adj.id);
    })();
    return { ok: true };
  },
  /** Delete a group. ON DELETE SET NULL on messages.group_id orphans children. */
  deleteByIdForUser(id, userId) {
    return MG.deleteByIdForUser.run(id, userId).changes > 0;
  },
  countForUser(userId) { return MG.countForUser.get(userId).c; },
};

// ---------- unified feed reorder (groups ↔ standalone messages) ----------
//
// The /messages page renders a single feed of two kinds of items:
// groups (from message_groups) and standalone messages (from messages
// where group_id IS NULL). Both tables carry their own sort_order
// column. When a user clicks the up/down arrows on EITHER kind of
// card, the visual neighbor could be in either table — so we need to
// find the next item by sort_order across BOTH tables and swap their
// sort_order values, even though they live in different rows.

function findAdjacentInFeed(userId, currentSortOrder, direction) {
  const op = direction === 'up' ? '>' : '<';
  const order = direction === 'up' ? 'ASC' : 'DESC';

  const grp = db.prepare(`
    SELECT id, sort_order FROM message_groups
    WHERE user_id = ? AND sort_order ${op} ?
    ORDER BY sort_order ${order} LIMIT 1
  `).get(userId, currentSortOrder);

  const msg = db.prepare(`
    SELECT id, sort_order FROM messages
    WHERE user_id = ? AND group_id IS NULL AND sort_order ${op} ?
    ORDER BY sort_order ${order} LIMIT 1
  `).get(userId, currentSortOrder);

  if (!grp && !msg) return null;
  if (!grp) return { kind: 'message', ...msg };
  if (!msg) return { kind: 'group',   ...grp };
  // Pick the row whose sort_order is closer to the current one.
  if (direction === 'up') {
    return grp.sort_order < msg.sort_order
      ? { kind: 'group',   ...grp }
      : { kind: 'message', ...msg };
  } else {
    return grp.sort_order > msg.sort_order
      ? { kind: 'group',   ...grp }
      : { kind: 'message', ...msg };
  }
}

function setFeedSortOrder(kind, id, sortOrder) {
  if (kind === 'group') {
    db.prepare('UPDATE message_groups SET sort_order = ? WHERE id = ?').run(sortOrder, id);
  } else {
    db.prepare('UPDATE messages SET sort_order = ? WHERE id = ?').run(sortOrder, id);
  }
}

const feed = {
  /**
   * Move a feed item (group or standalone message) up/down by one.
   * Looks across BOTH tables for the adjacent item and swaps
   * sort_order values inside a transaction.
   */
  move({ kind, slug, userId, direction }) {
    let cur = null;
    if (kind === 'group') {
      cur = MG.getBySlugForUser.get(slug, userId);
    } else {
      cur = M.getBySlugForUser.get(slug, userId);
      // A grouped message is not part of the top-level feed; refuse
      // to reorder it from this code path.
      if (cur && cur.group_id) return { ok: false, reason: 'message is in a group' };
    }
    if (!cur) return { ok: false, reason: 'not found' };

    const adj = findAdjacentInFeed(userId, cur.sort_order, direction);
    if (!adj) {
      return { ok: false, reason: direction === 'up' ? 'already at top' : 'already at bottom' };
    }
    db.transaction(() => {
      setFeedSortOrder(kind, cur.id, adj.sort_order);
      setFeedSortOrder(adj.kind, adj.id, cur.sort_order);
    })();
    return { ok: true };
  },
};

module.exports = { users, files, passwordResets, magicLinks, messages, groups, feed, raw: db };

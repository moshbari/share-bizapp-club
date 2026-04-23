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
    INSERT INTO files (slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, user_id)
    VALUES (@slug, @title, @original_filename, @kind, @mime_type, @size_bytes, @download_allowed, @ghl_url, @user_id)
  `),
  getBySlug: db.prepare(`
    SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at, user_id
    FROM files WHERE slug = ?
  `),
  listPageByUser: db.prepare(`
    SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at, user_id
    FROM files WHERE user_id = ? AND id < ?
    ORDER BY id DESC LIMIT ?
  `),
  countByUserAndKind: db.prepare(`SELECT COUNT(*) AS c FROM files WHERE user_id = ? AND kind = ?`),
  countByUser: db.prepare(`SELECT COUNT(*) AS c FROM files WHERE user_id = ?`),
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
      user_id: row.user_id,
    });
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
    const conds = ['user_id = ?'];
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

module.exports = { users, files, raw: db };

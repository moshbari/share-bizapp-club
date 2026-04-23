// SQLite wrapper for the file-share app. One table, no migrations framework
// — we add columns by editing the CREATE here when the schema changes.
//
// Schema notes:
//   - `slug` is the public 8-char nanoid that appears in /f/<slug>
//   - `original_filename` preserves whatever the user dropped in (e.g.
//     "my notes.md") so the viewer can pick the right renderer and the
//     download proxy can serve a useful Content-Disposition filename
//   - `kind` is one of: image, video, audio, pdf, text
//   - `mime_type` is the best-guess MIME we'll send when serving raw bytes
//   - `download_allowed` is the per-file uploader toggle (1=yes, 0=no)
//   - `ghl_url` is the public CDN URL returned by GHL — preview-only paths
//     can use it directly, the download proxy streams it through us so we
//     can attach Content-Disposition: attachment

const Database = require('better-sqlite3');
const path = require('node:path');
const fs = require('node:fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'share.db'));
db.pragma('journal_mode = WAL');

db.exec(`
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

const insertStmt = db.prepare(`
  INSERT INTO files (slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url)
  VALUES (@slug, @title, @original_filename, @kind, @mime_type, @size_bytes, @download_allowed, @ghl_url)
`);

const getBySlugStmt = db.prepare(`
  SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at
  FROM files WHERE slug = ?
`);

// Cursor-based pagination. `before` is the lowest id from the previous page.
// `id < ?` stays O(log N) on the indexed PK; OFFSET would walk the skipped rows.
const listPageStmt = db.prepare(`
  SELECT id, slug, title, original_filename, kind, mime_type, size_bytes, download_allowed, ghl_url, created_at
  FROM files
  WHERE id < ?
  ORDER BY id DESC
  LIMIT ?
`);

const FIRST_PAGE_CURSOR = Number.MAX_SAFE_INTEGER;

const updateTitleStmt = db.prepare(`
  UPDATE files SET title = ? WHERE slug = ?
`);

const updateDownloadFlagStmt = db.prepare(`
  UPDATE files SET download_allowed = ? WHERE slug = ?
`);

const deleteBySlugStmt = db.prepare(`
  DELETE FROM files WHERE slug = ?
`);

function insert(row) {
  insertStmt.run({
    slug: row.slug,
    title: row.title || '',
    original_filename: row.original_filename || row.originalFilename || '',
    kind: row.kind,
    mime_type: row.mime_type || row.mimeType || 'application/octet-stream',
    size_bytes: row.size_bytes || row.sizeBytes || 0,
    download_allowed: row.download_allowed != null
      ? (row.download_allowed ? 1 : 0)
      : (row.downloadAllowed === false ? 0 : 1),
    ghl_url: row.ghl_url || row.ghlUrl || '',
  });
}

function getBySlug(slug) {
  return getBySlugStmt.get(slug) || null;
}

/**
 * Paginated recent list — same shape as listen.bizapp.club's listRecent.
 * @param {object} opts
 * @param {number} [opts.before] return rows with id strictly less than this
 * @param {number} [opts.limit=10]
 */
function listRecent({ before, limit = 10 } = {}) {
  const cursor = Number.isFinite(before) ? before : FIRST_PAGE_CURSOR;
  const cap = Math.max(1, Math.min(50, limit | 0 || 10));
  return listPageStmt.all(cursor, cap);
}

function updateTitle(slug, title) {
  const res = updateTitleStmt.run((title || '').toString().slice(0, 200), slug);
  return res.changes > 0;
}

function setDownloadAllowed(slug, allowed) {
  const res = updateDownloadFlagStmt.run(allowed ? 1 : 0, slug);
  return res.changes > 0;
}

/**
 * Delete a row and return the GHL url so callers can fire a best-effort
 * GHL delete after the DB row is gone.
 */
function deleteBySlug(slug) {
  const row = getBySlug(slug);
  if (!row) return null;
  deleteBySlugStmt.run(slug);
  return row.ghl_url;
}

module.exports = {
  insert,
  getBySlug,
  listRecent,
  updateTitle,
  setDownloadAllowed,
  deleteBySlug,
};

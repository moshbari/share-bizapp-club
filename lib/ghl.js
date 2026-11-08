// GHL media upload. Same curl-via-execFileSync pattern as before, but
// functions now accept an optional `config` arg so a call can target a
// user's own sub-account + folder instead of the shared env one.
//
// config shape:
//   { apiKey, locationId, folderId }
// Passing `null` (or omitting) uses the shared env config.
//
// Env fallback:
//   GHL_API_KEY       PIT token (pit-<uuid>)
//   GHL_LOCATION_ID   sub-account location id
//   GHL_FOLDER_ID     folder id

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const r2 = require('./r2');

function envConfig() {
  return {
    apiKey: process.env.GHL_API_KEY || '',
    locationId: process.env.GHL_LOCATION_ID || '',
    folderId: process.env.GHL_FOLDER_ID || '',
  };
}

function isSharedConfigured() {
  const c = envConfig();
  return Boolean(c.apiKey && c.locationId && c.folderId);
}

function pickConfig(config) {
  if (config && config.apiKey && config.locationId && config.folderId) return config;
  return envConfig();
}

/**
 * Store an uploaded file. Returns the url to save in the DB.
 *
 * Since 8 Nov 2026 EVERY new upload goes to ShareZPresso's own R2 bucket —
 * shared, guests, and users who once connected their own GHL folder. GHL
 * accounts are being cancelled, so GHL is NOT a fallback: if R2 fails the
 * upload fails with a clear message. Files already in GHL keep their old
 * urls (still readable/deletable via fetchStored / tryDeleteFromGhl).
 * Name kept as uploadToGhl so the existing call sites don't change.
 */
function uploadToGhl(filePath, displayName, mime /*, config — ignored */) {
  if (!r2.isConfigured()) throw new Error('Storage is not configured (R2 env vars missing).');
  return r2.upload(filePath, displayName, mime);
}

/**
 * fetch() for a stored url of either kind. R2 objects are private, so they
 * are read through a short-lived signed url; GHL urls are fetched as-is.
 */
function fetchStored(url, opts) {
  return fetch(r2.isR2Url(url) ? r2.presignGet(url, 3600) : url, opts);
}

/** Upload straight to the GHL media library. Returns the public CDN URL. */
function ghlUpload(filePath, displayName, mime, config = null) {
  const cfg = pickConfig(config);
  if (!cfg.apiKey || !cfg.locationId || !cfg.folderId) {
    throw new Error('[GHL] not configured (neither user nor shared env)');
  }
  if (!fs.existsSync(filePath)) throw new Error(`[GHL] file not found: ${filePath}`);
  if (!mime) throw new Error('[GHL] mime is required');

  const args = [
    '-s', '-S', '--fail-with-body',
    '-X', 'POST',
    'https://services.leadconnectorhq.com/medias/upload-file',
    '-H', `Authorization: Bearer ${cfg.apiKey}`,
    '-H', 'Version: 2021-07-28',
    // Explicit MIME so node:20-slim (no /etc/mime.types) doesn't fall
    // back to application/octet-stream and trip INVALID_FILE_TYPE.
    '-F', `file=@${filePath};type=${mime}`,
    '-F', 'hosted=false',
    '-F', `name=${displayName}`,
    '-F', `altId=${cfg.locationId}`,
    '-F', 'altType=location',
    '-F', `parentId=${cfg.folderId}`,
  ];

  let out;
  try {
    out = execFileSync('curl', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  } catch (err) {
    const body = (err.stdout || '') + (err.stderr || '');
    throw new Error(`[GHL] upload failed: ${body.slice(0, 500)}`);
  }

  let parsed;
  try { parsed = JSON.parse(out); }
  catch { throw new Error(`[GHL] non-JSON response: ${out.slice(0, 500)}`); }

  if (!parsed.url) {
    throw new Error(`[GHL] no url in response: ${JSON.stringify(parsed).slice(0, 500)}`);
  }
  return parsed.url;
}

/**
 * Best-effort delete by CDN URL. The file UUID is the slug between
 * `/media/` and the extension. If the caller provides a per-user config,
 * we use that PIT — otherwise we fall back to env. A delete using the
 * wrong PIT will just 401; we swallow and return false.
 */
function tryDeleteFromGhl(url, config = null) {
  if (r2.isR2Url(url)) return r2.tryDelete(url);
  const cfg = pickConfig(config);
  if (!cfg.apiKey || !cfg.locationId) return false;
  if (!url || typeof url !== 'string') return false;
  const m = url.match(/\/media\/([0-9a-f-]{36})\.[a-z0-9]+(?:\?.*)?$/i);
  if (!m) return false;
  const fileId = m[1];
  const args = [
    '-s', '-S', '--fail-with-body',
    '-X', 'DELETE',
    '-H', `Authorization: Bearer ${cfg.apiKey}`,
    '-H', 'Version: 2021-07-28',
    `https://services.leadconnectorhq.com/medias/${fileId}?altId=${cfg.locationId}&altType=location`,
  ];
  try { execFileSync('curl', args, { encoding: 'utf8' }); return true; }
  catch (err) {
    const body = (err.stdout || '') + (err.stderr || '');
    console.warn(`[GHL] tryDelete failed for ${fileId}: ${body.slice(0, 200)}`);
    return false;
  }
}

/**
 * List folders in a location. Used to validate the user's PIT + location
 * and to resolve "folder name" → folder_id on /account save.
 * Returns an array of { _id, name } on success, throws on HTTP error.
 */
function listFolders({ apiKey, locationId }) {
  if (!apiKey || !locationId) throw new Error('PIT and location are required.');
  const args = [
    '-s', '-S', '--fail-with-body',
    '-H', `Authorization: Bearer ${apiKey}`,
    '-H', 'Version: 2021-07-28',
    `https://services.leadconnectorhq.com/medias/files?altId=${locationId}&altType=location&type=folder&limit=200`,
  ];
  let out;
  try { out = execFileSync('curl', args, { encoding: 'utf8' }); }
  catch (err) {
    const body = (err.stdout || '') + (err.stderr || '');
    // Scrub the PIT from any error we bubble up to a user.
    throw new Error(`GHL rejected the token or location (${body.slice(0, 160)}).`);
  }
  let parsed;
  try { parsed = JSON.parse(out); }
  catch { throw new Error(`GHL returned a non-JSON response.`); }
  const list = Array.isArray(parsed.files) ? parsed.files
              : Array.isArray(parsed) ? parsed
              : (parsed.items || []);
  return list.map(f => ({ _id: f._id || f.id, name: f.name }));
}

/**
 * Find a folder by exact name (case-insensitive) in the given location.
 * Returns { _id, name } or null.
 */
function findFolderByName({ apiKey, locationId, folderName }) {
  const folders = listFolders({ apiKey, locationId });
  const needle = (folderName || '').trim().toLowerCase();
  return folders.find(f => (f.name || '').trim().toLowerCase() === needle) || null;
}

/**
 * Self-check at boot — list one folder so we fail fast if shared env is
 * broken. Per-user configs are validated when the user saves them.
 */
function healthCheck() {
  if (!isSharedConfigured()) return { ok: false, reason: 'missing shared env vars' };
  try {
    listFolders({ apiKey: process.env.GHL_API_KEY, locationId: process.env.GHL_LOCATION_ID });
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err.message.slice(0, 300) };
  }
}

module.exports = {
  isSharedConfigured,
  uploadToGhl,
  fetchStored,
  tryDeleteFromGhl,
  listFolders,
  findFolderByName,
  healthCheck,
};

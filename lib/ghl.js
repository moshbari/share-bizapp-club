// GHL media upload — same pattern as listen-bizapp-club, but generic across
// file types. We always pass `;type=<mime>` on the curl form field because
// node:20-slim doesn't ship /etc/mime.types — without it curl sends
// application/octet-stream and GHL rejects with INVALID_FILE_TYPE.
//
// Env:
//   GHL_API_KEY       PIT token (pit-<uuid>)
//   GHL_LOCATION_ID   sub-account location id
//   GHL_FOLDER_ID     folder id (resolve once, set as env)

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

function isConfigured() {
  return Boolean(
    process.env.GHL_API_KEY &&
    process.env.GHL_LOCATION_ID &&
    process.env.GHL_FOLDER_ID
  );
}

/**
 * Upload a file to GHL media library.
 *
 * @param {string} filePath  absolute path on disk
 * @param {string} displayName name shown in the GHL UI; MUST end in an
 *                              extension that GHL accepts (we coerce text-y
 *                              files to ".txt" upstream — see lib/classify)
 * @param {string} mime        MIME we tell curl to advertise. Required —
 *                              GHL rejects octet-stream for most types
 * @returns {string} CDN URL
 */
function uploadToGhl(filePath, displayName, mime) {
  if (!isConfigured()) throw new Error('[GHL] not configured');
  if (!fs.existsSync(filePath)) throw new Error(`[GHL] file not found: ${filePath}`);
  if (!mime) throw new Error('[GHL] mime is required');

  const args = [
    '-s',
    '-S',
    '--fail-with-body',
    '-X', 'POST',
    'https://services.leadconnectorhq.com/medias/upload-file',
    '-H', `Authorization: Bearer ${process.env.GHL_API_KEY}`,
    '-H', 'Version: 2021-07-28',
    '-F', `file=@${filePath};type=${mime}`,
    '-F', 'hosted=false',
    '-F', `name=${displayName}`,
    '-F', `altId=${process.env.GHL_LOCATION_ID}`,
    '-F', 'altType=location',
    '-F', `parentId=${process.env.GHL_FOLDER_ID}`,
  ];

  let out;
  try {
    // Big maxBuffer for the JSON response — the response itself is small but
    // curl progress can leak into stdout if -s is missing. We have -s, so
    // 16 MB is plenty.
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

  console.log(`[GHL] uploaded ${displayName} (${mime}) → ${parsed.url}`);
  return parsed.url;
}

/**
 * Best-effort delete by CDN URL. Same uuid-extracting regex as the listen app:
 *   https://assets.cdn.filesafe.space/<locationId>/media/<uuid>.<ext>
 */
function tryDeleteFromGhl(url) {
  if (!isConfigured()) return false;
  if (!url || typeof url !== 'string') return false;
  const m = url.match(/\/media\/([0-9a-f-]{36})\.[a-z0-9]+(?:\?.*)?$/i);
  if (!m) {
    console.warn('[GHL] tryDelete: could not extract uuid from', url);
    return false;
  }
  const fileId = m[1];
  const args = [
    '-s', '-S', '--fail-with-body',
    '-X', 'DELETE',
    '-H', `Authorization: Bearer ${process.env.GHL_API_KEY}`,
    '-H', 'Version: 2021-07-28',
    `https://services.leadconnectorhq.com/medias/${fileId}?altId=${process.env.GHL_LOCATION_ID}&altType=location`,
  ];
  try {
    execFileSync('curl', args, { encoding: 'utf8' });
    console.log(`[GHL] deleted ${fileId}`);
    return true;
  } catch (err) {
    const body = (err.stdout || '') + (err.stderr || '');
    console.warn(`[GHL] tryDelete failed for ${fileId}: ${body.slice(0, 200)}`);
    return false;
  }
}

/**
 * Self-check at boot — list one folder so we fail fast if the token or
 * location are wrong instead of silently breaking on first upload.
 */
function healthCheck() {
  if (!isConfigured()) return { ok: false, reason: 'missing env vars' };
  const args = [
    '-s', '-S', '--fail-with-body',
    '-H', `Authorization: Bearer ${process.env.GHL_API_KEY}`,
    '-H', 'Version: 2021-07-28',
    `https://services.leadconnectorhq.com/medias/files?altId=${process.env.GHL_LOCATION_ID}&altType=location&type=folder&limit=1`,
  ];
  try {
    const out = execFileSync('curl', args, { encoding: 'utf8' });
    JSON.parse(out);
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: (err.stdout || err.message || '').toString().slice(0, 300) };
  }
}

module.exports = { isConfigured, uploadToGhl, tryDeleteFromGhl, healthCheck };

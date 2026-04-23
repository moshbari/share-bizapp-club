// Classify an uploaded file into one of: image, video, audio, pdf, text, unknown.
// Also produces:
//   - `mime`         — what we'll store in DB and serve when streaming raw bytes
//   - `ghlMime`      — what curl should advertise to GHL (must match GHL's allowed
//                      list or upload returns INVALID_FILE_TYPE)
//   - `ghlExt`       — the extension to use on the GHL display name. For text-y
//                      files whose real extension GHL would reject (.md, .js,
//                      .py, .ts, ...) we coerce to ".txt"; original_filename in
//                      our DB still has the user's name so the viewer can pick
//                      the right rendering.
//   - `maxBytes`     — per-type size cap (matches GHL's documented limits)

const path = require('node:path');

// GHL "supported formats" — verified against
// https://help.gohighlevel.com/support/solutions/articles/48001216629
const GHL_IMAGE_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'tiff', 'tif', 'heic', 'ico']);
const GHL_VIDEO_EXT = new Set(['mp4', 'mov', 'webm', 'wmv', 'avi', 'm4v', 'mpeg', 'ogv']);
const GHL_AUDIO_EXT = new Set(['mp3', 'wav', 'ogg', 'oga', 'm4a', 'aac', 'aif', 'aiff', 'midi', 'mid', 'weba']);
const GHL_DOC_EXT   = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'zip']);

// Text-y extensions we accept but coerce to ".txt" before sending to GHL,
// because GHL rejects most code/markup MIME types as INVALID_FILE_TYPE.
const TEXT_LIKE_EXT = new Set([
  'md', 'markdown', 'log',
  'json', 'yaml', 'yml', 'xml', 'toml', 'ini', 'env',
  'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx',
  'py', 'rb', 'go', 'rs', 'java', 'c', 'cpp', 'cc', 'cxx', 'h', 'hpp',
  'cs', 'kt', 'swift', 'scala', 'lua', 'pl', 'r', 'php',
  'sh', 'bash', 'zsh', 'fish', 'ps1',
  'sql', 'graphql', 'proto',
  'html', 'htm', 'css', 'scss', 'less',
  'dockerfile', 'makefile', 'gitignore',
]);

const SIZE_CAPS = {
  image: 100 * 1024 * 1024,        // 100 MB
  video: 4 * 1024 * 1024 * 1024,   // 4 GB
  audio: 100 * 1024 * 1024,        // 100 MB
  pdf:   100 * 1024 * 1024,        // 100 MB
  text:  100 * 1024 * 1024,        // 100 MB
};

/**
 * @param {string} originalName e.g. "my notes.md"
 * @param {string} browserMime  e.g. "text/markdown" (from multer; may be empty)
 * @returns {{
 *   kind: 'image'|'video'|'audio'|'pdf'|'text'|'unknown',
 *   mime: string,
 *   ghlMime: string,
 *   ghlExt: string,
 *   maxBytes: number,
 *   reason?: string
 * }}
 */
function classify(originalName, browserMime) {
  const ext = (path.extname(originalName || '') || '').toLowerCase().replace(/^\./, '');
  const m = (browserMime || '').toLowerCase();

  // Image
  if (m.startsWith('image/') || GHL_IMAGE_EXT.has(ext)) {
    return {
      kind: 'image',
      mime: m || guessImageMime(ext),
      ghlMime: m || guessImageMime(ext),
      ghlExt: ext || 'jpg',
      maxBytes: SIZE_CAPS.image,
    };
  }

  // Video
  if (m.startsWith('video/') || GHL_VIDEO_EXT.has(ext)) {
    return {
      kind: 'video',
      mime: m || guessVideoMime(ext),
      ghlMime: m || guessVideoMime(ext),
      ghlExt: ext || 'mp4',
      maxBytes: SIZE_CAPS.video,
    };
  }

  // Audio
  if (m.startsWith('audio/') || GHL_AUDIO_EXT.has(ext)) {
    return {
      kind: 'audio',
      mime: m || guessAudioMime(ext),
      ghlMime: m || guessAudioMime(ext),
      ghlExt: ext || 'mp3',
      maxBytes: SIZE_CAPS.audio,
    };
  }

  // PDF
  if (m === 'application/pdf' || ext === 'pdf') {
    return {
      kind: 'pdf',
      mime: 'application/pdf',
      ghlMime: 'application/pdf',
      ghlExt: 'pdf',
      maxBytes: SIZE_CAPS.pdf,
    };
  }

  // Text — accept anything that looks like text or code by extension or MIME.
  // Coerce GHL ext to .txt so the upload doesn't trip INVALID_FILE_TYPE.
  if (
    ext === 'txt' ||
    TEXT_LIKE_EXT.has(ext) ||
    m.startsWith('text/') ||
    m === 'application/json' ||
    m === 'application/xml'
  ) {
    return {
      kind: 'text',
      mime: 'text/plain; charset=utf-8',
      ghlMime: 'text/plain',
      ghlExt: 'txt',
      maxBytes: SIZE_CAPS.text,
    };
  }

  // Other GHL-supported docs (.doc, .csv, .zip, ...) — accept but treat as
  // "binary" with download-only behavior. Not a primary use case.
  if (GHL_DOC_EXT.has(ext)) {
    return {
      kind: 'text', // best-effort viewer attempt
      mime: 'application/octet-stream',
      ghlMime: 'application/octet-stream',
      ghlExt: ext,
      maxBytes: SIZE_CAPS.text,
    };
  }

  return {
    kind: 'unknown',
    mime: 'application/octet-stream',
    ghlMime: 'application/octet-stream',
    ghlExt: ext || 'bin',
    maxBytes: SIZE_CAPS.text,
    reason: `File type .${ext || '(none)'} is not supported.`,
  };
}

function guessImageMime(ext) {
  return ({
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', tiff: 'image/tiff', tif: 'image/tiff',
    heic: 'image/heic', ico: 'image/x-icon',
  })[ext] || 'image/jpeg';
}
function guessVideoMime(ext) {
  return ({
    mp4: 'video/mp4', mov: 'video/quicktime', webm: 'video/webm',
    wmv: 'video/x-ms-wmv', avi: 'video/x-msvideo', m4v: 'video/x-m4v',
    mpeg: 'video/mpeg', ogv: 'video/ogg',
  })[ext] || 'video/mp4';
}
function guessAudioMime(ext) {
  return ({
    mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', oga: 'audio/ogg',
    m4a: 'audio/mp4', aac: 'audio/aac', aif: 'audio/aiff', aiff: 'audio/aiff',
    midi: 'audio/midi', mid: 'audio/midi', weba: 'audio/webm',
  })[ext] || 'audio/mpeg';
}

function fmtBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0; let n = bytes;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}

module.exports = { classify, SIZE_CAPS, fmtBytes };

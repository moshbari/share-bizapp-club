// The optional video (VSL) at the top of a page.
//
// A page has at most one. It comes from either:
//   - a LINK the owner pastes: YouTube, Vimeo, Loom, Tella, Wistia, Google
//     Drive, Dropbox, a GoHighLevel media link, or any direct video file; or
//   - one of the owner's OWN uploaded videos (a `files` row) — uploading from
//     the editor goes through the normal /api/upload, so it lands in the same
//     storage and limits as every other upload.
//
// Everything a visitor's browser gets is built here from a parsed, rebuilt
// URL — never the pasted string itself — so a link can't smuggle markup or a
// javascript: address onto the page.

const { raw: db } = require('./db');

function maybeAddColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some(c => c.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`);
}
maybeAddColumn('pages', 'vsl_enabled', 'INTEGER NOT NULL DEFAULT 0');
maybeAddColumn('pages', 'vsl_source', "TEXT NOT NULL DEFAULT ''");   // 'link' | 'file'
maybeAddColumn('pages', 'vsl_url', "TEXT NOT NULL DEFAULT ''");
maybeAddColumn('pages', 'vsl_ref', "TEXT NOT NULL DEFAULT ''");      // files.slug
maybeAddColumn('pages', 'vsl_title', "TEXT NOT NULL DEFAULT ''");
maybeAddColumn('pages', 'vsl_position', "TEXT NOT NULL DEFAULT 'below_bio'"); // 'below_bio' | 'top'

const setStmt = db.prepare(`
  UPDATE pages SET vsl_enabled = @enabled, vsl_source = @source, vsl_url = @url, vsl_ref = @ref,
                   vsl_title = @title, vsl_position = @position, updated_at = CURRENT_TIMESTAMP
  WHERE id = @id
`);

const HOSTS_SENTENCE = 'YouTube, Vimeo, Loom, Tella, Wistia, Google Drive, Dropbox, a GoHighLevel media link, or a direct video file link (.mp4)';
const VIDEO_EXT = /\.(mp4|m4v|webm|mov|ogv)$/i;
const ID = /^[\w-]{3,120}$/;

/**
 * A pasted link → { type: 'iframe'|'video', src, host, vertical } or null.
 * `ownOrigins` are this site's hosts, so a /f/<slug> share link can be
 * recognised and turned into the owner's own file instead.
 */
function parseVideoUrl(input, ownHosts = []) {
  let s = (input || '').toString().trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (!/^https?:$/.test(u.protocol)) return null;
  const host = u.hostname.toLowerCase().replace(/^www\./, '').replace(/^m\./, '');
  const parts = u.pathname.split('/').filter(Boolean);

  if (ownHosts.includes(host) && parts[0] === 'f' && parts[1] && ID.test(parts[1])) {
    return { type: 'own', slug: parts[1], host };
  }

  // YouTube
  if (host === 'youtu.be' && parts[0] && ID.test(parts[0])) {
    return { type: 'iframe', host: 'YouTube', src: `https://www.youtube-nocookie.com/embed/${parts[0]}?rel=0&playsinline=1` };
  }
  if (host === 'youtube.com' || host === 'youtube-nocookie.com' || host === 'music.youtube.com') {
    let id = u.searchParams.get('v');
    let vertical = false;
    if (!id && ['embed', 'shorts', 'live', 'v'].includes(parts[0])) { id = parts[1]; vertical = parts[0] === 'shorts'; }
    if (id && ID.test(id)) return { type: 'iframe', host: 'YouTube', vertical, src: `https://www.youtube-nocookie.com/embed/${id}?rel=0&playsinline=1` };
    return null;
  }

  // Vimeo (incl. unlisted links that carry a hash: vimeo.com/123/abcdef)
  if (host === 'vimeo.com' || host === 'player.vimeo.com') {
    const nums = parts.filter(p => /^\d{5,}$/.test(p));
    if (!nums.length) return null;
    const id = nums[0];
    const after = parts[parts.indexOf(id) + 1];
    const h = u.searchParams.get('h') || (after && /^[0-9a-f]{6,}$/i.test(after) ? after : '');
    return { type: 'iframe', host: 'Vimeo', src: `https://player.vimeo.com/video/${id}${h ? `?h=${h}` : ''}` };
  }

  // Loom
  if (host === 'loom.com' && ['share', 'embed'].includes(parts[0]) && parts[1] && ID.test(parts[1])) {
    return { type: 'iframe', host: 'Loom', src: `https://www.loom.com/embed/${parts[1]}` };
  }

  // Tella: tella.tv/video/<id>  (share)  →  /video/<id>/embed
  if ((host === 'tella.tv' || host === 'tella.com') && parts[0] === 'video' && parts[1] && ID.test(parts[1])) {
    return { type: 'iframe', host: 'Tella', src: `https://www.tella.tv/video/${parts[1]}/embed` };
  }

  // Wistia: <acct>.wistia.com/medias/<id>, wi.st/medias/<id>, fast.wistia.net/embed/iframe/<id>
  if (host.endsWith('wistia.com') || host === 'wi.st' || host.endsWith('wistia.net')) {
    const i = parts.findIndex(p => p === 'medias' || p === 'iframe');
    const id = i >= 0 ? parts[i + 1] : '';
    if (id && ID.test(id)) return { type: 'iframe', host: 'Wistia', src: `https://fast.wistia.net/embed/iframe/${id}` };
    return null;
  }

  // Google Drive: /file/d/<id>/view → /preview (the file must be shared "anyone with the link")
  if (host === 'drive.google.com') {
    const id = parts[0] === 'file' && parts[1] === 'd' ? parts[2] : u.searchParams.get('id');
    if (id && ID.test(id)) return { type: 'iframe', host: 'Google Drive', src: `https://drive.google.com/file/d/${id}/preview` };
    return null;
  }

  // Dropbox: a share link plays as a file once it asks for the raw bytes.
  if (host === 'dropbox.com' || host === 'dl.dropboxusercontent.com') {
    if (!VIDEO_EXT.test(u.pathname)) return null;
    u.searchParams.delete('dl');
    u.searchParams.set('raw', '1');
    return { type: 'video', host: 'Dropbox', src: u.toString() };
  }

  // GoHighLevel media storage, or any direct video file on any host.
  const ghl = host.endsWith('filesafe.space') || host === 'storage.googleapis.com' || host.endsWith('leadconnectorhq.com') || host.endsWith('msgsndr.com');
  if (u.protocol === 'https:' && (VIDEO_EXT.test(u.pathname) || ghl)) {
    return { type: 'video', host: ghl ? 'GoHighLevel' : host, src: u.toString() };
  }
  return null;
}

/**
 * What to show for a page's VSL, or null when it's off or broken.
 * `getFile(slug)` returns a files row; only the owner's activated videos count.
 */
function resolveVsl(page, getFile) {
  if (!page.vsl_enabled) return null;
  if (page.vsl_source === 'file') {
    const f = page.vsl_ref ? getFile(page.vsl_ref) : null;
    if (!f || f.user_id !== page.user_id || !f.activated || f.kind !== 'video') return null;
    return { type: 'video', host: 'your upload', src: `/raw/${f.slug}`, fileTitle: f.title || f.original_filename || 'Video', slug: f.slug };
  }
  if (page.vsl_source === 'link') {
    const v = parseVideoUrl(page.vsl_url);
    return v && v.type !== 'own' ? v : null;
  }
  return null;
}

/**
 * Validates and saves the editor's VSL form. Returns '' or an error sentence.
 * body: { enabled, source: 'link'|'file', url, ref_slug, title, position }
 */
function saveVsl(page, body, { getFile, ownHosts }) {
  const enabled = body.enabled === true || body.enabled === '1' || body.enabled === 'on';
  const title = (body.title || '').toString().trim().slice(0, 140);
  const position = body.position === 'top' ? 'top' : 'below_bio';
  let source = body.source === 'file' ? 'file' : body.source === 'link' ? 'link' : (page.vsl_source || '');
  let url = page.vsl_url || '';
  let ref = page.vsl_ref || '';

  if (source === 'link') {
    const raw = (body.url || '').toString().trim();
    if (raw) {
      const v = parseVideoUrl(raw, ownHosts);
      if (!v) return `That link can't be played on your page. Use ${HOSTS_SENTENCE}.`;
      if (v.type === 'own') { source = 'file'; ref = v.slug; }
      else url = raw.slice(0, 2000);
    } else if (enabled) {
      return 'Paste the link to your video.';
    }
  }
  if (source === 'file') {
    if (body.ref_slug) ref = body.ref_slug.toString().slice(0, 64);
    const f = ref ? getFile(ref) : null;
    if (enabled && (!f || f.user_id !== page.user_id || !f.activated)) return 'Pick one of your own videos.';
    if (f && f.kind !== 'video') return 'That file is not a video — pick a video.';
  }
  if (enabled && !source) return 'Choose where the video comes from.';

  setStmt.run({ id: page.id, enabled: enabled ? 1 : 0, source, url, ref, title, position });
  return '';
}

/** The markup for the public page. `esc` = the app's HTML escaper. */
function vslHtml(page, v, esc) {
  if (!v) return '';
  const title = page.vsl_title ? `<h2 class="pg-vsl-title">${esc(page.vsl_title)}</h2>` : '';
  const media = v.type === 'iframe'
    ? `<div class="pg-vsl-frame${v.vertical ? ' is-vertical' : ''}"><iframe src="${esc(v.src)}" title="${esc(page.vsl_title || 'Video')}" loading="lazy"
         allow="autoplay; fullscreen; picture-in-picture; encrypted-media; clipboard-write" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>`
    : `<div class="pg-vsl-frame is-file"><video src="${esc(v.src)}" controls playsinline preload="metadata"></video></div>`;
  return `<section class="pg-vsl pg-vsl-${esc(page.vsl_position)}">${title}${media}</section>`;
}

const VSL_CSS = `
  .pg-vsl { margin: 0 0 26px; }
  .pg-vsl-top { margin-top: -8px; }
  .pg-vsl-title { margin: 0 0 12px; text-align: center; font-size: 21px; line-height: 1.3; font-weight: 800; letter-spacing: -0.01em; word-break: break-word; }
  .pg-vsl-frame { position: relative; width: 100%; aspect-ratio: 16 / 9; border-radius: 16px; overflow: hidden; background: #000;
                  box-shadow: 0 14px 40px -12px rgba(15,23,42,.45); border: 1.5px solid var(--card-border); }
  .pg-vsl-frame.is-vertical { aspect-ratio: 9 / 16; max-width: 340px; margin: 0 auto; }
  .pg-vsl-frame.is-file { aspect-ratio: auto; }
  .pg-vsl-frame iframe { position: absolute; inset: 0; width: 100%; height: 100%; border: 0; }
  .pg-vsl-frame video { display: block; width: 100%; max-height: 78vh; background: #000; }
`;

module.exports = { parseVideoUrl, resolveVsl, saveVsl, vslHtml, VSL_CSS, HOSTS_SENTENCE };

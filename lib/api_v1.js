// JSON namespace under /api/v1/* — used by the ShareZPresso iOS app.
// Bearer-token authed; never touches cookies. All existing web routes
// (/, /login, /upload, /api/upload, etc.) keep working unchanged.

const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { nanoid } = require('nanoid');

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function newToken() {
  return crypto.randomBytes(32).toString('base64url');
}

// Whitelist of user fields we ever return — never include password_hash.
function sanitizeUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    email: u.email,
    name: u.name || '',
    status: u.status,
    is_admin: !!u.is_admin,
    created_at: u.created_at,
    has_custom_ghl: !!(u.ghl_api_key && u.ghl_location_id && u.ghl_folder_id),
    ghl_folder_name: u.ghl_folder_name || null,
  };
}

function fileToJSON(f, publicOrigin) {
  if (!f) return null;
  return {
    slug: f.slug,
    title: f.title,
    original_filename: f.original_filename,
    kind: f.kind,
    mime_type: f.mime_type,
    size_bytes: f.size_bytes,
    download_allowed: !!f.download_allowed,
    notes: f.notes || '',
    created_at: f.created_at,
    share_url: `${publicOrigin}/f/${f.slug}`,
    raw_url: `${publicOrigin}/raw/${f.slug}`,
    download_url: f.download_allowed ? `${publicOrigin}/d/${f.slug}` : null,
  };
}

// A chat scroll: an ordered run of screenshots that reads as one scrolling
// conversation. `items` are always sorted by position, because the order IS
// the content — a client that renders them in any other order is broken.
function chatToJSON(c, items, publicOrigin) {
  if (!c) return null;
  const list = items || [];
  return {
    slug: c.slug,
    title: c.title,
    status: c.status,                     // "draft" until every image lands
    download_allowed: !!c.download_allowed,
    notes: c.notes || '',
    item_count: list.length,
    created_at: c.created_at,
    updated_at: c.updated_at,
    public_url: `${publicOrigin}/c/${c.slug}`,
    cover_url: list.length ? `${publicOrigin}/cr/${c.slug}/${list[0].id}` : null,
    items: list.map((i) => ({
      id: i.id,
      position: i.position,
      width: i.width,
      height: i.height,
      size_bytes: i.size_bytes,
      original_filename: i.original_filename,
      url: `${publicOrigin}/cr/${c.slug}/${i.id}`,
    })),
  };
}

function messageToJSON(m, publicOrigin) {
  if (!m) return null;
  return {
    slug: m.slug,
    title: m.title || '',
    body: m.body || '',
    sort_order: m.sort_order,
    group_id: m.group_id ?? null,
    group_position: m.group_position ?? null,
    created_at: m.created_at,
    updated_at: m.updated_at,
    public_url: `${publicOrigin}/m/${m.slug}`,
  };
}

function groupToJSON(g, children, publicOrigin) {
  if (!g) return null;
  return {
    slug: g.slug,
    title: g.title || '',
    sort_order: g.sort_order,
    created_at: g.created_at,
    updated_at: g.updated_at,
    messages: (children || []).map((m) => messageToJSON(m, publicOrigin)),
  };
}

/**
 * Mount all /api/v1/* routes on the given Express app.
 *
 * Deps (passed in so the file stays decoupled from server.js):
 *   - db: { users, files, passwordResets, messages, groups, feed, apiTokens, deviceTokens }
 *   - users: lib/users.js (hashPassword, verifyPassword, signup, login,
 *            checkUploadAllowed, effectiveGhlConfig, sanitize, trialUsage)
 *   - ghl: lib/ghl.js
 *   - transcode: lib/transcode.js
 *   - email: lib/email.js (sendPasswordResetEmail)
 *   - classify: lib/classify.js {classify, fmtBytes}
 *   - apns: lib/apns.js
 *   - upload: multer middleware
 *   - PUBLIC_ORIGIN: string
 *   - baseFilename(name): string
 *   - sanitizeForFilename(s): string
 *   - kindEmoji(k): string
 */
function attach(app, deps) {
  const {
    db, users, ghl, transcode, email, classify: clsHelpers, apns,
    upload, PUBLIC_ORIGIN, baseFilename, sanitizeForFilename, kindEmoji,
    chatHelpers,
  } = deps;
  const { users: udb, files: fdb, passwordResets: prdb,
          messages: mdb, groups: gdb, feed: feeddb, chats: cdb,
          apiTokens: atdb, deviceTokens: dtdb, NOTES_MAX_CHARS } = db;
  const { classify, fmtBytes } = clsHelpers;

  const router = express.Router();

  // ---------- middleware ----------

  // All write routes use Bearer auth. Reads under /raw and /d remain on
  // the public web routes — iOS uses them directly with no auth.
  function requireApiToken(req, res, next) {
    const h = req.get('authorization') || '';
    const m = /^Bearer\s+(.+)$/i.exec(h.trim());
    if (!m) return res.status(401).json({ ok: false, error: 'Bearer token required.' });
    const raw = m[1].trim();
    const row = atdb.getByHash(sha256(raw));
    if (!row) return res.status(401).json({ ok: false, error: 'Token invalid or revoked.' });
    const u = udb.getById(row.user_id);
    if (!u || u.status === 'deactivated') {
      atdb.deleteByHash(sha256(raw));
      return res.status(401).json({ ok: false, error: 'Account disabled.' });
    }
    atdb.touch(row.id);
    req.user = users.sanitize(u);
    req.userRow = u;
    req.tokenRowId = row.id;
    req.tokenHash = sha256(raw);
    req.deviceId = row.device_id;
    next();
  }

  function requireAdmin(req, res, next) {
    if (!req.user?.is_admin) return res.status(403).json({ ok: false, error: 'Admin only.' });
    next();
  }

  // JSON body parsing only for these routes (web routes parse separately)
  const jsonBody = express.json({ limit: '2mb' });

  function fireAndForgetPush(userId, alert) {
    if (!apns.configured) return;
    process.nextTick(async () => {
      try {
        const toks = dtdb.listByUser(userId);
        const r = await apns.fanOut(toks, alert);
        if (r.stale.length) {
          // Drop tokens APNs says are dead.
          for (const t of toks) {
            if (r.stale.includes(t.apns_token)) {
              dtdb.deleteByUserAndDevice(t.user_id, t.device_id);
            }
          }
        }
      } catch (err) {
        console.warn('[apns] push hook failed:', err.message);
      }
    });
  }

  // Expose push helper so the cookie-based handlers can also call it
  // (for /raw/:slug first-view events).
  attach.firePush = fireAndForgetPush;

  // ---------- AUTH ----------

  router.post('/auth/signup', jsonBody, (req, res) => {
    try {
      const { name, email, password, device_name, device_id } = req.body || {};
      if (!device_id) return res.status(400).json({ ok: false, error: 'device_id required' });
      const u = users.signup({ name, email, password, status: 'trial' });
      const raw = newToken();
      atdb.upsert({
        user_id: u.id,
        token_hash: sha256(raw),
        device_name: device_name || null,
        device_id: String(device_id).slice(0, 128),
      });
      res.json({ ok: true, token: raw, user: sanitizeUser(udb.getById(u.id)) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message || 'Signup failed.' });
    }
  });

  router.post('/auth/login', jsonBody, (req, res) => {
    try {
      const { email, password, device_name, device_id } = req.body || {};
      if (!device_id) return res.status(400).json({ ok: false, error: 'device_id required' });
      const u = users.login({ email, password });
      if (!u) return res.status(401).json({ ok: false, error: 'Wrong email or password.' });
      const raw = newToken();
      atdb.upsert({
        user_id: u.id,
        token_hash: sha256(raw),
        device_name: device_name || null,
        device_id: String(device_id).slice(0, 128),
      });
      res.json({ ok: true, token: raw, user: sanitizeUser(udb.getById(u.id)) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message || 'Login failed.' });
    }
  });

  router.post('/auth/logout', requireApiToken, (req, res) => {
    atdb.deleteByHash(req.tokenHash);
    // Also drop the device's push token so it stops getting pushes
    dtdb.deleteByUserAndDevice(req.user.id, req.deviceId);
    res.json({ ok: true });
  });

  router.post('/auth/forgot', jsonBody, async (req, res) => {
    // Always 204 — account-enumeration-safe.
    const email = (req.body?.email || '').toString().toLowerCase().trim();
    res.json({ ok: true });
    if (!email) return;
    try {
      const u = udb.getByEmail(email);
      if (!u) return;
      const raw = newToken();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      prdb.create({ userId: u.id, tokenHash: sha256(raw), expiresAt });
      await email_sendPasswordReset(email, raw);
    } catch (err) {
      console.warn('[api/v1 forgot] best-effort failed:', err.message);
    }
  });

  // Indirection so we can survive email module having a different export name
  async function email_sendPasswordReset(toEmail, rawToken) {
    const url = `${PUBLIC_ORIGIN}/reset/${rawToken}`;
    if (email && typeof email.sendPasswordResetEmail === 'function') {
      return email.sendPasswordResetEmail(toEmail, url);
    }
    if (email && typeof email.sendResetEmail === 'function') {
      return email.sendResetEmail(toEmail, url);
    }
    console.log(`[api/v1 forgot] no email transport — reset URL for ${toEmail}: ${url}`);
  }

  router.post('/auth/reset/:token', jsonBody, (req, res) => {
    try {
      const raw = String(req.params.token || '');
      const newPassword = String(req.body?.password || '');
      if (newPassword.length < 8) {
        return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });
      }
      const row = prdb.getByHash(sha256(raw));
      if (!row || row.used_at || new Date(row.expires_at).getTime() < Date.now()) {
        return res.status(400).json({ ok: false, error: 'Reset link is invalid or expired.' });
      }
      const hash = users.hashPassword(newPassword);
      udb.setPasswordHash(row.user_id, hash);
      prdb.markUsed(sha256(raw));
      if (typeof prdb.invalidateForUser === 'function') {
        prdb.invalidateForUser(row.user_id);
      }
      // Auto-issue a new bearer for whichever device sent the reset request
      const device_id = String(req.body?.device_id || '').slice(0, 128);
      const device_name = req.body?.device_name || null;
      let token = null;
      if (device_id) {
        token = newToken();
        atdb.upsert({
          user_id: row.user_id,
          token_hash: sha256(token),
          device_name,
          device_id,
        });
      }
      res.json({ ok: true, token, user: sanitizeUser(udb.getById(row.user_id)) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  // ---------- ME ----------

  router.get('/me', requireApiToken, (req, res) => {
    res.json({ ok: true, user: sanitizeUser(udb.getById(req.user.id)) });
  });

  router.post('/me/password', requireApiToken, jsonBody, (req, res) => {
    try {
      const { current, new: newPw } = req.body || {};
      const fresh = udb.getById(req.user.id);
      if (!users.verifyPassword(current, fresh.password_hash)) {
        return res.status(400).json({ ok: false, error: 'Current password is wrong.' });
      }
      if (!newPw || newPw.length < 8) {
        return res.status(400).json({ ok: false, error: 'New password must be at least 8 characters.' });
      }
      udb.setPasswordHash(req.user.id, users.hashPassword(newPw));
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  router.post('/me/ghl', requireApiToken, jsonBody, async (req, res) => {
    try {
      if (req.user.status === 'trial') {
        return res.status(403).json({ ok: false, error: 'Trial accounts cannot set custom GHL config.' });
      }
      const { api_key, location_id, folder_name } = req.body || {};
      if (!api_key || !location_id || !folder_name) {
        return res.status(400).json({ ok: false, error: 'api_key, location_id and folder_name are required.' });
      }
      // Resolve folder by name via GHL — mirrors web /account/ghl-settings.
      const folder = await ghl.findFolderByName({ apiKey: api_key, locationId: location_id, folderName: folder_name });
      if (!folder) {
        return res.status(400).json({ ok: false, error: `No folder named "${folder_name}" in that GHL location.` });
      }
      udb.setGhlConfig(req.user.id, {
        apiKey: api_key,
        locationId: location_id,
        folderId: folder.id,
        folderName: folder_name,
      });
      res.json({ ok: true, folder_id: folder.id, folder_name });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  router.delete('/me/ghl', requireApiToken, (req, res) => {
    udb.setGhlConfig(req.user.id, { apiKey: null, locationId: null, folderId: null, folderName: null });
    res.json({ ok: true });
  });

  // ---------- FILES ----------

  router.get('/files', requireApiToken, (req, res) => {
    const limit = Math.max(1, Math.min(50, parseInt(req.query.limit || '33', 10) || 33));
    const cursor = parseInt(req.query.cursor || '', 10);
    const kind = (req.query.kind || '').toString().trim() || undefined;
    const q = (req.query.q || '').toString().trim() || undefined;
    const from = (req.query.from || '').toString().trim() || undefined;
    const to = (req.query.to || '').toString().trim() || undefined;
    const rows = fdb.listRecentFilteredByUser(req.user.id, {
      before: Number.isFinite(cursor) ? cursor : undefined,
      limit, kind, q, from, to,
    });
    // The cursor walks sort_order (the drag-to-reorder rank the web list
    // uses), not id — listRecentFilteredByUser pages on sort_order now.
    const next = rows.length === limit ? rows[rows.length - 1].sort_order : null;
    res.json({
      ok: true,
      files: rows.map((r) => fileToJSON(r, PUBLIC_ORIGIN)),
      next_cursor: next != null ? String(next) : null,
    });
  });

  // Drag-to-reorder from the phone. `order` is the slugs top-to-bottom, the
  // same rank the web list at /upload writes. Registered before /files/:slug
  // handlers so "reorder" can never be read as a slug.
  router.post('/files/reorder', requireApiToken, jsonBody, (req, res) => {
    const order = Array.isArray(req.body?.order) ? req.body.order.map(String) : null;
    if (!order) return res.status(400).json({ ok: false, error: 'order: [slug...] required' });
    const result = fdb.reorderForUser(req.user.id, order);
    res.json({ ok: true, updated: result.updated });
  });

  router.post('/files', requireApiToken, upload.single('file'), async (req, res) => {
    const f = req.file;
    if (!f) return res.status(400).json({ ok: false, error: 'No file uploaded.' });
    try {
      const cls = classify(f.originalname, f.mimetype);
      if (cls.kind === 'unknown') throw new Error(cls.reason || 'Unsupported file type');
      if (f.size > cls.maxBytes) {
        throw new Error(`${f.originalname} is ${fmtBytes(f.size)} but the limit for ${cls.kind} files is ${fmtBytes(cls.maxBytes)}.`);
      }
      const fresh = udb.getById(req.user.id);
      const gate = users.checkUploadAllowed(fresh, cls.kind);
      if (!gate.ok) throw new Error(gate.reason);

      const userTitle = (req.body.title || '').toString().trim();
      const fallbackTitle = baseFilename(f.originalname) || 'File';
      const title = (userTitle || fallbackTitle).slice(0, 200);
      const notes = (req.body.notes || '').toString().slice(0, NOTES_MAX_CHARS);
      const allowDownload = req.body.allow_download === '1' || req.body.allow_download === 'true' || req.body.allow_download === 'on';

      const slug = nanoid(8);
      const uniq = nanoid(4);
      const ghlDisplayName = `${sanitizeForFilename(title)}-${uniq}.${cls.ghlExt}`;

      let uploadPath = f.path;
      let uploadSize = f.size;
      let effectiveOriginalName = f.originalname;
      let transcodedTmp = null;
      if (cls.needsTranscode && cls.kind === 'audio') {
        transcodedTmp = transcode.transcodeToMp3(f.path);
        uploadPath = transcodedTmp;
        uploadSize = fs.statSync(transcodedTmp).size;
        effectiveOriginalName = f.originalname.replace(/\.[^.]+$/, '') + '.mp3';
        if (uploadSize > cls.maxBytes) {
          try { fs.unlinkSync(transcodedTmp); } catch {}
          throw new Error(`Recording is too long — after MP3 conversion it's ${fmtBytes(uploadSize)} (limit ${fmtBytes(cls.maxBytes)}).`);
        }
      }

      const ghlCfg = users.effectiveGhlConfig(fresh);
      const ghlUrl = ghl.uploadToGhl(uploadPath, ghlDisplayName, cls.ghlMime, ghlCfg);

      fdb.insert({
        slug, title, original_filename: effectiveOriginalName,
        kind: cls.kind, mime_type: cls.mime, size_bytes: uploadSize,
        download_allowed: allowDownload, ghl_url: ghlUrl,
        user_id: req.user.id, notes,
      });
      if (transcodedTmp) { try { fs.unlinkSync(transcodedTmp); } catch {} }

      const fresh2 = fdb.getBySlug(slug);
      res.json({ ok: true, file: fileToJSON(fresh2, PUBLIC_ORIGIN) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    } finally {
      try { fs.unlinkSync(f.path); } catch {}
    }
  });

  router.get('/files/:slug', requireApiToken, (req, res) => {
    const row = fdb.getBySlug(req.params.slug);
    if (!row || row.user_id !== req.user.id) return res.status(404).json({ ok: false, error: 'Not found.' });
    res.json({ ok: true, file: fileToJSON(row, PUBLIC_ORIGIN) });
  });

  router.patch('/files/:slug', requireApiToken, jsonBody, (req, res) => {
    const row = fdb.getBySlug(req.params.slug);
    if (!row || row.user_id !== req.user.id) return res.status(404).json({ ok: false, error: 'Not found.' });
    const updates = req.body || {};
    if (typeof updates.title === 'string') {
      fdb.updateTitle(row.slug, req.user.id, updates.title.trim().slice(0, 200));
    }
    if (typeof updates.notes === 'string') {
      fdb.updateNotes(row.slug, req.user.id, updates.notes.slice(0, NOTES_MAX_CHARS));
    }
    if (typeof updates.download_allowed === 'boolean') {
      fdb.setDownloadAllowed(row.slug, req.user.id, updates.download_allowed);
    }
    res.json({ ok: true, file: fileToJSON(fdb.getBySlug(req.params.slug), PUBLIC_ORIGIN) });
  });

  router.delete('/files/:slug', requireApiToken, (req, res) => {
    const ghlUrl = fdb.deleteBySlugForUser(req.params.slug, req.user.id);
    if (ghlUrl == null) return res.status(404).json({ ok: false, error: 'Not found.' });
    try {
      const cfg = users.effectiveGhlConfig(udb.getById(req.user.id));
      ghl.tryDeleteFromGhl(ghlUrl, cfg);
    } catch {}
    res.json({ ok: true });
  });

  // ---------- MESSAGES + GROUPS ----------

  router.get('/messages', requireApiToken, (req, res) => {
    const groups = gdb.listForUser(req.user.id);
    // listRecentByUser returns all messages; filter to standalone only here.
    const allMessages = mdb.listRecentByUser(req.user.id, { limit: 100 });
    const standalone = (allMessages || []).filter((m) => m.group_id == null);
    const groupsWithChildren = groups.map((g) => {
      const children = mdb.listInGroup(g.id, req.user.id);
      return groupToJSON(g, children, PUBLIC_ORIGIN);
    });
    res.json({
      ok: true,
      groups: groupsWithChildren,
      messages: standalone.map((m) => messageToJSON(m, PUBLIC_ORIGIN)),
    });
  });

  router.post('/messages', requireApiToken, jsonBody, (req, res) => {
    try {
      const { title, body, group_slug } = req.body || {};
      const slug = nanoid(8);
      let groupId = null;
      if (group_slug) {
        const g = gdb.getBySlugForUser(group_slug, req.user.id);
        if (!g) return res.status(400).json({ ok: false, error: 'Group not found.' });
        groupId = g.id;
      }
      mdb.insert({
        slug, userId: req.user.id,
        title: (title || '').toString().slice(0, 200),
        body: (body || '').toString().slice(0, 200000),
      });
      if (groupId) {
        mdb.moveToGroup(slug, req.user.id, groupId);
      }
      const fresh = mdb.getBySlugForUser(slug, req.user.id);
      res.json({ ok: true, message: messageToJSON(fresh, PUBLIC_ORIGIN) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  router.patch('/messages/:slug', requireApiToken, jsonBody, (req, res) => {
    const m = mdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!m) return res.status(404).json({ ok: false, error: 'Not found.' });
    const { title, body } = req.body || {};
    mdb.update(m.id, req.user.id, {
      title: title != null ? String(title).slice(0, 200) : m.title,
      body:  body  != null ? String(body).slice(0, 200000) : m.body,
    });
    const fresh = mdb.getBySlugForUser(req.params.slug, req.user.id);
    res.json({ ok: true, message: messageToJSON(fresh, PUBLIC_ORIGIN) });
  });

  router.delete('/messages/:slug', requireApiToken, (req, res) => {
    const m = mdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!m) return res.status(404).json({ ok: false, error: 'Not found.' });
    mdb.deleteByIdForUser(m.id, req.user.id);
    res.json({ ok: true });
  });

  router.post('/messages/:slug/move', requireApiToken, jsonBody, (req, res) => {
    const direction = (req.body?.direction || '').toString();
    if (!['up', 'down'].includes(direction)) {
      return res.status(400).json({ ok: false, error: "direction must be 'up' or 'down'" });
    }
    const r = feeddb.move({ kind: 'message', slug: req.params.slug, userId: req.user.id, direction });
    if (!r.ok) return res.status(400).json({ ok: false, error: r.reason });
    res.json({ ok: true });
  });

  router.post('/groups/:slug/move', requireApiToken, jsonBody, (req, res) => {
    const direction = (req.body?.direction || '').toString();
    if (!['up', 'down'].includes(direction)) {
      return res.status(400).json({ ok: false, error: "direction must be 'up' or 'down'" });
    }
    const r = feeddb.move({ kind: 'group', slug: req.params.slug, userId: req.user.id, direction });
    if (!r.ok) return res.status(400).json({ ok: false, error: r.reason });
    res.json({ ok: true });
  });

  router.post('/messages/:slug/group', requireApiToken, jsonBody, (req, res) => {
    const m = mdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!m) return res.status(404).json({ ok: false, error: 'Not found.' });
    const groupSlug = req.body?.group_slug;
    if (groupSlug == null) {
      mdb.moveToGroup(m.slug, req.user.id, null);
      return res.json({ ok: true });
    }
    const g = gdb.getBySlugForUser(groupSlug, req.user.id);
    if (!g) return res.status(400).json({ ok: false, error: 'Group not found.' });
    mdb.moveToGroup(m.slug, req.user.id, g.id);
    res.json({ ok: true });
  });

  router.get('/groups', requireApiToken, (req, res) => {
    const groups = gdb.listForUser(req.user.id);
    res.json({
      ok: true,
      groups: groups.map((g) => groupToJSON(g, [], PUBLIC_ORIGIN)),
    });
  });

  router.post('/groups', requireApiToken, jsonBody, (req, res) => {
    try {
      const slug = nanoid(8);
      gdb.insert({ slug, user_id: req.user.id, title: (req.body?.title || '').toString().slice(0, 200) });
      const fresh = gdb.getBySlugForUser(slug, req.user.id);
      res.json({ ok: true, group: groupToJSON(fresh, [], PUBLIC_ORIGIN) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  router.patch('/groups/:slug', requireApiToken, jsonBody, (req, res) => {
    const g = gdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!g) return res.status(404).json({ ok: false, error: 'Not found.' });
    gdb.rename(g.id, req.user.id, (req.body?.title || '').toString().slice(0, 200));
    const fresh = gdb.getBySlugForUser(req.params.slug, req.user.id);
    res.json({ ok: true, group: groupToJSON(fresh, [], PUBLIC_ORIGIN) });
  });

  router.delete('/groups/:slug', requireApiToken, (req, res) => {
    const g = gdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!g) return res.status(404).json({ ok: false, error: 'Not found.' });
    gdb.deleteByIdForUser(g.id, req.user.id);
    res.json({ ok: true });
  });

  router.post('/groups/:slug/reorder-tiles', requireApiToken, jsonBody, (req, res) => {
    const g = gdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!g) return res.status(404).json({ ok: false, error: 'Not found.' });
    const order = Array.isArray(req.body?.order) ? req.body.order.map(String) : null;
    if (!order) return res.status(400).json({ ok: false, error: 'order: [slug...] required' });
    mdb.reorderTilesInGroup({ groupId: g.id, userId: req.user.id, slugs: order });
    res.json({ ok: true });
  });

  // ---------- DEVICES ----------

  // ---------- CHAT SCROLLS ----------
  //
  // Lifecycle mirrors the web flow exactly, and the client must follow it in
  // order: create a draft → POST each screenshot one at a time → finalize.
  // Position is assigned server-side from arrival order, so a client that
  // uploads in parallel will scramble the sequence the user just arranged.
  // A draft is invisible at /c/<slug> until finalize, and is swept after 24h
  // if the client walks away mid-upload.

  function ownedChat(req, res) {
    const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
    if (!c) {
      res.status(404).json({ ok: false, error: 'Not found.' });
      return null;
    }
    return c;
  }

  router.get('/chats', requireApiToken, (req, res) => {
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit || '50', 10) || 50));
    const offset = Math.max(0, parseInt(req.query.offset || '0', 10) || 0);
    const rows = cdb.listByUser(req.user.id, { limit, offset });
    res.json({
      ok: true,
      chats: rows.map((c) => chatToJSON(c, cdb.items(c.id), PUBLIC_ORIGIN)),
      // So the client can grey out "New chat scroll" instead of letting the
      // user pick 20 screenshots and only then hit a 403.
      can_create: chatHelpers.gate(req.user).ok,
      max_items: chatHelpers.itemCap(req.user),
    });
  });

  // Reorder the chat-scroll CARDS. The screenshots inside one scroll are
  // reordered by /chats/:slug/reorder further down — different thing.
  router.post('/chats/reorder', requireApiToken, jsonBody, (req, res) => {
    const order = Array.isArray(req.body?.order) ? req.body.order.map(String) : null;
    if (!order) return res.status(400).json({ ok: false, error: 'order: [slug...] required' });
    const result = cdb.reorderForUser(req.user.id, order);
    res.json({ ok: true, updated: result.updated });
  });

  router.post('/chats', requireApiToken, jsonBody, (req, res) => {
    const gate = chatHelpers.gate(req.user);
    if (!gate.ok) return res.status(403).json({ ok: false, error: gate.reason });
    const title = (req.body?.title || '').toString().trim().slice(0, 200);
    const notes = (req.body?.notes || '').toString().slice(0, NOTES_MAX_CHARS);
    const allowDownload = req.body?.download_allowed === true;
    const slug = nanoid(8);
    cdb.create({ slug, user_id: req.user.id, title, notes, download_allowed: allowDownload ? 1 : 0 });
    const c = cdb.getBySlugForUser(slug, req.user.id);
    res.json({ ok: true, chat: chatToJSON(c, [], PUBLIC_ORIGIN) });
  });

  router.get('/chats/:slug', requireApiToken, (req, res) => {
    const c = ownedChat(req, res); if (!c) return;
    res.json({ ok: true, chat: chatToJSON(c, cdb.items(c.id), PUBLIC_ORIGIN) });
  });

  router.post('/chats/:slug/items', requireApiToken, upload.single('file'), (req, res) => {
    const f = req.file;
    if (!f) return res.status(400).json({ ok: false, error: 'No image uploaded.' });
    try {
      const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
      if (!c) throw new Error('That chat scroll no longer exists.');

      const fresh = udb.getById(req.user.id);
      if (!fresh) throw new Error('Account not found.');
      if (fresh.status === 'deactivated') throw new Error('Your account is deactivated. Contact the admin.');

      const cls = classify(f.originalname, f.mimetype);
      if (cls.kind !== 'image') {
        throw new Error(`${f.originalname} isn't an image — a chat scroll only takes screenshots.`);
      }
      if (f.size > cls.maxBytes) {
        throw new Error(`${f.originalname} is ${fmtBytes(f.size)} but the limit is ${fmtBytes(cls.maxBytes)} per screenshot.`);
      }

      const cap = chatHelpers.itemCap(fresh);
      const count = cdb.countItems(c.id);
      if (count >= cap) throw new Error(`This scroll is full at ${cap} screenshots.`);

      const position = cdb.nextPosition(c.id);
      const uniq = nanoid(6);
      const ghlDisplayName =
        `${sanitizeForFilename(c.title || 'chat')}-${String(position + 1).padStart(3, '0')}-${uniq}.${cls.ghlExt}`;

      const ghlCfg = users.effectiveGhlConfig(fresh);
      const ghlUrl = ghl.uploadToGhl(f.path, ghlDisplayName, cls.ghlMime, ghlCfg);

      cdb.addItem({
        chat_id: c.id, position, ghl_url: ghlUrl,
        original_filename: f.originalname,
        mime_type: cls.mime, size_bytes: f.size,
        width: Math.max(0, parseInt(req.body.width, 10) || 0),
        height: Math.max(0, parseInt(req.body.height, 10) || 0),
      });
      cdb.touch(c.id);

      res.json({ ok: true, chat: chatToJSON(c, cdb.items(c.id), PUBLIC_ORIGIN) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    } finally {
      try { fs.unlinkSync(f.path); } catch {}
    }
  });

  /**
   * Replace the picture behind one screenshot, in place.
   *
   * This is what "edit screenshot 3" means: same id, same position, same link —
   * only the picture changes. The new one goes up to the drive first, and the
   * one it replaced is only deleted once the swap is safely recorded, so a
   * failure halfway can never leave the scroll pointing at nothing.
   */
  router.post('/chats/:slug/items/:id', requireApiToken, upload.single('file'), (req, res) => {
    const f = req.file;
    if (!f) return res.status(400).json({ ok: false, error: 'No image uploaded.' });
    try {
      const c = cdb.getBySlugForUser(req.params.slug, req.user.id);
      if (!c) throw new Error('That chat scroll no longer exists.');

      const itemId = parseInt(req.params.id, 10);
      const existing = cdb.getItem(c.id, itemId);
      if (!existing) throw new Error('That screenshot is no longer in this scroll.');

      const fresh = udb.getById(req.user.id);
      if (!fresh) throw new Error('Account not found.');
      if (fresh.status === 'deactivated') throw new Error('Your account is deactivated. Contact the admin.');

      const cls = classify(f.originalname, f.mimetype);
      if (cls.kind !== 'image') {
        throw new Error(`${f.originalname} isn't an image — a chat scroll only takes screenshots.`);
      }
      if (f.size > cls.maxBytes) {
        throw new Error(`${f.originalname} is ${fmtBytes(f.size)} but the limit is ${fmtBytes(cls.maxBytes)} per screenshot.`);
      }

      const uniq = nanoid(6);
      const ghlDisplayName =
        `${sanitizeForFilename(c.title || 'chat')}-${String(existing.position + 1).padStart(3, '0')}-${uniq}.${cls.ghlExt}`;

      const ghlCfg = users.effectiveGhlConfig(fresh);
      const ghlUrl = ghl.uploadToGhl(f.path, ghlDisplayName, cls.ghlMime, ghlCfg);

      const before = cdb.replaceItem(c.id, itemId, {
        ghl_url: ghlUrl,
        original_filename: f.originalname,
        mime_type: cls.mime,
        size_bytes: f.size,
        width: Math.max(0, parseInt(req.body.width, 10) || 0),
        height: Math.max(0, parseInt(req.body.height, 10) || 0),
      });
      cdb.touch(c.id);

      if (before && before.ghl_url && before.ghl_url !== ghlUrl) {
        chatHelpers.purge([before.ghl_url], fresh);
      }

      res.json({ ok: true, chat: chatToJSON(c, cdb.items(c.id), PUBLIC_ORIGIN) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    } finally {
      try { fs.unlinkSync(f.path); } catch {}
    }
  });

  router.post('/chats/:slug/finalize', requireApiToken, (req, res) => {
    const c = ownedChat(req, res); if (!c) return;
    if (cdb.countItems(c.id) < 1) {
      return res.status(400).json({ ok: false, error: 'Add at least one screenshot first.' });
    }
    cdb.markReady(c.id);
    const fresh = cdb.getBySlugForUser(c.slug, req.user.id);
    res.json({ ok: true, chat: chatToJSON(fresh, cdb.items(c.id), PUBLIC_ORIGIN) });
  });

  router.post('/chats/:slug/reorder', requireApiToken, jsonBody, (req, res) => {
    const c = ownedChat(req, res); if (!c) return;
    const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
    cdb.reorder(c.id, ids);
    res.json({ ok: true, chat: chatToJSON(c, cdb.items(c.id), PUBLIC_ORIGIN) });
  });

  router.patch('/chats/:slug', requireApiToken, jsonBody, (req, res) => {
    const c = ownedChat(req, res); if (!c) return;
    if (typeof req.body?.title === 'string') cdb.setTitle(c.id, req.body.title.trim());
    if (typeof req.body?.notes === 'string') cdb.setNotes(c.id, req.body.notes.slice(0, NOTES_MAX_CHARS));
    if (typeof req.body?.download_allowed === 'boolean') cdb.setDownload(c.id, req.body.download_allowed);
    const fresh = cdb.getBySlugForUser(c.slug, req.user.id);
    res.json({ ok: true, chat: chatToJSON(fresh, cdb.items(c.id), PUBLIC_ORIGIN) });
  });

  router.delete('/chats/:slug/items/:id', requireApiToken, (req, res) => {
    const c = ownedChat(req, res); if (!c) return;
    const removed = cdb.deleteItem(c.id, parseInt(req.params.id, 10));
    if (!removed) return res.status(404).json({ ok: false, error: 'That screenshot is already gone.' });
    // Close the gap so positions stay 0..n-1.
    cdb.reorder(c.id, cdb.items(c.id).map((i) => i.id));
    chatHelpers.purge([removed.ghl_url], udb.getById(req.user.id));
    res.json({ ok: true, chat: chatToJSON(c, cdb.items(c.id), PUBLIC_ORIGIN) });
  });

  router.delete('/chats/:slug', requireApiToken, (req, res) => {
    const userRow = udb.getById(req.user.id);
    const urls = cdb.deleteForUser(req.params.slug, req.user.id);
    if (urls == null) return res.status(404).json({ ok: false, error: 'Not found.' });
    chatHelpers.purge(urls, userRow);
    res.json({ ok: true });
  });

  router.post('/devices/register', requireApiToken, jsonBody, (req, res) => {
    const { apns_token, device_id, env } = req.body || {};
    if (!apns_token || !device_id) {
      return res.status(400).json({ ok: false, error: 'apns_token and device_id required' });
    }
    dtdb.upsert({
      user_id: req.user.id,
      device_id: String(device_id).slice(0, 128),
      apns_token: String(apns_token),
      apns_env: env === 'sandbox' ? 'sandbox' : 'production',
    });
    res.json({ ok: true });
  });

  router.delete('/devices/:device_id', requireApiToken, (req, res) => {
    dtdb.deleteByUserAndDevice(req.user.id, String(req.params.device_id));
    res.json({ ok: true });
  });

  // ---------- ADMIN ----------

  router.get('/admin/users', requireApiToken, requireAdmin, (req, res) => {
    const list = udb.list();
    res.json({ ok: true, users: list.map(sanitizeUser) });
  });

  router.post('/admin/users', requireApiToken, requireAdmin, jsonBody, (req, res) => {
    try {
      const { name, email, password, type } = req.body || {};
      const status = type === 'admin' ? 'regular'
                  : type === 'deactivated' ? 'deactivated'
                  : type === 'regular' ? 'regular'
                  : 'trial';
      const u = users.signup({ name, email, password, status, is_admin: type === 'admin' });
      res.json({ ok: true, user: sanitizeUser(udb.getById(u.id)) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  router.patch('/admin/users/:id', requireApiToken, requireAdmin, jsonBody, (req, res) => {
    const id = parseInt(req.params.id, 10);
    const target = udb.getById(id);
    if (!target) return res.status(404).json({ ok: false, error: 'Not found.' });
    if (id === req.user.id && req.body?.status === 'deactivated') {
      return res.status(400).json({ ok: false, error: 'You cannot deactivate yourself.' });
    }
    if (req.body?.status) udb.setStatus(id, req.body.status);
    res.json({ ok: true, user: sanitizeUser(udb.getById(id)) });
  });

  router.post('/admin/users/:id/reset-password', requireApiToken, requireAdmin, jsonBody, (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const pw = (req.body?.password || '').toString();
      if (pw.length < 8) return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });
      udb.setPasswordHash(id, users.hashPassword(pw));
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  router.delete('/admin/users/:id', requireApiToken, requireAdmin, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (id === req.user.id) {
      return res.status(400).json({ ok: false, error: 'You cannot delete yourself.' });
    }
    // Best-effort GHL teardown for that user's files using their own config
    try {
      const ownerRow = udb.getById(id);
      const cfg = users.effectiveGhlConfig(ownerRow || {});
      const ownerFiles = fdb.listByUser(id) || [];
      for (const f of ownerFiles) {
        try { ghl.tryDeleteFromGhl(f.ghl_url, cfg); } catch {}
      }
    } catch {}
    udb.deleteById(id);
    res.json({ ok: true });
  });

  router.get('/admin/system', requireApiToken, requireAdmin, (req, res) => {
    const { execSync } = require('node:child_process');
    function tryExec(cmd) {
      try { return execSync(cmd, { encoding: 'utf8', timeout: 5000 }).trim(); }
      catch (e) { return `error: ${e.message}`; }
    }
    res.json({
      ok: true,
      df: tryExec('df -h'),
      uptime: tryExec('uptime'),
      free: tryExec('free -h || vm_stat'),
      hostname: tryExec('hostname'),
      node_version: process.version,
      apns_configured: apns.configured,
    });
  });

  // Mount under /api/v1
  app.use('/api/v1', router);
}

module.exports = { attach };

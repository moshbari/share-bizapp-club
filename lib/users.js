// User helpers: password hashing, signup/login, session helpers, trial seed.
//
// We use bcryptjs (pure JS) instead of bcrypt (native addon) so the Docker
// image stays slim — no compile toolchain needed. Cost tradeoff is fine at
// 10 rounds for our scale.

const bcrypt = require('bcryptjs');
const { users: udb, files: fdb } = require('./db');

const BCRYPT_ROUNDS = 10;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function hashPassword(plain) {
  if (!plain || typeof plain !== 'string') throw new Error('password required');
  if (plain.length < 8) throw new Error('password must be at least 8 characters');
  return bcrypt.hashSync(plain, BCRYPT_ROUNDS);
}

function verifyPassword(plain, hash) {
  if (!plain || !hash) return false;
  try { return bcrypt.compareSync(plain, hash); }
  catch { return false; }
}

/**
 * Create a new user. New signups default to status='trial'.
 * Returns the new user row (with password_hash stripped).
 */
function signup({ email, name, password, status = 'trial', is_admin = false }) {
  email = (email || '').toLowerCase().trim();
  name = (name || '').trim();
  if (!EMAIL_RE.test(email)) throw new Error('Please use a valid email address.');
  if (!name) throw new Error('Please enter your name.');
  if (udb.getByEmail(email)) throw new Error('An account with that email already exists.');

  const password_hash = hashPassword(password);
  const id = udb.insert({ email, name, password_hash, status, is_admin: is_admin ? 1 : 0 });
  return sanitize(udb.getById(id));
}

/**
 * Log in — returns a sanitized user row on success, or null on failure
 * or on a disabled account.
 */
function login({ email, password }) {
  const u = udb.getByEmail(email);
  if (!u) return null;
  if (!verifyPassword(password, u.password_hash)) return null;
  if (u.status === 'deactivated') return null;
  return sanitize(u);
}

/** Strip the password hash before ever handing a user to a caller. */
function sanitize(u) {
  if (!u) return null;
  const { password_hash, ...rest } = u;
  return rest;
}

/**
 * Seed an admin on first boot if ADMIN_EMAIL + ADMIN_PASSWORD are set and
 * no admin currently exists. Also promotes an existing non-admin with that
 * email if one exists, and backfills any orphan files to the admin id.
 */
function seedAdminFromEnv() {
  const email = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!email || !password) {
    console.warn('[admin-seed] ADMIN_EMAIL / ADMIN_PASSWORD not set — skipping seed');
    return null;
  }

  let existing = udb.getByEmail(email);
  if (!existing) {
    const id = udb.insert({
      email,
      name: 'Admin',
      password_hash: hashPassword(password),
      status: 'regular',
      is_admin: 1,
    });
    existing = udb.getById(id);
    console.log(`[admin-seed] created admin ${email} (id=${id})`);
  } else {
    let changed = false;
    if (!existing.is_admin) { udb.setAdmin(existing.id, true); changed = true; }
    if (existing.status !== 'regular') { udb.setStatus(existing.id, 'regular'); changed = true; }
    if (changed) {
      existing = udb.getById(existing.id);
      console.log(`[admin-seed] promoted ${email} to admin/regular`);
    }
  }

  // Backfill any files that predate the multi-user schema — they'd otherwise
  // be invisible to every user. Pin them to the admin so they remain usable.
  const backfilled = fdb.backfillNullUserTo(existing.id);
  if (backfilled > 0) {
    console.log(`[admin-seed] backfilled ${backfilled} orphan file(s) to admin id=${existing.id}`);
  }

  return sanitize(existing);
}

/**
 * Trial cap: one file per kind. Returns the kinds they've already used so
 * the upload page can render a nice status.
 */
function trialUsage(userId) {
  const kinds = ['image', 'video', 'audio', 'pdf', 'text'];
  const used = {};
  for (const k of kinds) {
    used[k] = fdb.countByUserAndKind(userId, k) > 0;
  }
  const remaining = kinds.filter(k => !used[k]);
  return { kinds, used, remaining };
}

/**
 * Gate an upload against the user's status.
 * Returns { ok: true } or { ok: false, reason }.
 */
function checkUploadAllowed(user, kind) {
  if (!user) return { ok: false, reason: 'Not logged in.' };
  if (user.status === 'deactivated') {
    return { ok: false, reason: 'Your account is deactivated. Contact the admin.' };
  }
  if (user.status === 'trial') {
    const count = fdb.countByUserAndKind(user.id, kind);
    if (count >= 1) {
      return {
        ok: false,
        reason: `Your trial allows one ${kind} file. Ask the admin to upgrade your account to upload more.`,
      };
    }
  }
  return { ok: true };
}

/**
 * Resolve the effective GHL config for a user.
 * Returns { apiKey, locationId, folderId, folderName, source } where
 * `source` is 'user' if all three required fields are set on the user,
 * otherwise 'shared'. `folderName` is for display only.
 */
function effectiveGhlConfig(userRow) {
  if (userRow && userRow.ghl_api_key && userRow.ghl_location_id && userRow.ghl_folder_id) {
    return {
      apiKey: userRow.ghl_api_key,
      locationId: userRow.ghl_location_id,
      folderId: userRow.ghl_folder_id,
      folderName: userRow.ghl_folder_name || '(your folder)',
      source: 'user',
    };
  }
  return {
    apiKey: process.env.GHL_API_KEY || '',
    locationId: process.env.GHL_LOCATION_ID || '',
    folderId: process.env.GHL_FOLDER_ID || '',
    folderName: 'shared (default)',
    source: 'shared',
  };
}

module.exports = {
  hashPassword,
  verifyPassword,
  signup,
  login,
  seedAdminFromEnv,
  trialUsage,
  checkUploadAllowed,
  effectiveGhlConfig,
  sanitize,
};

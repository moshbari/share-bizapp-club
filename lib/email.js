// Transactional email via Resend (resend.com). One endpoint, one function.
//
// Env vars:
//   RESEND_API_KEY    the key you created in Resend → API Keys
//   EMAIL_FROM        the full "From" address (must be on a verified Resend domain)
//   EMAIL_FROM_NAME   optional display name (defaults to SITE_NAME)
//
// We POST to https://api.resend.com/emails using Node 20's built-in fetch.
// No additional npm deps. On send failures, we log the body and throw so the
// caller can decide whether to surface to the user or swallow.

function isConfigured() {
  return Boolean(process.env.RESEND_API_KEY && process.env.EMAIL_FROM);
}

/**
 * Send a transactional email.
 * @param {{to: string, subject: string, html: string, text: string, replyTo?: string}} msg
 * @returns {Promise<{id: string}>} — Resend's message id on success
 */
async function send({ to, subject, html, text, replyTo }) {
  if (!isConfigured()) {
    throw new Error('[email] RESEND_API_KEY or EMAIL_FROM not set');
  }
  const fromName = process.env.EMAIL_FROM_NAME || process.env.SITE_NAME || 'share.bizapp.club';
  const fromAddr = process.env.EMAIL_FROM;
  const from = fromName ? `${fromName} <${fromAddr}>` : fromAddr;

  const body = { from, to: [to], subject, html, text };
  if (replyTo) body.reply_to = replyTo;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const responseText = await res.text();
  if (!res.ok) {
    // Scrub our key from any echoed body before logging.
    throw new Error(`[email] Resend ${res.status}: ${responseText.slice(0, 400)}`);
  }
  try {
    const parsed = JSON.parse(responseText);
    return { id: parsed.id };
  } catch {
    return { id: null };
  }
}

/**
 * Render + send a password-reset email. Caller builds the reset URL with a
 * raw (not hashed) token that's been stored hashed in the DB.
 */
async function sendPasswordResetEmail({ toEmail, toName, resetUrl, siteName }) {
  const name = (toName || '').split(/\s+/)[0] || 'there';
  const subject = `Reset your ${siteName} password`;

  const text = [
    `Hi ${name},`,
    '',
    `Someone asked to reset the password for your ${siteName} account.`,
    `Open the link below to choose a new password. The link expires in 24 hours.`,
    '',
    resetUrl,
    '',
    `If that wasn't you, ignore this email — your password won't change.`,
    '',
    `— ${siteName}`,
  ].join('\n');

  const html = `<!doctype html>
<html>
<body style="margin:0; padding:0; background:#f3f5fb; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',sans-serif; color:#0f172a;">
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:#f3f5fb; padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="max-width:520px; background:#ffffff; border-radius:16px; border:1px solid #e5e7eb; overflow:hidden;">
        <tr><td style="padding:32px 32px 8px;">
          <div style="font-size:15px; font-weight:700; letter-spacing:-0.01em; color:#0f172a;">
            <span style="display:inline-block; vertical-align:middle; font-size:20px; margin-right:6px;">\u{1F4E4}</span>
            ${escapeHtml(siteName)}
          </div>
        </td></tr>
        <tr><td style="padding:8px 32px 0;">
          <h1 style="margin:0 0 8px; font-size:22px; font-weight:700; letter-spacing:-0.02em; color:#0f172a;">Reset your password</h1>
          <p style="margin:0 0 20px; font-size:15px; line-height:1.55; color:#334155;">
            Hi ${escapeHtml(name)}, someone asked to reset the password for your ${escapeHtml(siteName)} account.
            Click the button below to choose a new one. The link expires in <strong>24 hours</strong>.
          </p>
        </td></tr>
        <tr><td style="padding:8px 32px 24px;">
          <a href="${escapeHtml(resetUrl)}"
             style="display:inline-block; padding:12px 20px; background:#2563eb; color:#ffffff; text-decoration:none; font-weight:600; font-size:15px; border-radius:10px;">
            Set new password
          </a>
        </td></tr>
        <tr><td style="padding:0 32px 24px;">
          <p style="margin:0 0 8px; font-size:13px; color:#64748b;">
            If the button doesn't work, paste this into your browser:
          </p>
          <p style="margin:0; font-size:12px; color:#475569; word-break:break-all; font-family:ui-monospace,Menlo,monospace;">${escapeHtml(resetUrl)}</p>
        </td></tr>
        <tr><td style="padding:16px 32px 32px; border-top:1px solid #e5e7eb;">
          <p style="margin:0; font-size:12px; color:#94a3b8;">
            If that wasn't you, ignore this email \u2014 your password won't change. Links expire after use or 24 hours.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  return send({ to: toEmail, subject, html, text });
}

function escapeHtml(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

module.exports = { isConfigured, send, sendPasswordResetEmail };

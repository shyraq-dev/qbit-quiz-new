const crypto = require('crypto');
const SECRET = () => process.env.SESSION_SECRET || 'session_secret_change_me';

function makeSessionToken(uid) {
  const payload = Buffer.from(JSON.stringify({ uid, ts: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET()).update(payload).digest('hex');
  return `${payload}.${sig}`;
}
function verifySessionToken(token) {
  if (!token) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = token.slice(0, dot);
  const sig     = token.slice(dot + 1);
  const exp = crypto.createHmac('sha256', SECRET()).update(payload).digest('hex');
  if (exp !== sig) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()); }
  catch { return null; }
}
module.exports = { makeSessionToken, verifySessionToken };

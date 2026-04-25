// lib/session.js — session token логикасы (auth.js мен db.js ортақ қолданады)
import crypto from 'crypto';

const SECRET = () => process.env.SESSION_SECRET || 'session_secret_change_me';

export function makeSessionToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, ts: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET()).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

export function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = token.slice(0, dot);
  const sig     = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SECRET()).update(payload).digest('hex');
  if (expected !== sig) return null;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}
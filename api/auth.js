// api/auth.js
import crypto from 'crypto';
import { sbSelect, sbInsert, sbUpsert, sbUpdate, cors, ok, err } from '../lib/supabase.js';

const BOT_TOKEN  = process.env.BOT_TOKEN;
const ADMIN_ID   = process.env.ADMIN_ID;

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return err(res, 'POST only', 405);

  const { action, payload = {} } = req.body || {};

  try {
    switch (action) {
      case 'register':        return ok(res, await register(payload));
      case 'login':           return ok(res, await login(payload));
      case 'telegram_auth':   return ok(res, await telegramAuth(payload));
      case 'forgot_password': return ok(res, await forgotPassword(payload));
      case 'reset_password':  return ok(res, await resetPassword(payload));
      case 'verify_session':  return ok(res, await verifySession(payload));
      default: return err(res, 'Unknown action');
    }
  } catch (e) {
    console.error('[auth]', action, e.message);
    return err(res, e.message, e.status || 500);
  }
}

// ── Helpers ───────────────────────────────────────────────
function hashPwd(pwd) {
  return crypto.createHmac('sha256', process.env.PWD_SECRET || 'qbit_secret')
    .update(pwd).digest('hex');
}

function makeToken(len = 32) {
  return crypto.randomBytes(len).toString('hex');
}

function makeSessionToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, ts: Date.now() })).toString('base64');
  const sig = crypto.createHmac('sha256', process.env.SESSION_SECRET || 'session_secret')
    .update(payload).digest('hex');
  return `${payload}.${sig}`;
}

export function verifySessionToken(token) {
  if (!token) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET || 'session_secret')
    .update(payload).digest('hex');
  if (expected !== sig) return null;
  try {
    return JSON.parse(Buffer.from(payload, 'base64').toString());
  } catch { return null; }
}

// ── Telegram initData verification ────────────────────────
function verifyTelegram(initData) {
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  params.delete('hash');
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`).join('\n');
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const expected  = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  return expected === hash;
}

// ── ACTIONS ───────────────────────────────────────────────
async function register({ username, handle, password, password2, first_name, bio, birthdate, avatar_emoji }) {
  if (!username?.trim()) throw Object.assign(new Error('username_required'), { status: 400 });
  if (!password || password.length < 6) throw Object.assign(new Error('password_too_short'), { status: 400 });
  if (password !== password2) throw Object.assign(new Error('passwords_mismatch'), { status: 400 });

  const uid = 'web:' + makeToken(8);

  // username бірегейлігін тексеру
  const existing = await sbSelect('users', `username=eq.${encodeURIComponent(username)}&limit=1`);
  if (existing.length) throw Object.assign(new Error('username_taken'), { status: 400 });

  // handle тексеру
  if (handle) {
    const h = handle.replace(/^@/, '');
    const hexist = await sbSelect('users', `handle=eq.${encodeURIComponent(h)}&limit=1`);
    if (hexist.length) throw Object.assign(new Error('handle_taken'), { status: 400 });
  }

  const rows = await sbInsert('users', {
    id: uid,
    source: 'web',
    username: username.trim(),
    handle: handle ? handle.replace(/^@/, '') : null,
    first_name: first_name?.trim() || username.trim(),
    bio: bio?.trim() || null,
    birthdate: birthdate || null,
    avatar_emoji: avatar_emoji || null,
    password_hash: hashPwd(password),
    is_admin: false,
  });

  const user = Array.isArray(rows) ? rows[0] : rows;
  const token = makeSessionToken(user.id);
  return { user: safeUser(user), token };
}

async function login({ username, password }) {
  if (!username || !password) throw Object.assign(new Error('fields_required'), { status: 400 });
  const rows = await sbSelect('users', `username=eq.${encodeURIComponent(username)}&source=eq.web&limit=1`);
  if (!rows.length) throw Object.assign(new Error('user_not_found'), { status: 404 });
  const user = rows[0];
  if (user.password_hash !== hashPwd(password)) throw Object.assign(new Error('wrong_password'), { status: 401 });
  const token = makeSessionToken(user.id);
  return { user: safeUser(user), token };
}

async function telegramAuth({ initData }) {
  // Dev mode: initData жоқ болса тек demo
  let tgUser = null;
  if (initData && initData !== 'demo') {
    if (!verifyTelegram(initData)) throw Object.assign(new Error('invalid_telegram_data'), { status: 401 });
    const params = new URLSearchParams(initData);
    tgUser = JSON.parse(params.get('user') || '{}');
  }

  const uid = tgUser ? `tg:${tgUser.id}` : `tg:demo_${makeToken(4)}`;
  const username = tgUser?.username || tgUser?.first_name?.replace(/\s/g, '_') || 'User';

  const rows = await sbUpsert('users', {
    id: uid,
    source: 'telegram',
    username,
    first_name: tgUser?.first_name || username,
    avatar_url: tgUser?.photo_url || null,
    is_admin: tgUser ? String(tgUser.id) === ADMIN_ID : false,
  }, 'id');

  const user = Array.isArray(rows) ? rows[0] : rows;
  const token = makeSessionToken(user.id);
  return { user: safeUser(user), token };
}

async function forgotPassword({ username }) {
  const rows = await sbSelect('users', `username=eq.${encodeURIComponent(username)}&source=eq.web&limit=1`);
  if (!rows.length) return { sent: true }; // security: бар-жоғын айтпаймыз
  const token  = makeToken();
  const expires = new Date(Date.now() + 3600000).toISOString();
  await sbUpdate('users', { reset_token: token, reset_expires: expires }, `id=eq.${rows[0].id}`);
  // Нақты жүйеде email жіберіледі. Қазір token-ді қайтарамыз (demo).
  return { sent: true, _dev_token: token };
}

async function resetPassword({ token, password, password2 }) {
  if (!token || !password) throw Object.assign(new Error('fields_required'), { status: 400 });
  if (password !== password2) throw Object.assign(new Error('passwords_mismatch'), { status: 400 });
  const rows = await sbSelect('users',
    `reset_token=eq.${token}&reset_expires=gte.${new Date().toISOString()}&limit=1`);
  if (!rows.length) throw Object.assign(new Error('invalid_or_expired_token'), { status: 400 });
  await sbUpdate('users', {
    password_hash: hashPwd(password),
    reset_token: null, reset_expires: null,
  }, `id=eq.${rows[0].id}`);
  return { ok: true };
}

async function verifySession({ token }) {
  const decoded = verifySessionToken(token);
  if (!decoded) throw Object.assign(new Error('invalid_session'), { status: 401 });
  const rows = await sbSelect('users', `id=eq.${decoded.uid}&limit=1`);
  if (!rows.length) throw Object.assign(new Error('user_not_found'), { status: 404 });
  return { user: safeUser(rows[0]) };
}

function safeUser(u) {
  const { password_hash, reset_token, reset_expires, ...safe } = u;
  return safe;
}
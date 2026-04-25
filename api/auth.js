// api/auth.js
import crypto from 'crypto';
import { sbSelect, sbInsert, sbUpdate, cors, ok, err } from '../lib/supabase.js';
import { makeSessionToken, verifySessionToken } from '../lib/session.js';

const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_ID  = process.env.ADMIN_ID || process.env.ADMIN_TG_ID || '';

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

// ── Crypto helpers ────────────────────────────────────────
function hashPwd(pwd) {
  return crypto
    .createHmac('sha256', process.env.PWD_SECRET || 'qbit_secret_change_me')
    .update(pwd).digest('hex');
}

function makeToken(len = 32) {
  return crypto.randomBytes(len).toString('hex');
}




// ── Telegram initData verification ───────────────────────
function verifyTelegram(initData) {
  if (!BOT_TOKEN) return true; // dev: token жоқ болса өткіз
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return false;
    params.delete('hash');
    const dataStr = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const expected  = crypto.createHmac('sha256', secretKey).update(dataStr).digest('hex');
    return expected === hash;
  } catch (e) {
    console.warn('[verifyTelegram]', e.message);
    return false;
  }
}

// ── REGISTER (web) ────────────────────────────────────────
async function register({ username, handle, password, password2, first_name, bio, birthdate, avatar_emoji }) {
  if (!username?.trim()) throw se('username_required', 400);
  if (!password || password.length < 6) throw se('password_too_short', 400);
  if (password !== password2) throw se('passwords_mismatch', 400);

  const clean = username.trim();
  const existing = await sbSelect('users', `username=eq.${encodeURIComponent(clean)}&limit=1`);
  if (existing.length) throw se('username_taken', 400);

  if (handle) {
    const h = handle.replace(/^@/, '').trim();
    if (h) {
      const hexist = await sbSelect('users', `handle=eq.${encodeURIComponent(h)}&limit=1`);
      if (hexist.length) throw se('handle_taken', 400);
    }
  }

  const uid  = 'web:' + makeToken(8);
  const rows = await sbInsert('users', {
    id: uid,
    source: 'web',
    username: clean,
    handle: handle ? handle.replace(/^@/, '').trim() || null : null,
    first_name: first_name?.trim() || clean,
    bio: bio?.trim() || null,
    birthdate: birthdate || null,
    avatar_emoji: avatar_emoji || null,
    password_hash: hashPwd(password),
    is_admin: false,
  });

  const user = Array.isArray(rows) ? rows[0] : rows;
  return { user: safe(user), token: makeSessionToken(user.id) };
}

// ── LOGIN (web) ───────────────────────────────────────────
async function login({ username, password }) {
  if (!username || !password) throw se('fields_required', 400);
  const rows = await sbSelect('users',
    `username=eq.${encodeURIComponent(username.trim())}&source=eq.web&limit=1`);
  if (!rows.length) throw se('user_not_found', 404);
  const user = rows[0];
  if (user.password_hash !== hashPwd(password)) throw se('wrong_password', 401);
  return { user: safe(user), token: makeSessionToken(user.id) };
}

// ── TELEGRAM AUTH ─────────────────────────────────────────
async function telegramAuth({ initData }) {
  // initData жоқ немесе бос — браузерден келген, web auth керек
  if (!initData || initData === '') {
    throw se('no_telegram_user', 400);
  }

  // Верификация (BOT_TOKEN жоқ болса dev режим)
  if (!verifyTelegram(initData)) {
    throw se('invalid_telegram_data', 401);
  }

  // User парсинг
  let tgUser = null;
  try {
    const params = new URLSearchParams(initData);
    const userStr = params.get('user');
    if (userStr) tgUser = JSON.parse(userStr);
  } catch (e) {
    console.warn('[tg-auth] parse:', e.message);
  }

  if (!tgUser?.id) throw se('no_telegram_user', 400);

  const uid     = `tg:${tgUser.id}`;
  const isAdmin = !!(ADMIN_ID && String(tgUser.id) === String(ADMIN_ID).trim());

  // Бар user-ді тексеру
  const existing = await sbSelect('users', `id=eq.${encodeURIComponent(uid)}&limit=1`);

  if (existing.length) {
    // Бар user — аватар мен admin-ді жаңарту, username-ді сақтау
    await sbUpdate('users', {
      avatar_url: tgUser.photo_url || existing[0].avatar_url || null,
      first_name: tgUser.first_name || existing[0].first_name,
      is_admin:   isAdmin,
    }, `id=eq.${encodeURIComponent(uid)}`);
    const updated = await sbSelect('users', `id=eq.${encodeURIComponent(uid)}&limit=1`);
    return { user: safe(updated[0] || existing[0]), token: makeSessionToken(uid) };
  }

  // Жаңа user — username қайшылығын шешу
  let base = (tgUser.username || tgUser.first_name || 'user')
    .replace(/\s+/g, '_')
    .replace(/[^a-zA-Z0-9_\u0400-\u04FF]/g, '')
    .slice(0, 20) || 'tg_user';

  const taken = await sbSelect('users', `username=eq.${encodeURIComponent(base)}&limit=1`);
  const username = taken.length ? `${base}_${String(tgUser.id).slice(-4)}` : base;

  const rows = await sbInsert('users', {
    id:         uid,
    source:     'telegram',
    username,
    first_name: tgUser.first_name || username,
    avatar_url: tgUser.photo_url || null,
    is_admin:   isAdmin,
  });

  const user = Array.isArray(rows) ? rows[0] : rows;
  if (!user?.id) throw se('db_error', 500);
  return { user: safe(user), token: makeSessionToken(uid) };
}

// ── FORGOT / RESET PASSWORD ───────────────────────────────
async function forgotPassword({ username }) {
  const rows = await sbSelect('users',
    `username=eq.${encodeURIComponent((username || '').trim())}&source=eq.web&limit=1`);
  if (!rows.length) return { sent: true }; // security: бар-жоғын айтпаймыз

  const token   = makeToken(24);
  const expires = new Date(Date.now() + 3_600_000).toISOString(); // 1 сағат
  await sbUpdate('users',
    { reset_token: token, reset_expires: expires },
    `id=eq.${rows[0].id}`);

  // Production-да email жіберу керек.
  // Dev үшін token-ді қайтарамыз — response-та көрінеді.
  return { sent: true, _dev_token: token };
}

async function resetPassword({ token, password, password2 }) {
  if (!token || !password) throw se('fields_required', 400);
  if (password !== password2) throw se('passwords_mismatch', 400);
  if (password.length < 6) throw se('password_too_short', 400);

  const rows = await sbSelect('users',
    `reset_token=eq.${token}&reset_expires=gte.${new Date().toISOString()}&limit=1`);
  if (!rows.length) throw se('invalid_or_expired_token', 400);

  await sbUpdate('users',
    { password_hash: hashPwd(password), reset_token: null, reset_expires: null },
    `id=eq.${rows[0].id}`);
  return { ok: true };
}

// ── VERIFY SESSION ────────────────────────────────────────
async function verifySession({ token }) {
  const decoded = verifySessionToken(token);
  if (!decoded) throw se('invalid_session', 401);

  const rows = await sbSelect('users', `id=eq.${encodeURIComponent(decoded.uid)}&limit=1`);
  if (!rows.length) throw se('user_not_found', 404);

  const user = safe(rows[0]);
  console.log('[admin-check] user.id='+user.id+' ADMIN_ID='+ADMIN_ID+' match='+(user.id===`tg:${String(ADMIN_ID).trim()}`));
  // is_admin: ADMIN_ID арқылы сервер жағында тексеру
  // (Supabase-та is_admin column жоқ болса да жұмыс істейді)
  if (ADMIN_ID && user.id === `tg:${String(ADMIN_ID).trim()}`) {
    user.is_admin = true;
    // DB-да да жаңарту (жоқ болса қате болмауы үшін try/catch)
    try {
      await sbUpdate('users', { is_admin: true }, `id=eq.${encodeURIComponent(user.id)}`);
    } catch (_) {}
  }
  return { user };
}

// ── Helpers ───────────────────────────────────────────────
function safe(u) {
  if (!u) return null;
  const { password_hash, reset_token, reset_expires, ...rest } = u;
  return rest;
}

function se(msg, status) {
  return Object.assign(new Error(msg), { status });
}
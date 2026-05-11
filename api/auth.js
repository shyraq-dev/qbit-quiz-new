// api/auth.js — Supabase SDK + verifyTelegramData (сіз көрсеткен тәсіл)
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY
);

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_ID  = (process.env.ADMIN_ID || process.env.ADMIN_TG_ID || '').trim();
const PWD_SECRET     = process.env.PWD_SECRET     || 'qbit_pwd_secret';
const SESSION_SECRET = process.env.SESSION_SECRET || 'qbit_session_secret';

// ── CORS ──────────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

// ── TELEGRAM DATA VERIFICATION (сіз көрсеткен тәсіл) ─────
function verifyTelegramData(initData) {
  try {
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    if (!hash) return null;

    urlParams.delete('hash');
    const dataCheckString = Array.from(urlParams.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');

    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(BOT_TOKEN)
      .digest();
    const expectedHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    if (expectedHash !== hash) return null;

    const userStr = urlParams.get('user');
    if (!userStr) return null;
    return JSON.parse(userStr);
  } catch (e) {
    console.error('[verifyTelegramData]', e.message);
    return null;
  }
}

// ── SESSION TOKEN ─────────────────────────────────────────
function makeToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, ts: Date.now() })).toString('base64');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = token.slice(0, dot);
  const sig     = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  if (expected !== sig) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64').toString()); }
  catch { return null; }
}

// ── PASSWORD HASH ─────────────────────────────────────────
function hashPwd(pwd) {
  return crypto.createHmac('sha256', PWD_SECRET).update(pwd).digest('hex');
}

// ── SAFE USER ─────────────────────────────────────────────
function safe(u) {
  if (!u) return null;
  const { password_hash, reset_token, reset_expires, ...rest } = u;
  return rest;
}

function se(msg, status) {
  return Object.assign(new Error(msg), { status });
}

// ── HANDLER ───────────────────────────────────────────────
const handler = async function(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ ok:false, error:'POST only' });

  const { action, payload = {} } = req.body || {};
  try {
    let data;
    switch (action) {
      case 'telegram_auth':   data = await telegramAuth(payload);   break;
      case 'register':        data = await register(payload);       break;
      case 'login':           data = await login(payload);          break;
      case 'verify_session':  data = await verifySession(payload);  break;
      case 'forgot_password': data = await forgotPassword(payload); break;
      case 'reset_password':  data = await resetPassword(payload);  break;
      default: return res.status(400).json({ ok:false, error:'Unknown action' });
    }
    res.status(200).json({ ok:true, data });
  } catch (e) {
    console.error('[auth]', action, e.message);
    res.status(e.status||500).json({ ok:false, error: e.message });
  }
};

// ── TELEGRAM AUTH ─────────────────────────────────────────
async function telegramAuth({ initData }) {
  if (!initData || initData.length < 10) throw se('no_init_data', 400);

  // BOT_TOKEN жоқ болса dev режим
  let tgUser;
  if (!BOT_TOKEN) {
    try { tgUser = JSON.parse(new URLSearchParams(initData).get('user') || '{}'); }
    catch { throw se('parse_error', 400); }
  } else {
    tgUser = verifyTelegramData(initData);
    if (!tgUser) throw se('invalid_telegram_data', 401);
  }

  if (!tgUser?.id) throw se('no_user_id', 400);

  const uid     = `tg:${tgUser.id}`;
  // ── #2 FIX: тек нақты ADMIN_ID ──
  // String(tgUser.id) ADMIN_ID-мен дәл сәйкес келуі керек
  const isAdmin = !!(ADMIN_ID && String(tgUser.id) === ADMIN_ID);

  console.log(`[telegramAuth] uid=${uid} ADMIN_ID=${ADMIN_ID} isAdmin=${isAdmin}`);

  // Бар user-ді тексеру
  const { data: existing } = await supabase
    .from('users').select('*').eq('id', uid).single();

  if (existing) {
    // Жаңарту — is_admin нақты қайта есептеу
    await supabase.from('users').update({
      avatar_url: tgUser.photo_url || existing.avatar_url || null,
      first_name: tgUser.first_name || existing.first_name,
      // is_admin DB-ге жазбаймыз — тек ADMIN_ID арқылы runtime анықталады
    }).eq('id', uid);

    const { data: updated } = await supabase
      .from('users').select('*').eq('id', uid).single();
    return { user: safe(updated), token: makeToken(uid) };
  }

  // Жаңа user — #8 FIX: username коллизиясын шешу
  let base = (tgUser.username || tgUser.first_name || 'user')
    .replace(/\s+/g, '_')
    .replace(/[^a-zA-Z0-9_\u0400-\u04FF]/g, '')
    .slice(0, 20);
  if (!base) base = 'user';

  // Бар-жоғын тексеру
  const { data: taken } = await supabase
    .from('users').select('id').eq('username', base).single();
  // Алынған болса — TG id-нің соңғы 5 цифрын қос
  const username = taken ? `${base}_${String(tgUser.id).slice(-5)}` : base;

  const { data: newUser, error } = await supabase.from('users').insert({
    id:         uid,
    source:     'telegram',
    username,
    first_name: tgUser.first_name || username,
    avatar_url: tgUser.photo_url || null,
    is_admin:   isAdmin,
  }).select().single();

  if (error) throw se('db_error: ' + error.message, 500);
  return { user: safe(newUser), token: makeToken(uid) };
}

// ── REGISTER ──────────────────────────────────────────────
async function register({ username, handle, password, password2, bio, birthdate, avatar_emoji, avatar_url }) {
  if (!username?.trim()) throw se('username_required', 400);
  if (!password || password.length < 6) throw se('password_too_short', 400);
  if (password !== password2) throw se('passwords_mismatch', 400);

  const uname = username.trim();
  const { data: ex } = await supabase.from('users').select('id').eq('username', uname).single();
  if (ex) throw se('username_taken', 400);

  if (handle) {
    const h = handle.replace(/^@/, '').trim();
    if (h) {
      const { data: hex } = await supabase.from('users').select('id').eq('handle', h).single();
      if (hex) throw se('handle_taken', 400);
    }
  }

  const uid = 'web:' + crypto.randomBytes(8).toString('hex');
  const { data: newUser, error } = await supabase.from('users').insert({
    id: uid, source: 'web', username: uname,
    handle: handle ? handle.replace(/^@/, '').trim() || null : null,
    first_name: uname,
    bio: bio?.trim() || null,
    birthdate: birthdate || null,
    avatar_emoji: avatar_emoji || null,
    avatar_url: avatar_url || null,
    password_hash: hashPwd(password),
    is_admin: false,
  }).select().single();

  if (error) throw se('db_error: ' + error.message, 500);
  return { user: safe(newUser), token: makeToken(uid) };
}

// ── LOGIN ─────────────────────────────────────────────────
async function login({ username, password }) {
  if (!username || !password) throw se('fields_required', 400);
  const { data: user } = await supabase
    .from('users').select('*')
    .eq('username', username.trim())
    .eq('source', 'web')
    .single();
  if (!user) throw se('user_not_found', 404);
  if (user.password_hash !== hashPwd(password)) throw se('wrong_password', 401);
  return { user: safe(user), token: makeToken(user.id) };
}

// ── VERIFY SESSION ────────────────────────────────────────
async function verifySession({ token }) {
  const decoded = verifyToken(token);
  if (!decoded) throw se('invalid_session', 401);

  const { data: user } = await supabase
    .from('users').select('*').eq('id', decoded.uid).single();
  if (!user) throw se('user_not_found', 404);

  // SECURITY: is_admin тек ADMIN_ID env var арқылы анықталады
  // DB-дағы is_admin флагына СЕНБЕЙМІЗ
  const adminId = (ADMIN_ID || '').trim();
  const isAdmin = !!(adminId && decoded.uid === `tg:${adminId}`);
  user.is_admin = isAdmin; // DB-ға жазбаймыз — тек runtime-да орнатамыз
  console.log(`[verifySession] uid=${decoded.uid} isAdmin=${isAdmin} ADMIN_ID=${adminId}`);
  return { user: safe(user) };
}

// ── FORGOT / RESET PASSWORD ───────────────────────────────
async function forgotPassword({ username }) {
  const { data: user } = await supabase
    .from('users').select('id').eq('username', (username||'').trim()).eq('source','web').single();
  if (!user) return { sent: true };

  const token   = crypto.randomBytes(24).toString('hex');
  const expires = new Date(Date.now() + 3_600_000).toISOString();
  await supabase.from('users').update({ reset_token: token, reset_expires: expires }).eq('id', user.id);
  return { sent: true, _dev_token: token };
}

async function resetPassword({ token, password, password2 }) {
  if (!token || !password) throw se('fields_required', 400);
  if (password !== password2) throw se('passwords_mismatch', 400);
  if (password.length < 6) throw se('password_too_short', 400);

  const { data: user } = await supabase
    .from('users').select('id')
    .eq('reset_token', token)
    .gte('reset_expires', new Date().toISOString())
    .single();
  if (!user) throw se('invalid_or_expired_token', 400);

  await supabase.from('users').update({
    password_hash: hashPwd(password), reset_token: null, reset_expires: null
  }).eq('id', user.id);
  return { ok: true };
}

module.exports = handler;
module.exports.verifyToken = verifyToken;

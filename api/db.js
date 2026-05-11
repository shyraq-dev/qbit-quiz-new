// api/db.js — CommonJS, @supabase/supabase-js
const { supabase, cors, ok, err } = require('../lib/supabase.js');
const { verifySessionToken }      = require('../lib/session.js');

const ADMIN_ID = (process.env.ADMIN_ID || process.env.ADMIN_TG_ID || '').trim();

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return err(res, 'POST only', 405);

  const { action, payload = {} } = req.body || {};
  const token   = (req.headers.authorization || '').replace('Bearer ', '');
  const session = verifySessionToken(token);

  const ACTIONS = {
    get_profile:            () => getProfile(payload),
    update_profile:         () => auth(session, () => updateProfile(session, payload)),
    delete_account:         () => auth(session, () => deleteAccount(session)),
    get_tests:              () => getTests(payload),
    get_test:               () => getTest(payload),
    save_record:            () => auth(session, () => saveRecord(session, payload)),
    get_leaderboard:        () => getLeaderboard(payload),
    create_session:         () => auth(session, () => createGameSession(session, payload)),
    join_session:           () => auth(session, () => joinSession(session, payload)),
    update_session:         () => admin(session, () => updateSession(payload)),
    submit_answer:          () => auth(session, () => submitAnswer(session, payload)),
    get_session:            () => getSession(payload),
    get_session_board:      () => getSessionBoard(payload),
    get_session_answers: (s) => getSessionAnswers(payload),
    admin_stats:            () => admin(session, () => adminStats()),
    admin_tests:            () => admin(session, () => adminTests()),
    admin_create_test:      () => admin(session, () => adminCreateTest(payload)),
    admin_update_test:      () => admin(session, () => adminUpdateTest(payload)),
    admin_delete_test:      () => admin(session, () => adminDeleteTest(payload)),
    admin_users:            () => admin(session, () => adminUsers()),
    admin_recent:           () => admin(session, () => adminRecent()),
    get_builtin_questions:  () => getBuiltinQuestions(payload),
    add_builtin_question:   () => admin(session, () => addBuiltinQ(payload)),
    delete_builtin_question:() => admin(session, () => delBuiltinQ(payload)),
  };

  const fn = ACTIONS[action];
  if (!fn) return err(res, 'Unknown action: ' + action);

  try {
    return ok(res, await fn());
  } catch (e) {
    console.error('[db]', action, e.message);
    return res.status(e.status || 500).json({ ok: false, error: e.message });
  }
};

// ── Guards ────────────────────────────────────────────────
async function auth(session, fn) {
  if (!session) throw Object.assign(new Error('unauthorized'), { status: 401 });
  return fn();
}
async function admin(session, fn) {
  if (!session) throw Object.assign(new Error('unauthorized'), { status: 401 });
  const uid = session.uid;

  // ── SECURITY: Тек нақты ADMIN_ID env var арқылы тексеру ──
  // initData server-та verifyTelegramData-мен тексерілген
  if (ADMIN_ID && uid === `tg:${ADMIN_ID}`) {
    return fn(); // ✓ Нақты ADMIN
  }

  // DB is_admin flag — тек ADMIN_ID жазбасында true болуы мүмкін
  if (uid.startsWith('tg:')) {
    const tgNum = uid.replace('tg:', '');
    if (ADMIN_ID && tgNum !== String(ADMIN_ID)) {
      // Бұл user ADMIN_ID емес — is_admin=true болса да тазалаймыз
      try {
        await supabase.from('users')
          .update({ is_admin: false })
          .eq('id', uid)
          .neq('id', `tg:${ADMIN_ID}`); // тек өзгелерді тазала
      } catch (_) {}
      throw Object.assign(new Error('forbidden'), { status: 403 });
    }
  }

  // Web user — ешқашан admin болмайды
  throw Object.assign(new Error('forbidden'), { status: 403 });
}

// ── PROFILE ───────────────────────────────────────────────
async function getProfile({ user_id }) {
  if (!user_id) throw new Error('user_id required');
  const { data: user } = await supabase.from('users').select('*').eq('id', user_id).single();
  if (!user) throw Object.assign(new Error('not_found'), { status: 404 });
  const { password_hash, reset_token, reset_expires, ...safe } = user;
  const { data: records } = await supabase.from('play_records')
    .select('*').eq('user_id', user_id).order('played_at', { ascending: false }).limit(20);
  return { user: safe, records: records || [] };
}

async function updateProfile(session, { username, handle, first_name, bio, birthdate, avatar_url, avatar_emoji, wallpaper_url, password, password_new, password_new2 }) {
  const update = {};
  if (username  !== undefined) update.username      = username || null;
  if (handle    !== undefined) update.handle        = handle ? handle.replace(/^@/, '').trim() || null : null;
  if (first_name!== undefined) update.first_name    = first_name || null;
  if (bio       !== undefined) update.bio           = bio || null;
  if (birthdate !== undefined) update.birthdate     = birthdate || null;
  if (avatar_url!== undefined) update.avatar_url    = avatar_url || null;
  if (avatar_emoji!==undefined)update.avatar_emoji  = avatar_emoji || null;
  if (wallpaper_url!==undefined)update.wallpaper_url= wallpaper_url || null;

  if (password_new) {
    const crypto = require('crypto');
    const hash = (p) => crypto.createHmac('sha256', process.env.PWD_SECRET || 'qbit_secret_change_me').update(p).digest('hex');
    const { data: u } = await supabase.from('users').select('password_hash').eq('id', session.uid).single();
    if (!u || u.password_hash !== hash(password)) throw Object.assign(new Error('wrong_password'), { status: 401 });
    if (password_new !== password_new2) throw Object.assign(new Error('passwords_mismatch'), { status: 400 });
    if (password_new.length < 6) throw Object.assign(new Error('password_too_short'), { status: 400 });
    update.password_hash = hash(password_new);
  }

  if (!Object.keys(update).length) return {};
  const { data, error } = await supabase.from('users').update(update).eq('id', session.uid).select().single();
  if (error) throw new Error(error.message);
  const { password_hash, reset_token, reset_expires, ...safe } = data;
  return safe;
}

async function deleteAccount(session) {
  await supabase.from('users').delete().eq('id', session.uid);
  return { deleted: true };
}

// ── TESTS ─────────────────────────────────────────────────
async function getTests({ mode }) {
  let q = supabase.from('tests').select('*').eq('is_public', true).order('created_at', { ascending: false });
  if (mode) q = q.eq('mode', mode);
  const { data } = await q;
  return data || [];
}

async function getTest({ test_id }) {
  if (!test_id) throw new Error('test_id required');
  const { data: test } = await supabase.from('tests').select('*').eq('id', test_id).single();
  if (!test) throw Object.assign(new Error('not_found'), { status: 404 });
  const { data: questions } = await supabase.from('questions')
    .select('*').eq('test_id', test_id).order('position');
  return { test, questions: questions || [] };
}

async function saveRecord(session, { test_id, mode, score, pct, best_streak, avg_time_ms, answers }) {
  await supabase.from('play_records').insert({
    user_id: session.uid, test_id, mode, score, pct,
    best_streak: best_streak || 0, avg_time_ms: avg_time_ms || 0, answers: answers || null,
  });
  // Stats жаңарту
  const { data: u } = await supabase.from('users').select('total_games,best_score,total_score,best_streak').eq('id', session.uid).single();
  if (u) {
    await supabase.from('users').update({
      total_games: (u.total_games || 0) + 1,
      best_score:  Math.max(u.best_score || 0, score),
      total_score: (u.total_score || 0) + score,
      best_streak: Math.max(u.best_streak || 0, best_streak || 0),
    }).eq('id', session.uid);
  }
  return { saved: true };
}

// ── LEADERBOARD ───────────────────────────────────────────
async function getLeaderboard({ period = 'all', limit = 50 }) {
  if (period === 'all') {
    const { data } = await supabase.from('users')
      .select('id,first_name,username,avatar_url,avatar_emoji,best_score,total_games')
      .order('best_score', { ascending: false }).limit(limit);
    return (data || []).map(u => ({
      id: u.id, name: u.first_name || u.username, username: u.username,
      avatar: u.avatar_url, avatar_emoji: u.avatar_emoji,
      score: u.best_score, games: u.total_games,
    }));
  }
  const from = period === 'today'
    ? new Date(new Date().setHours(0,0,0,0)).toISOString()
    : new Date(Date.now() - 7*864e5).toISOString();

  const { data: recs } = await supabase.from('play_records')
    .select('user_id,score').gte('played_at', from).order('score', { ascending: false }).limit(500);

  const map = {};
  for (const r of (recs || [])) {
    if (!map[r.user_id] || r.score > map[r.user_id]) map[r.user_id] = r.score;
  }
  const uids = Object.keys(map);
  if (!uids.length) return [];

  const { data: users } = await supabase.from('users')
    .select('id,first_name,username,avatar_url,avatar_emoji,total_games').in('id', uids);
  const umap = Object.fromEntries((users || []).map(u => [u.id, u]));

  return uids.map(id => ({
    id, score: map[id],
    name: umap[id]?.first_name || umap[id]?.username || id,
    username: umap[id]?.username, avatar: umap[id]?.avatar_url,
    avatar_emoji: umap[id]?.avatar_emoji, games: umap[id]?.total_games || 0,
  })).sort((a,b) => b.score - a.score).slice(0, limit);
}

// ── GAME SESSIONS ─────────────────────────────────────────
function genCode() {
  return Math.random().toString(36).slice(2,8).toUpperCase();
}

async function createGameSession(session, { test_id }) {
  let code = genCode();
  // Уникальность
  const { data: ex } = await supabase.from('game_sessions').select('id').eq('code', code).neq('status','finished').single();
  if (ex) code = genCode() + Math.floor(Math.random()*9);

  const { data, error } = await supabase.from('game_sessions')
    .insert({ test_id, host_id: session.uid, code, status: 'lobby' })
    .select().single();
  if (error) throw new Error(error.message);
  return data;
}

async function joinSession(session, { code, nickname }) {
  const { data: sess } = await supabase.from('game_sessions')
    .select('*').eq('code', code.toUpperCase()).single();
  if (!sess) throw Object.assign(new Error('session_not_found'), { status: 404 });
  if (sess.status === 'finished') throw Object.assign(new Error('session_finished'), { status: 400 });

  const { data: player, error } = await supabase.from('game_players')
    .insert({ session_id: sess.id, user_id: session.uid, nickname: nickname || 'Player' })
    .select().single();
  if (error) throw new Error(error.message);
  return { session: sess, player };
}

async function updateSession({ session_id, status, current_q }) {
  const update = {};
  if (status)            update.status      = status;
  if (current_q != null) update.current_q   = current_q;
  if (status === 'active')   update.started_at  = new Date().toISOString();
  if (status === 'finished') update.finished_at = new Date().toISOString();
  const { data } = await supabase.from('game_sessions').update(update).eq('id', session_id).select().single();
  return data;
}

async function submitAnswer(session, { session_id, player_id, question_id, answer, time_taken }) {
  const { data: q } = await supabase.from('questions').select('*').eq('id', question_id).single();
  if (!q) throw new Error('question_not_found');
  const is_correct = answer === q.correct;
  const points = is_correct ? Math.max(100, Math.round(1000 * (1 - (time_taken||3000) / ((q.time_limit||20)*1000)))) : 0;
  await supabase.from('game_answers').insert({ session_id, player_id, question_id, answer, is_correct, time_taken: time_taken||0, points });
  // Player stats жаңарту — score + correct/wrong count
  const { data: p } = await supabase.from('game_players').select('score,correct_count,wrong_count').eq('id', player_id).single();
  if (p) {
    await supabase.from('game_players').update({
      score:         (p.score||0) + points,
      correct_count: (p.correct_count||0) + (is_correct ? 1 : 0),
      wrong_count:   (p.wrong_count||0)   + (is_correct ? 0 : 1),
    }).eq('id', player_id);
  }
  return { is_correct, points };
}


async function getSessionAnswers({ session_id, question_id }) {
  if (!session_id) throw new Error('session_id required');
  let q = supabase.from('game_answers').select('*').eq('session_id', session_id);
  if (question_id) q = q.eq('question_id', question_id);
  const { data, error } = await q;
  if (error) throw new Error(error.message);
  return data || [];
}

async function getSession({ code, session_id }) {
  const { data: sess } = code
    ? await supabase.from('game_sessions').select('*').eq('code', code.toUpperCase()).single()
    : await supabase.from('game_sessions').select('*').eq('id', session_id).single();
  if (!sess) throw Object.assign(new Error('not_found'), { status: 404 });

  const [{ data: players }, { data: answers }, testData] = await Promise.all([
    supabase.from('game_players').select('*').eq('session_id', sess.id).order('score', { ascending: false }),
    supabase.from('game_answers').select('*').eq('session_id', sess.id),
    getTest({ test_id: sess.test_id }),
  ]);

  const { test, questions } = testData;
  const allAnswers  = answers  || [];
  const allPlayers  = players  || [];

  // Ағымдағы сұрақ бойынша жауаптар санақтары (4 нұсқа)
  const curQ  = questions?.[sess.current_q || 0];
  const forQ  = curQ ? allAnswers.filter(a => a.question_id === curQ.id) : [];
  const counts = [0, 0, 0, 0];
  forQ.forEach(a => { if (a.answer >= 0 && a.answer <= 3) counts[a.answer]++; });

  // Әр ойыншының соңғы жауабы
  const enrichedPlayers = allPlayers.map(p => {
    const pAns = allAnswers.filter(a => a.player_id === p.id);
    const last  = curQ ? pAns.find(a => a.question_id === curQ.id) : null;
    return {
      ...p,
      correct_count:     pAns.filter(a => a.is_correct).length,
      wrong_answers_count: pAns.filter(a => !a.is_correct).length,
      last_correct:      last ? last.is_correct : null,
    };
  });

  return {
    session:       sess,
    players:       enrichedPlayers,
    test,
    questions,
    answer_counts: counts,
    answered_count: forQ.length,
  };
}

async function getSessionBoard({ session_id }) {
  const { data } = await supabase.from('game_players').select('*').eq('session_id', session_id).order('score', { ascending: false });
  return data || [];
}

async function getSessionAnswers({ session_id, question_id }) {
  if (!session_id) throw new Error('session_id required');
  let q = supabase.from('game_answers').select('*').eq('session_id', session_id);
  if (question_id) q = q.eq('question_id', question_id);
  const { data, error } = await q;
  if (error) throw new Error(error.message);
  return data || [];
}

// ── ADMIN ─────────────────────────────────────────────────
async function adminStats() {
  const [u, g, s] = await Promise.all([
    supabase.from('users').select('id', { count: 'exact', head: true }),
    supabase.from('play_records').select('id', { count: 'exact', head: true }),
    supabase.from('game_sessions').select('id', { count: 'exact', head: true }),
  ]);
  const week = new Date(Date.now() - 7*864e5).toISOString();
  const { count: active } = await supabase.from('users').select('id', { count: 'exact', head: true }).gte('updated_at', week);
  return { total_users: u.count||0, total_games: g.count||0, total_sessions: s.count||0, active_week: active||0 };
}

async function adminTests() {
  const { data } = await supabase.from('tests').select('*').order('created_at', { ascending: false });
  return data || [];
}

async function adminCreateTest({ title, description, category, mode, cover_emoji, questions: qs }) {
  const { data: test, error } = await supabase.from('tests')
    .insert({ title, description, category, mode: mode||'quiz', cover_emoji: cover_emoji||'📝', is_public: true })
    .select().single();
  if (error) throw new Error(error.message);
  if (qs?.length) {
    await supabase.from('questions').insert(qs.map((q,i) => ({ test_id: test.id, position: i, ...q })));
  }
  return test;
}

async function adminUpdateTest({ test_id, questions: qs, ...fields }) {
  if (Object.keys(fields).length) {
    await supabase.from('tests').update(fields).eq('id', test_id);
  }
  if (qs) {
    await supabase.from('questions').delete().eq('test_id', test_id);
    if (qs.length) await supabase.from('questions').insert(qs.map((q,i) => ({ test_id, position: i, ...q })));
  }
  return { updated: true };
}

async function adminDeleteTest({ test_id }) {
  await supabase.from('tests').delete().eq('id', test_id);
  return { deleted: true };
}

async function adminUsers() {
  const { data } = await supabase.from('users')
    .select('id,source,username,handle,first_name,is_admin,total_games,best_score,created_at')
    .order('created_at', { ascending: false });
  return data || [];
}

async function adminRecent() {
  const { data: records } = await supabase.from('play_records')
    .select('*').order('played_at', { ascending: false }).limit(30);
  if (!records?.length) return [];
  const uids = [...new Set(records.map(r => r.user_id))];
  const tids = [...new Set(records.map(r => r.test_id).filter(Boolean))];
  const [{ data: users }, { data: tests }] = await Promise.all([
    supabase.from('users').select('id,username,first_name').in('id', uids),
    tids.length ? supabase.from('tests').select('id,title').in('id', tids) : { data: [] },
  ]);
  const umap = Object.fromEntries((users||[]).map(u => [u.id, u]));
  const tmap = Object.fromEntries((tests||[]).map(t => [t.id, t]));
  return records.map(r => ({ ...r, user: umap[r.user_id]||null, test: tmap[r.test_id]||null }));
}

// ── BUILTIN GAMES ─────────────────────────────────────────
async function getBuiltinQuestions({ slug }) {
  const { data } = await supabase.from('builtin_questions').select('*').eq('slug', slug).order('created_at');
  return data || [];
}
async function playBuiltin({ slug, count = 10 }) {
  if (!slug) throw new Error('slug required');
  const { data: all } = await supabase.from('builtin_questions').select('*').eq('slug', slug);
  if (!all || all.length < 4) throw new Error('not_enough_questions');
  // Кездейсоқ сұрақтарды алу
  const shuffled = all.sort(() => Math.random() - 0.5).slice(0, Math.min(count, all.length));
  // Әр сұрақ үшін 4 жауап жасау (1 дұрыс + 3 жалған)
  const result = shuffled.map(q => {
    let wrong = (q.wrong_answers || []);
    // wrong_answers жеткіліксіз болса — басқа сұрақтардан алу
    if (wrong.length < 3) {
      const others = all.filter(o => o.id !== q.id).sort(() => Math.random() - 0.5);
      wrong = [...wrong, ...others.map(o => o.answer)].slice(0, 3);
    }
    wrong = wrong.slice(0, 3);
    // 4 жауапты аралас орналастыру
    const options = [q.answer, ...wrong].sort(() => Math.random() - 0.5);
    const correct = options.indexOf(q.answer);
    return {
      id: q.id,
      question: q.question,
      answer: q.answer,
      flag: q.flag || null,
      images: q.images || null,
      letter_count: q.letter_count || q.answer.length,
      options,
      correct,
    };
  });
  return result;
}

async function addBuiltinQ({ slug, question, answer, flag, images, wrong_answers, letter_count }) {
  if (!slug || !answer) throw Object.assign(new Error('answer required'), { status: 400 });
  const row = {
    slug,
    question:      question      || answer,
    answer,
    flag:          flag          || null,
    images:        images        || null,
    wrong_answers: wrong_answers || null,
    letter_count:  letter_count  || null,
  };
  const { data, error } = await supabase.from('builtin_questions')
    .insert(row).select().single();
  if (error) throw new Error(error.message);
  return data;
}
async function delBuiltinQ({ id }) {
  await supabase.from('builtin_questions').delete().eq('id', id);
  return { deleted: true };
}

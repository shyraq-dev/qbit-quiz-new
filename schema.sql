-- ══════════════════════════════════════════════════════════
-- QBit Quiz — Supabase SQL Schema (толық нұсқа)
-- Supabase Dashboard → SQL Editor → Run
-- ══════════════════════════════════════════════════════════

-- ── EXTENSIONS ───────────────────────────────────────────
create extension if not exists "pgcrypto";

-- ── 1. USERS ─────────────────────────────────────────────
create table if not exists users (
  id            text primary key,          -- tg:12345 немесе web:uuid
  source        text not null default 'web', -- 'telegram' | 'web'
  username      text not null,
  handle        text unique,               -- @лақап (nullable)
  first_name    text,
  bio           text,
  birthdate     date,
  avatar_url    text,                      -- URL немесе emoji
  avatar_emoji  text,                      -- emoji-кейіпкер
  wallpaper_url text,
  password_hash text,                      -- тек web қолданушылар
  reset_token   text,
  reset_expires timestamptz,
  is_admin      boolean not null default false,
  total_games   integer not null default 0,
  best_score    integer not null default 0,
  total_score   bigint  not null default 0,
  best_streak   integer not null default 0,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- ── 2. TESTS & QUIZZES ───────────────────────────────────
create table if not exists tests (
  id          uuid primary key default gen_random_uuid(),
  creator_id  text references users(id) on delete set null,
  title       text not null,
  description text,
  category    text,
  mode        text not null default 'quiz', -- 'quiz' | 'test'
  is_public   boolean not null default true,
  cover_emoji text default '📝',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists questions (
  id          uuid primary key default gen_random_uuid(),
  test_id     uuid not null references tests(id) on delete cascade,
  position    integer not null default 0,
  text        text not null,
  options     jsonb not null,              -- ["A","B","C","D"]
  correct     integer not null,           -- 0-3 индекс
  explanation text,
  time_limit  integer not null default 20, -- секунд
  created_at  timestamptz not null default now()
);

-- ── 3. GAMES (ойындар — жарыс форматы) ──────────────────
create table if not exists game_sessions (
  id           uuid primary key default gen_random_uuid(),
  test_id      uuid references tests(id) on delete cascade,
  host_id      text references users(id) on delete cascade,
  code         text unique not null,       -- ABC123
  status       text not null default 'lobby', -- lobby|active|finished
  current_q    integer not null default 0,
  started_at   timestamptz,
  finished_at  timestamptz,
  created_at   timestamptz not null default now()
);

create table if not exists game_players (
  id         uuid primary key default gen_random_uuid(),
  session_id uuid not null references game_sessions(id) on delete cascade,
  user_id    text references users(id) on delete set null,
  nickname   text not null,
  score      integer not null default 0,
  joined_at  timestamptz not null default now()
);

create table if not exists game_answers (
  id          uuid primary key default gen_random_uuid(),
  session_id  uuid not null references game_sessions(id) on delete cascade,
  player_id   uuid not null references game_players(id) on delete cascade,
  question_id uuid not null references questions(id) on delete cascade,
  answer      integer,                     -- null = timeout
  is_correct  boolean not null default false,
  time_taken  integer not null default 0,  -- ms
  points      integer not null default 0,
  answered_at timestamptz not null default now()
);

-- ── 4. PLAY RECORDS (куиз/тест нәтижелері) ───────────────
create table if not exists play_records (
  id          uuid primary key default gen_random_uuid(),
  user_id     text references users(id) on delete cascade,
  test_id     uuid references tests(id) on delete cascade,
  mode        text not null default 'quiz',
  score       integer not null,
  pct         integer not null,
  best_streak integer not null default 0,
  avg_time_ms integer not null default 0,
  answers     jsonb,                       -- детальды жауаптар
  played_at   timestamptz not null default now()
);

-- ── 5. BUILT-IN GAMES (елдер, туулар, т.б.) ──────────────
create table if not exists builtin_games (
  id          uuid primary key default gen_random_uuid(),
  slug        text unique not null,        -- 'capitals'|'flags'|'4pics'
  title       text not null,
  description text,
  icon        text,
  is_active   boolean not null default true
);

-- Үлгі деректер
insert into builtin_games (slug, title, description, icon) values
  ('capitals', 'Астаналар', 'Елдердің астаналарын тап', '🗺️'),
  ('flags',    'Туулар',    'Елдің туын тап',           '🏳️'),
  ('4pics',    '4 сурет, 1 сөз', 'Суреттерден сөзді тап', '🖼️')
on conflict (slug) do nothing;

-- ── 6. INDEXES ───────────────────────────────────────────
create index if not exists idx_users_best_score   on users(best_score desc);
create index if not exists idx_users_handle       on users(handle);
create index if not exists idx_questions_test     on questions(test_id, position);
create index if not exists idx_play_records_user  on play_records(user_id, played_at desc);
create index if not exists idx_play_records_test  on play_records(test_id, played_at desc);
create index if not exists idx_game_sessions_code on game_sessions(code);
create index if not exists idx_game_players_sess  on game_players(session_id);
create index if not exists idx_game_answers_sess  on game_answers(session_id, player_id);

-- ── 7. TRIGGERS ──────────────────────────────────────────
create or replace function set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;

create trigger trg_users_upd before update on users
  for each row execute function set_updated_at();
create trigger trg_tests_upd before update on tests
  for each row execute function set_updated_at();

-- ── 8. RPC FUNCTIONS ─────────────────────────────────────

-- Ойын нәтижесін сақтау (atomic)
create or replace function update_user_stats(
  p_user_id text, p_score integer, p_streak integer
) returns void language plpgsql security definer as $$
begin
  update users set
    total_games = total_games + 1,
    best_score  = greatest(best_score, p_score),
    total_score = total_score + p_score,
    best_streak = greatest(best_streak, p_streak)
  where id = p_user_id;
end;
$$;

-- Ойын коды генерациясы
create or replace function generate_game_code()
returns text language plpgsql as $$
declare code text;
begin
  loop
    code := upper(substring(md5(random()::text) from 1 for 6));
    exit when not exists (select 1 from game_sessions where game_sessions.code = code and status != 'finished');
  end loop;
  return code;
end;
$$;

-- ── 9. RLS ───────────────────────────────────────────────
alter table users          enable row level security;
alter table tests          enable row level security;
alter table questions      enable row level security;
alter table game_sessions  enable row level security;
alter table game_players   enable row level security;
alter table game_answers   enable row level security;
alter table play_records   enable row level security;
alter table builtin_games  enable row level security;

-- Барлығы оқи алады
create policy "public read" on users         for select using (true);
create policy "public read" on tests         for select using (true);
create policy "public read" on questions     for select using (true);
create policy "public read" on game_sessions for select using (true);
create policy "public read" on game_players  for select using (true);
create policy "public read" on game_answers  for select using (true);
create policy "public read" on play_records  for select using (true);
create policy "public read" on builtin_games for select using (true);

-- Тек service_role жаза алады (server API арқылы)
create policy "service write" on users         for all using (auth.role()='service_role') with check (auth.role()='service_role');
create policy "service write" on tests         for all using (auth.role()='service_role') with check (auth.role()='service_role');
create policy "service write" on questions     for all using (auth.role()='service_role') with check (auth.role()='service_role');
create policy "service write" on game_sessions for all using (auth.role()='service_role') with check (auth.role()='service_role');
create policy "service write" on game_players  for all using (auth.role()='service_role') with check (auth.role()='service_role');
create policy "service write" on game_answers  for all using (auth.role()='service_role') with check (auth.role()='service_role');
create policy "service write" on play_records  for all using (auth.role()='service_role') with check (auth.role()='service_role');
create policy "service write" on builtin_games for all using (auth.role()='service_role') with check (auth.role()='service_role');

-- ── 10. REALTIME (ойын үшін) ─────────────────────────────
-- Supabase Dashboard → Database → Replication → enable for:
-- game_sessions, game_players, game_answers

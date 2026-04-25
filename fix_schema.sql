-- ══════════════════════════════════════════════════════════
-- QBit Quiz — PATCH SQL
-- Supabase Dashboard → SQL Editor → Run
-- (schema.sql толық орындалмаған жағдайда осыны іске қосыңыз)
-- ══════════════════════════════════════════════════════════

-- 1. Жетіспейтін columns қосу (қате болса ALTER IGNORE жасайды)
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin      boolean      NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS source        text         NOT NULL DEFAULT 'web';
ALTER TABLE users ADD COLUMN IF NOT EXISTS handle        text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio           text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS birthdate     date;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_emoji  text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS wallpaper_url text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token   text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS total_score   bigint       NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS best_streak   integer      NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at    timestamptz  NOT NULL DEFAULT now();

-- 2. handle unique index (бар болса өткіз)
CREATE UNIQUE INDEX IF NOT EXISTS users_handle_unique ON users(handle) WHERE handle IS NOT NULL;

-- 3. updated_at trigger
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN new.updated_at = now(); RETURN new; END;
$$;

DROP TRIGGER IF EXISTS trg_users_upd ON users;
CREATE TRIGGER trg_users_upd
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 4. Басқа кестелер бар ма — тексеру, жоқ болса жасау
CREATE TABLE IF NOT EXISTS tests (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id  text        REFERENCES users(id) ON DELETE SET NULL,
  title       text        NOT NULL,
  description text,
  category    text,
  mode        text        NOT NULL DEFAULT 'quiz',
  is_public   boolean     NOT NULL DEFAULT true,
  cover_emoji text        DEFAULT '📝',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS questions (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  test_id     uuid        NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
  position    integer     NOT NULL DEFAULT 0,
  text        text        NOT NULL,
  options     jsonb       NOT NULL,
  correct     integer     NOT NULL,
  explanation text,
  time_limit  integer     NOT NULL DEFAULT 20,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS game_sessions (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  test_id     uuid        REFERENCES tests(id) ON DELETE CASCADE,
  host_id     text        REFERENCES users(id) ON DELETE CASCADE,
  code        text        UNIQUE NOT NULL,
  status      text        NOT NULL DEFAULT 'lobby',
  current_q   integer     NOT NULL DEFAULT 0,
  started_at  timestamptz,
  finished_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS game_players (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid        NOT NULL REFERENCES game_sessions(id) ON DELETE CASCADE,
  user_id    text        REFERENCES users(id) ON DELETE SET NULL,
  nickname   text        NOT NULL,
  score      integer     NOT NULL DEFAULT 0,
  joined_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS game_answers (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id  uuid        NOT NULL REFERENCES game_sessions(id) ON DELETE CASCADE,
  player_id   uuid        NOT NULL REFERENCES game_players(id) ON DELETE CASCADE,
  question_id uuid        NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  answer      integer,
  is_correct  boolean     NOT NULL DEFAULT false,
  time_taken  integer     NOT NULL DEFAULT 0,
  points      integer     NOT NULL DEFAULT 0,
  answered_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS play_records (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     text        REFERENCES users(id) ON DELETE CASCADE,
  test_id     uuid        REFERENCES tests(id) ON DELETE CASCADE,
  mode        text        NOT NULL DEFAULT 'quiz',
  score       integer     NOT NULL,
  pct         integer     NOT NULL,
  best_streak integer     NOT NULL DEFAULT 0,
  avg_time_ms integer     NOT NULL DEFAULT 0,
  answers     jsonb,
  played_at   timestamptz NOT NULL DEFAULT now()
);

-- 5. Indexes
CREATE INDEX IF NOT EXISTS idx_users_best_score  ON users(best_score DESC);
CREATE INDEX IF NOT EXISTS idx_questions_test    ON questions(test_id, position);
CREATE INDEX IF NOT EXISTS idx_play_user         ON play_records(user_id, played_at DESC);
CREATE INDEX IF NOT EXISTS idx_play_test         ON play_records(test_id, played_at DESC);
CREATE INDEX IF NOT EXISTS idx_game_code         ON game_sessions(code);
CREATE INDEX IF NOT EXISTS idx_game_players_sess ON game_players(session_id);

-- 6. RPC: update_user_stats
CREATE OR REPLACE FUNCTION update_user_stats(
  p_user_id text, p_score integer, p_streak integer
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE users SET
    total_games = total_games + 1,
    best_score  = GREATEST(best_score, p_score),
    total_score = total_score + p_score,
    best_streak = GREATEST(best_streak, p_streak)
  WHERE id = p_user_id;
END;
$$;

-- 7. RPC: generate_game_code
CREATE OR REPLACE FUNCTION generate_game_code()
RETURNS text LANGUAGE plpgsql AS $$
DECLARE code text;
BEGIN
  LOOP
    code := UPPER(SUBSTRING(MD5(RANDOM()::text) FROM 1 FOR 6));
    EXIT WHEN NOT EXISTS (
      SELECT 1 FROM game_sessions WHERE game_sessions.code = code AND status != 'finished'
    );
  END LOOP;
  RETURN code;
END;
$$;

-- 8. RLS — service_role барлығын жаза алады, anon тек оқиды
ALTER TABLE users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE tests         ENABLE ROW LEVEL SECURITY;
ALTER TABLE questions     ENABLE ROW LEVEL SECURITY;
ALTER TABLE game_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE game_players  ENABLE ROW LEVEL SECURITY;
ALTER TABLE game_answers  ENABLE ROW LEVEL SECURITY;
ALTER TABLE play_records  ENABLE ROW LEVEL SECURITY;

-- Оқу саясаттары (бар болса өткіз)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='users'         AND policyname='anon read users')         THEN CREATE POLICY "anon read users"         ON users         FOR SELECT USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='tests'         AND policyname='anon read tests')         THEN CREATE POLICY "anon read tests"         ON tests         FOR SELECT USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='questions'     AND policyname='anon read questions')     THEN CREATE POLICY "anon read questions"     ON questions     FOR SELECT USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='game_sessions' AND policyname='anon read game_sessions') THEN CREATE POLICY "anon read game_sessions" ON game_sessions FOR SELECT USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='game_players'  AND policyname='anon read game_players')  THEN CREATE POLICY "anon read game_players"  ON game_players  FOR SELECT USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='game_answers'  AND policyname='anon read game_answers')  THEN CREATE POLICY "anon read game_answers"  ON game_answers  FOR SELECT USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='play_records'  AND policyname='anon read play_records')  THEN CREATE POLICY "anon read play_records"  ON play_records  FOR SELECT USING (true); END IF;
END $$;

-- Жазу саясаттары — service_role
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='users'         AND policyname='service write users')         THEN CREATE POLICY "service write users"         ON users         FOR ALL USING (auth.role()='service_role') WITH CHECK (auth.role()='service_role'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='tests'         AND policyname='service write tests')         THEN CREATE POLICY "service write tests"         ON tests         FOR ALL USING (auth.role()='service_role') WITH CHECK (auth.role()='service_role'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='questions'     AND policyname='service write questions')     THEN CREATE POLICY "service write questions"     ON questions     FOR ALL USING (auth.role()='service_role') WITH CHECK (auth.role()='service_role'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='game_sessions' AND policyname='service write game_sessions') THEN CREATE POLICY "service write game_sessions" ON game_sessions FOR ALL USING (auth.role()='service_role') WITH CHECK (auth.role()='service_role'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='game_players'  AND policyname='service write game_players')  THEN CREATE POLICY "service write game_players"  ON game_players  FOR ALL USING (auth.role()='service_role') WITH CHECK (auth.role()='service_role'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='game_answers'  AND policyname='service write game_answers')  THEN CREATE POLICY "service write game_answers"  ON game_answers  FOR ALL USING (auth.role()='service_role') WITH CHECK (auth.role()='service_role'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='play_records'  AND policyname='service write play_records')  THEN CREATE POLICY "service write play_records"  ON play_records  FOR ALL USING (auth.role()='service_role') WITH CHECK (auth.role()='service_role'); END IF;
END $$;

-- 9. Schema cache жаңарту
NOTIFY pgrst, 'reload schema';

-- 10. Тексеру
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'users'
ORDER BY ordinal_position;
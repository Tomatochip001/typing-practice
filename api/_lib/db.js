// Neon Postgres への接続とテーブル作成。テーブルは初回アクセス時に自動で作られる。
const { neon } = require('@neondatabase/serverless');

let sql = null;
let ready = null;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id bigserial PRIMARY KEY,
     username text UNIQUE NOT NULL,
     salt text NOT NULL,
     hash text NOT NULL,
     created_at bigint NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS runs (
     id bigserial,
     user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     t bigint NOT NULL,
     mode text NOT NULL,
     spd integer NOT NULL,
     acc double precision NOT NULL,
     sec integer NOT NULL,
     miss integer NOT NULL,
     PRIMARY KEY (user_id, t, mode))`,
  `CREATE INDEX IF NOT EXISTS runs_user_id_idx ON runs (user_id, id)`,
  `ALTER TABLE runs ADD COLUMN IF NOT EXISTS score integer NOT NULL DEFAULT 0`, // ラッシュモードの語数(ほかのモードは0)
  `CREATE TABLE IF NOT EXISTS key_stats (
     user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     k text NOT NULL,
     n bigint NOT NULL, m bigint NOT NULL, t bigint NOT NULL, c bigint NOT NULL,
     PRIMARY KEY (user_id, k))`,
  `CREATE TABLE IF NOT EXISTS user_data (
     user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
     prefs jsonb NOT NULL,
     updated_at bigint NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS login_fails (
     username text NOT NULL,
     ip text NOT NULL,
     at bigint NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS login_fails_idx ON login_fails (username, at)`,
  // 固定窓のアクセス回数カウンタ(登録・同期のレート制限用)
  `CREATE TABLE IF NOT EXISTS rate_limits (
     bucket text NOT NULL,
     key text NOT NULL,
     win bigint NOT NULL,
     n integer NOT NULL,
     PRIMARY KEY (bucket, key, win))`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen bigint`,
  // パスワードの回復・変更、記録の上限
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_salt text`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hash text`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS session_epoch integer NOT NULL DEFAULT 0`,   // 上げると、古いログイン(cookie)が全部無効になる
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change boolean NOT NULL DEFAULT false`, // 運営が発行した仮パスワードのまま、true
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS quota_mult integer NOT NULL DEFAULT 1`,      // 記録の上限の倍率。0 = 無制限
  // 記録の上限を上げる申請
  `CREATE TABLE IF NOT EXISTS quota_requests (
     id bigserial PRIMARY KEY,
     user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     note text NOT NULL DEFAULT '',
     status text NOT NULL DEFAULT 'pending',
     runs_at_request integer NOT NULL,
     created_at bigint NOT NULL,
     decided_at bigint,
     admin_note text NOT NULL DEFAULT '',
     granted_mult integer)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS quota_pending_one ON quota_requests (user_id) WHERE status = 'pending'`,
  `CREATE INDEX IF NOT EXISTS quota_requests_status_idx ON quota_requests (status, id)`,
  // 回復コードをなくした人の、パスワード再発行の申請
  `CREATE TABLE IF NOT EXISTS reset_requests (
     id bigserial PRIMARY KEY,
     user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     note text NOT NULL DEFAULT '',
     status text NOT NULL DEFAULT 'pending',
     created_at bigint NOT NULL,
     decided_at bigint,
     admin_note text NOT NULL DEFAULT '')`,
  `CREATE UNIQUE INDEX IF NOT EXISTS reset_pending_one ON reset_requests (user_id) WHERE status = 'pending'`,
  `CREATE INDEX IF NOT EXISTS reset_requests_status_idx ON reset_requests (status, id)`
];

function getSql() {
  if (sql) return sql;
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) { const e = new Error('DATABASE_URL is not set'); e.code = 'not_configured'; throw e; }
  sql = neon(url);
  return sql;
}

async function init(q) {
  for (const stmt of SCHEMA) {
    // @neondatabase/serverless v1 では sql('文字列') は使えない。文字列の SQL は sql.query() で実行する
    try { await q.query(stmt); }
    catch (e) { await q.query(stmt); } // 同時に起動した別インスタンスとの競合は1回だけ再試行
  }
}

async function db() {
  const q = getSql();
  if (!ready) ready = init(q).catch(e => { ready = null; throw e; });
  await ready;
  return q;
}

// テスト用: tagged template 形式の関数を差し込む
function __setSql(fn) { sql = fn; ready = null; }

module.exports = { db, __setSql };

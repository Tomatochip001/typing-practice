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
  `CREATE INDEX IF NOT EXISTS login_fails_idx ON login_fails (username, at)`
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
    try { await q(stmt); }
    catch (e) { await q(stmt); } // 同時に起動した別インスタンスとの競合は1回だけ再試行
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

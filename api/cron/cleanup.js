// 1日1回の掃除(Vercel Cron)。古いカウンタ・ログイン失敗の記録と、使われていない空のアカウントを削除する。
// CRON_SECRET を設定すると、Vercel が Authorization: Bearer <CRON_SECRET> を付けて呼び出す。
const crypto = require('crypto');
const { db } = require('../_lib/db');
const { api, send } = require('../_lib/http');

const DAY = 86400000;
// rate_limits.win は「窓の番号」なので、バケットごとの窓の長さで古さを判定する
const WINDOWS = { reg_ip: 3600000, sync_user: 600000, reg_day: DAY };
const UNUSED_ACCOUNT_DAYS = 30;

function authorized(req) {
  const secret = process.env.CRON_SECRET;
  if (!secret || secret.length < 32) { const e = new Error('CRON_SECRET is missing or shorter than 32 chars'); e.code = 'not_configured'; throw e; }
  const got = Buffer.from(String(req.headers.authorization || ''));
  const want = Buffer.from(`Bearer ${secret}`);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

module.exports = api('GET', async (req, res) => {
  if (!authorized(req)) return send(res, 401, { error: 'unauthorized' });
  const sql = await db();
  const now = Date.now(), old = now - 2 * DAY;

  let counters = 0;
  for (const [bucket, ms] of Object.entries(WINDOWS)) {
    const rows = await sql`WITH d AS (DELETE FROM rate_limits WHERE bucket = ${bucket} AND win < ${Math.floor(old / ms)} RETURNING 1)
                           SELECT count(*)::int AS n FROM d`;
    counters += rows[0].n;
  }
  const [{ n: fails }] = await sql`WITH d AS (DELETE FROM login_fails WHERE at < ${old} RETURNING 1) SELECT count(*)::int AS n FROM d`;
  // 記録が1件もなく、30日以上使われていないアカウントだけを消す(記録のあるアカウントは消さない)
  const cutoff = now - UNUSED_ACCOUNT_DAYS * DAY;
  const [{ n: users }] = await sql`WITH d AS (
      DELETE FROM users u WHERE COALESCE(u.last_seen, u.created_at) < ${cutoff}
        AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.user_id = u.id) RETURNING 1)
    SELECT count(*)::int AS n FROM d`;
  const [{ n: total }] = await sql`SELECT count(*)::int AS n FROM users`;
  send(res, 200, { deleted: { rate_limits: counters, login_fails: fails, unused_users: users }, users_now: total });
});

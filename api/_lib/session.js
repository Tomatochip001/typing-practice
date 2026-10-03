// ログイン中のユーザーの確認と、記録の上限の情報。
const A = require('./auth');
const C = require('./config');

const DAY = 86400000;

// cookie を確かめて、ユーザーを返す(なければ null)。パスワードを変えた後の古いcookie(epochが違う)も null
async function currentUser(sql, req) {
  const s = A.readSession(req);
  if (!s) return null;
  const rows = await sql`SELECT id, username, salt, hash, session_epoch, must_change, quota_mult, (recovery_hash IS NOT NULL) AS has_recovery
                         FROM users WHERE id = ${s.uid}`;
  if (!rows.length || Number(rows[0].session_epoch) !== s.epoch) return null;
  const u = rows[0];
  return { id: Number(u.id), username: u.username, salt: u.salt, hash: u.hash, epoch: Number(u.session_epoch),
           mustChange: !!u.must_change, mult: Number(u.quota_mult), hasRecovery: !!u.has_recovery };
}

// 画面に出す、記録の件数・上限・申請の状況
async function quotaInfo(sql, user) {
  const [{ n }] = await sql`SELECT count(*)::int AS n FROM runs WHERE user_id = ${user.id}`;
  const cap = C.runsCap(user.mult); // null = 無制限
  const atLimit = cap !== null && n >= Math.floor(cap * 0.95);
  const rq = await sql`SELECT status, note, admin_note, granted_mult, created_at, decided_at
                       FROM quota_requests WHERE user_id = ${user.id} ORDER BY id DESC LIMIT 1`;
  let request = null;
  if (rq.length) {
    const r = rq[0], at = Number(r.decided_at || r.created_at);
    if (r.status === 'pending' || Date.now() - at < 30 * DAY) {
      request = { status: r.status, note: r.note, adminNote: r.admin_note,
                  grantedMult: r.granted_mult == null ? null : Number(r.granted_mult),
                  createdAt: Number(r.created_at), decidedAt: r.decided_at == null ? null : Number(r.decided_at) };
    }
  }
  return { runs: n, cap, mult: user.mult, atLimit, request };
}

module.exports = { currentUser, quotaInfo };

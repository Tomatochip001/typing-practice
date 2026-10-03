// 運営(管理者)用の API。Authorization: Bearer <ADMIN_TOKEN> が必要。画面は admin.html。
const crypto = require('crypto');
const { db } = require('./_lib/db');
const { api, send, clientIp } = require('./_lib/http');
const A = require('./_lib/auth');
const R = require('./_lib/ratelimit');
const { cleanText } = require('./_lib/text');

const FAIL_WINDOW = 15 * 60 * 1000, MAX_FAILS = 10;

function adminToken() {
  const t = process.env.ADMIN_TOKEN;
  if (!t || t.length < 32) { const e = new Error('ADMIN_TOKEN is missing or shorter than 32 chars'); e.code = 'not_configured'; throw e; }
  return t;
}
const digest = s => crypto.createHash('sha256').update(String(s)).digest();
function isAdmin(req) {
  const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
  return !!m && crypto.timingSafeEqual(digest(m[1]), digest(adminToken()));
}
const int = v => Number.isInteger(v) && v > 0 ? v : null;
const num = v => v == null ? null : Number(v);

module.exports = api('POST', async (req, res, body) => {
  adminToken();
  const sql = await db();
  const ip = clientIp(req);
  // 総当たり対策: 失敗が続いたIPは、一定時間受け付けない(正しいトークンでも)
  if (await R.peek(sql, 'admin_fail', ip, FAIL_WINDOW) >= MAX_FAILS) return send(res, 429, { error: 'locked' });
  if (!isAdmin(req)) { await R.hit(sql, 'admin_fail', ip, FAIL_WINDOW, Infinity); return send(res, 401, { error: 'unauthorized' }); }

  const now = Date.now();
  switch (body.action) {
    case 'overview': {
      const [u] = await sql`SELECT count(*)::int AS n FROM users`;
      const [q] = await sql`SELECT count(*)::int AS n FROM quota_requests WHERE status = 'pending'`;
      const [r] = await sql`SELECT count(*)::int AS n FROM reset_requests WHERE status = 'pending'`;
      const [d] = await sql`SELECT pg_database_size(current_database())::bigint AS bytes`;
      return send(res, 200, { users: u.n, pendingQuota: q.n, pendingReset: r.n, dbBytes: Number(d.bytes) });
    }

    case 'list_quota': {
      const all = body.status === 'all';
      const rows = await sql`SELECT q.id, u.username, q.note, q.status, q.runs_at_request, q.created_at, q.decided_at, q.admin_note, q.granted_mult,
                                    u.quota_mult, u.last_seen, (SELECT count(*)::int FROM runs r WHERE r.user_id = q.user_id) AS runs_now
                             FROM quota_requests q JOIN users u ON u.id = q.user_id
                             WHERE (${all} OR q.status = 'pending') ORDER BY q.id DESC LIMIT 100`;
      return send(res, 200, { items: rows.map(r => ({ id: Number(r.id), username: r.username, note: r.note, status: r.status, runsAtRequest: r.runs_at_request, runsNow: r.runs_now,
        currentMult: Number(r.quota_mult), createdAt: Number(r.created_at), decidedAt: num(r.decided_at), adminNote: r.admin_note, grantedMult: num(r.granted_mult), lastSeen: num(r.last_seen) })) });
    }

    case 'decide_quota': {
      const id = int(body.id), note = cleanText(body.note, 300);
      if (!id || !['approve', 'reject'].includes(body.decision)) return send(res, 400, { error: 'invalid' });
      if (body.decision === 'approve') {
        if (![2, 5, 0].includes(body.mult)) return send(res, 400, { error: 'invalid', message: '引き上げ幅は 2倍 / 5倍 / 無制限 から選んでください。' });
        // 申請の更新とユーザーの上限の更新を、1つの文で一緒に行う(片方だけ変わらないように)
        const ok = await sql`WITH r AS (UPDATE quota_requests SET status = 'approved', decided_at = ${now}, admin_note = ${note}, granted_mult = ${body.mult}
                                        WHERE id = ${id} AND status = 'pending' RETURNING user_id)
                             UPDATE users u SET quota_mult = ${body.mult} FROM r WHERE u.id = r.user_id RETURNING u.username`;
        if (!ok.length) return send(res, 409, { error: 'already_decided', message: 'すでに処理済みです。' });
        return send(res, 200, { ok: true, username: ok[0].username });
      }
      const ok = await sql`UPDATE quota_requests SET status = 'rejected', decided_at = ${now}, admin_note = ${note} WHERE id = ${id} AND status = 'pending' RETURNING id`;
      if (!ok.length) return send(res, 409, { error: 'already_decided', message: 'すでに処理済みです。' });
      return send(res, 200, { ok: true });
    }

    case 'list_reset': {
      const all = body.status === 'all';
      const rows = await sql`SELECT q.id, u.username, q.note, q.status, q.created_at, q.decided_at, q.admin_note, u.created_at AS user_created, u.last_seen,
                                    (SELECT count(*)::int FROM runs r WHERE r.user_id = q.user_id) AS runs
                             FROM reset_requests q JOIN users u ON u.id = q.user_id
                             WHERE (${all} OR q.status = 'pending') ORDER BY q.id DESC LIMIT 100`;
      return send(res, 200, { items: rows.map(r => ({ id: Number(r.id), username: r.username, note: r.note, status: r.status, createdAt: Number(r.created_at),
        decidedAt: num(r.decided_at), adminNote: r.admin_note, userCreated: Number(r.user_created), lastSeen: num(r.last_seen), runs: r.runs })) });
    }

    case 'decide_reset': {
      const id = int(body.id), note = cleanText(body.note, 300);
      if (!id || !['issue', 'reject'].includes(body.decision)) return send(res, 400, { error: 'invalid' });
      if (body.decision === 'reject') {
        const ok = await sql`UPDATE reset_requests SET status = 'rejected', decided_at = ${now}, admin_note = ${note} WHERE id = ${id} AND status = 'pending' RETURNING id`;
        if (!ok.length) return send(res, 409, { error: 'already_decided', message: 'すでに処理済みです。' });
        return send(res, 200, { ok: true });
      }
      // 仮パスワードを発行する。1回だけ画面に出す(DBにはハッシュしか残さない)。ログインした本人は、すぐ新しいパスワードに変える必要がある
      const temp = A.newTempPassword(), h = await A.hashPassword(temp);
      const ok = await sql`WITH r AS (UPDATE reset_requests SET status = 'issued', decided_at = ${now}, admin_note = ${note}
                                      WHERE id = ${id} AND status = 'pending' RETURNING user_id)
                           UPDATE users u SET salt = ${h.salt}, hash = ${h.hash}, session_epoch = u.session_epoch + 1, must_change = true
                           FROM r WHERE u.id = r.user_id RETURNING u.id, u.username`;
      if (!ok.length) return send(res, 409, { error: 'already_decided', message: 'すでに処理済みです。' });
      await sql`DELETE FROM login_fails WHERE username IN (${ok[0].username}, ${'rec:' + ok[0].username}, ${'acct:' + ok[0].id})`;
      return send(res, 200, { ok: true, username: ok[0].username, tempPassword: temp });
    }

    case 'list_users': {
      const q = cleanText(body.q, 30).toLowerCase().replace(/[\\%_]/g, c => '\\' + c);
      const rows = await sql`SELECT u.username, u.created_at, u.last_seen, u.quota_mult, u.must_change, (SELECT count(*)::int FROM runs r WHERE r.user_id = u.id) AS runs
                             FROM users u WHERE u.username LIKE ${'%' + q + '%'} ESCAPE '\\' ORDER BY u.id DESC LIMIT 100`;
      return send(res, 200, { items: rows.map(r => ({ username: r.username, createdAt: Number(r.created_at), lastSeen: num(r.last_seen), mult: Number(r.quota_mult), mustChange: !!r.must_change, runs: r.runs })) });
    }

    case 'delete_user': {
      const name = A.normUsername(body.username);
      if (!name || body.confirm !== body.username) return send(res, 400, { error: 'invalid', message: '確認のため、ユーザー名をもう一度入力してください。' });
      const ok = await sql`DELETE FROM users WHERE username = ${name} RETURNING id`;
      if (!ok.length) return send(res, 404, { error: 'not_found' });
      return send(res, 200, { ok: true });
    }

    default:
      return send(res, 400, { error: 'bad_action' });
  }
}, { maxBytes: 16 * 1024 });

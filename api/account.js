// ログイン中のユーザーの操作: パスワード変更・回復コードの再発行・記録の上限の申請
const { db } = require('./_lib/db');
const { api, send, clientIp, baseUrl } = require('./_lib/http');
const A = require('./_lib/auth');
const R = require('./_lib/ratelimit');
const { currentUser, quotaInfo } = require('./_lib/session');
const { cleanText } = require('./_lib/text');
const { notifyAdmin } = require('./_lib/notify');

const WINDOW = 15 * 60 * 1000, MAX_FAILS = 5, DAY = 86400000;

// 「いまのパスワード」の確認。5回続けて間違えると15分ロック(盗まれたログイン状態から、パスワードを推測されないように)
async function confirmPassword(sql, req, user, pw) {
  const key = `acct:${user.id}`, now = Date.now();
  const [{ n }] = await sql`SELECT count(*)::int AS n FROM login_fails WHERE username = ${key} AND at > ${now - WINDOW}`;
  if (n >= MAX_FAILS) return 'locked';
  if (typeof pw !== 'string' || !(await A.verifyPassword(pw.slice(0, 200), user.salt, user.hash))) {
    await sql`INSERT INTO login_fails (username, ip, at) VALUES (${key}, ${clientIp(req)}, ${now})`;
    return 'bad';
  }
  await sql`DELETE FROM login_fails WHERE username = ${key}`;
  return 'ok';
}
const WRONG = { error: 'bad_credentials', message: 'いまのパスワードが違います。' };
const LOCKED = { error: 'locked', message: '失敗が続いたため、一時的にロックしました。15分後にやり直してください。' };

module.exports = api('POST', async (req, res, body) => {
  A.ensureConfigured();
  if (!A.readSession(req)) return send(res, 401, { error: 'unauthorized' });
  const sql = await db();
  const user = await currentUser(sql, req);
  if (!user) return send(res, 401, { error: 'unauthorized' }, { 'Set-Cookie': A.clearCookie() });

  /* ---- パスワードの変更(仮パスワードからの変更も、ここ) ---- */
  if (body.action === 'change_password') {
    const err = A.checkPassword(body.next, user.username);
    if (err) return send(res, 400, { error: 'invalid', message: err });
    if (body.next === body.current) return send(res, 400, { error: 'same', message: '新しいパスワードは、いまのパスワードと別のものにしてください。' });
    const c = await confirmPassword(sql, req, user, body.current);
    if (c === 'locked') return send(res, 429, LOCKED);
    if (c === 'bad') return send(res, 401, WRONG);
    const h = await A.hashPassword(body.next);
    // 運営が発行した仮パスワードからの変更では、回復コードも新しくする(前のコードは、本人が持っていない可能性があるため)
    let recoveryCode = null, rec = { salt: null, hash: null };
    if (user.mustChange) { recoveryCode = A.newRecoveryCode(); rec = await A.hashPassword(A.normRecoveryCode(recoveryCode)); }
    const rows = await sql`UPDATE users SET salt = ${h.salt}, hash = ${h.hash}, session_epoch = session_epoch + 1, must_change = false,
                             recovery_salt = COALESCE(${rec.salt}, recovery_salt), recovery_hash = COALESCE(${rec.hash}, recovery_hash)
                           WHERE id = ${user.id} RETURNING session_epoch`;
    // epoch が上がるので、ほかの端末のログインは切れる。この端末は新しい cookie で続ける
    return send(res, 200, { ok: true, recoveryCode }, { 'Set-Cookie': A.sessionCookie(user.id, Number(rows[0].session_epoch)) });
  }

  // これ以降は、仮パスワードのままでは使えない(先にパスワードを変えてもらう)
  if (user.mustChange) return send(res, 403, { error: 'must_change_password' });

  /* ---- 回復コードの再発行(前のコードは使えなくなる) ---- */
  if (body.action === 'new_recovery_code') {
    const c = await confirmPassword(sql, req, user, body.password);
    if (c === 'locked') return send(res, 429, LOCKED);
    if (c === 'bad') return send(res, 401, { error: 'bad_credentials', message: 'パスワードが違います。' });
    const recoveryCode = A.newRecoveryCode(), rec = await A.hashPassword(A.normRecoveryCode(recoveryCode));
    await sql`UPDATE users SET recovery_salt = ${rec.salt}, recovery_hash = ${rec.hash} WHERE id = ${user.id}`;
    return send(res, 200, { ok: true, recoveryCode });
  }

  /* ---- 記録の上限を上げる申請 ---- */
  if (body.action === 'quota_request') {
    const q = await quotaInfo(sql, user);
    if (!q.atLimit) return send(res, 400, { error: 'not_at_limit', message: 'まだ上限に近づいていないため、申請できません。' });
    if (q.request && q.request.status === 'pending') return send(res, 409, { error: 'pending', message: 'すでに申請中です。結果をお待ちください。' });
    const lim = await R.hit(sql, 'quota_req', String(user.id), DAY, 3);
    if (!lim.ok) return send(res, 429, { error: 'rate_limited', message: '申請の回数が多すぎます。明日またお試しください。' });
    const note = cleanText(body.note, 300);
    const ins = await sql`INSERT INTO quota_requests (user_id, note, runs_at_request, created_at) VALUES (${user.id}, ${note}, ${q.runs}, ${Date.now()})
                          ON CONFLICT (user_id) WHERE status = 'pending' DO NOTHING RETURNING id`;
    if (!ins.length) return send(res, 409, { error: 'pending', message: 'すでに申請中です。結果をお待ちください。' });
    await notifyAdmin({
      title: '📈 記録の上限を上げる申請が届きました',
      link: `${baseUrl(req)}/admin.html`,
      fields: [
        { name: 'ユーザー', value: user.username },
        { name: '記録の件数 / 現在の上限', value: `${q.runs.toLocaleString('en-US')} 件 / ${q.cap === null ? '無制限' : q.cap.toLocaleString('en-US') + ' 件'}(${user.mult === 0 ? '無制限' : user.mult + '倍'})` },
        { name: '本人の備考', value: note || '(なし)' }
      ]
    });
    return send(res, 200, { ok: true, quota: await quotaInfo(sql, user) });
  }

  return send(res, 400, { error: 'bad_action' });
});

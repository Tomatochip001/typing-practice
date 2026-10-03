// ログイン前の操作: 回復コードでのパスワード再設定 / 回復コードもなくした人の、運営への再発行の申請
const { db } = require('./_lib/db');
const { api, send, clientIp, baseUrl } = require('./_lib/http');
const A = require('./_lib/auth');
const R = require('./_lib/ratelimit');
const T = require('./_lib/turnstile');
const { cleanText } = require('./_lib/text');
const { notifyAdmin } = require('./_lib/notify');

const WINDOW = 15 * 60 * 1000, MAX_FAILS = 5, HOUR = 3600000, DAY = 86400000;
const MAX_REQUESTS_PER_DAY = 30;

async function reset(req, res, body) {
  const username = A.normUsername(body.username), code = A.normRecoveryCode(body.code);
  if (A.checkUsername(username) || !A.validRecoveryCode(code)) {
    return send(res, 400, { error: 'invalid', message: 'ユーザー名と、回復コード(20文字)を確認してください。' });
  }
  const perr = A.checkPassword(body.password, username);
  if (perr) return send(res, 400, { error: 'invalid', message: perr });

  const sql = await db();
  const ip = clientIp(req), now = Date.now(), key = `rec:${username}`;
  const lim = await R.hit(sql, 'rec_ip', ip, HOUR, 10);
  if (!lim.ok) return send(res, 429, { error: 'rate_limited', message: '試行の回数が多すぎます。しばらくしてからやり直してください。' }, { 'Retry-After': String(lim.retryAfterSec) });
  const [{ n }] = await sql`SELECT count(*)::int AS n FROM login_fails WHERE username = ${key} AND at > ${now - WINDOW}`;
  if (n >= MAX_FAILS) return send(res, 429, { error: 'locked', message: '失敗が続いたため、一時的にロックしました。15分後にやり直してください。' });

  const rows = await sql`SELECT id, recovery_salt, recovery_hash FROM users WHERE username = ${username}`;
  let ok = false;
  if (rows.length && rows[0].recovery_hash) ok = await A.verifyPassword(code, rows[0].recovery_salt, rows[0].recovery_hash);
  else await A.burn(code); // 存在しないときも、同じ時間をかける
  if (!ok) {
    await sql`INSERT INTO login_fails (username, ip, at) VALUES (${key}, ${ip}, ${now})`;
    return send(res, 401, { error: 'bad_credentials', message: 'ユーザー名か回復コードが違います。' });
  }

  // 成功: パスワードを替え、回復コードも新しくする(使ったコードは、もう使えない)。古いログインは全部切れる
  const h = await A.hashPassword(body.password);
  const recoveryCode = A.newRecoveryCode(), rec = await A.hashPassword(A.normRecoveryCode(recoveryCode));
  const upd = await sql`UPDATE users SET salt = ${h.salt}, hash = ${h.hash}, recovery_salt = ${rec.salt}, recovery_hash = ${rec.hash},
                          session_epoch = session_epoch + 1, must_change = false, last_seen = ${now}
                        WHERE id = ${Number(rows[0].id)} RETURNING session_epoch`;
  await sql`DELETE FROM login_fails WHERE username = ${key} OR username = ${username}`;
  send(res, 200, { username, recoveryCode }, { 'Set-Cookie': A.sessionCookie(Number(rows[0].id), Number(upd[0].session_epoch)) });
}

// 申請の受け付け。そのユーザー名が存在するかどうかは、答えに出さない(誰かの名前を探られないように)
async function requestReset(req, res, body) {
  T.ensureConfigured();
  const username = A.normUsername(body.username);
  if (A.checkUsername(username)) return send(res, 400, { error: 'invalid', message: 'ユーザー名を確認してください。' });
  const note = cleanText(body.note, 500);
  if (Array.from(note).length < 5) return send(res, 400, { error: 'invalid', message: '本人確認と連絡のための情報を、5文字以上で書いてください。' });
  const token = body.turnstile;
  if (typeof token !== 'string' || !token || token.length > 2048) return send(res, 400, { error: 'captcha', message: 'ボット対策の確認が済んでいません。確認が終わってからもう一度お試しください。' });

  const sql = await db();
  const ip = clientIp(req);
  const lim = await R.hit(sql, 'rr_ip', ip, DAY, 3);
  if (!lim.ok) return send(res, 429, { error: 'rate_limited', message: '申請の回数が多すぎます。明日またお試しください。' }, { 'Retry-After': String(lim.retryAfterSec) });
  if (await R.peek(sql, 'rr_day', 'all', DAY) >= MAX_REQUESTS_PER_DAY) return send(res, 503, { error: 'closed', message: '現在、申請を受け付けられません。しばらくしてからお試しください。' });
  const human = await T.verify(token, ip);
  if (human === 'unavailable') return send(res, 503, { error: 'captcha_unavailable', message: 'ボット対策の確認サーバーに接続できませんでした。少し待ってからお試しください。' });
  if (human !== 'ok') return send(res, 400, { error: 'captcha', message: 'ボット対策の確認に失敗しました。もう一度お試しください。' });
  await R.hit(sql, 'rr_day', 'all', DAY, Infinity);

  const users = await sql`SELECT id, created_at, last_seen, (SELECT count(*)::int FROM runs r WHERE r.user_id = users.id) AS runs FROM users WHERE username = ${username}`;
  if (users.length) {
    const u = users[0];
    const ins = await sql`INSERT INTO reset_requests (user_id, note, created_at) VALUES (${Number(u.id)}, ${note}, ${Date.now()})
                          ON CONFLICT (user_id) WHERE status = 'pending' DO NOTHING RETURNING id`;
    if (ins.length) {
      const d = t => t == null ? '(不明)' : new Date(Number(t)).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
      await notifyAdmin({
        title: '🔑 パスワード再発行の申請が届きました',
        link: `${baseUrl(req)}/admin.html`,
        fields: [
          { name: 'ユーザー', value: username },
          { name: 'アカウントの作成 / 最後のアクセス / 記録の件数', value: `${d(u.created_at)} / ${d(u.last_seen)} / ${Number(u.runs)}件` },
          { name: '本人確認・連絡のための情報', value: note }
        ]
      });
    }
  }
  send(res, 200, { ok: true, message: '申請を受け付けました。運営が確認して、対応できる場合は、書いていただいた連絡先に連絡します(対応できない場合もあります)。' });
}

module.exports = api('POST', async (req, res, body) => {
  A.ensureConfigured();
  if (body.action === 'reset') return reset(req, res, body);
  if (body.action === 'request') return requestReset(req, res, body);
  send(res, 400, { error: 'bad_action' });
}, { maxBytes: 16 * 1024 });

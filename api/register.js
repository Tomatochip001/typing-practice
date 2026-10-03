const { db } = require('./_lib/db');
const { api, send, clientIp } = require('./_lib/http');
const A = require('./_lib/auth');
const C = require('./_lib/config');
const R = require('./_lib/ratelimit');
const T = require('./_lib/turnstile');

const CLOSED = { error: 'closed', message: '現在、新規登録を受け付けていません。しばらくしてからお試しください。' };

// 処理の順序は「安いチェックから先に」: 設定 → 入力の形式 → 回数制限 → 人数の上限 → Turnstile(外部通信) → (高コスト)ハッシュ化とINSERT
module.exports = api('POST', async (req, res, body) => {
  A.ensureConfigured();
  T.ensureConfigured();
  if (!C.registrationOpen()) return send(res, 503, CLOSED);

  const username = A.normUsername(body.username), password = body.password;
  const err = A.checkUsername(username) || A.checkPassword(password, username);
  if (err) return send(res, 400, { error: 'invalid', message: err });
  const token = body.turnstile;
  if (typeof token !== 'string' || !token || token.length > 2048) return send(res, 400, { error: 'captcha', message: 'ボット対策の確認が済んでいません。確認が終わってからもう一度お試しください。' });

  const sql = await db();
  const ip = clientIp(req);
  const lim = await R.hit(sql, 'reg_ip', ip, 3600000, C.registerPerIpPerHour());
  if (!lim.ok) return send(res, 429, { error: 'rate_limited', message: '登録の回数が多すぎます。しばらくしてからやり直してください。' }, { 'Retry-After': String(lim.retryAfterSec) });

  // 1日の登録数と総ユーザー数の上限(いたずらで無料枠を使い切られないための頭打ち)
  if (await R.peek(sql, 'reg_day', 'all', 86400000) >= C.maxRegistrationsPerDay()) return send(res, 503, CLOSED);
  const [{ n }] = await sql`SELECT count(*)::int AS n FROM users`;
  if (n >= C.maxUsers()) return send(res, 503, CLOSED);

  // 人かどうかの確認(トークンは1回限り)。ここを通ってから、重いハッシュ計算とDB書き込みに進む
  const human = await T.verify(token, ip);
  if (human === 'unavailable') return send(res, 503, { error: 'captcha_unavailable', message: 'ボット対策の確認サーバーに接続できませんでした。少し待ってからお試しください。' });
  if (human !== 'ok') return send(res, 400, { error: 'captcha', message: 'ボット対策の確認に失敗しました。もう一度お試しください。' });

  const now = Date.now();
  const { salt, hash } = await A.hashPassword(password);
  const rows = await sql`INSERT INTO users (username, salt, hash, created_at, last_seen) VALUES (${username}, ${salt}, ${hash}, ${now}, ${now})
                         ON CONFLICT (username) DO NOTHING RETURNING id`;
  if (!rows.length) return send(res, 409, { error: 'taken', message: 'そのユーザー名は使われています。' });
  await R.hit(sql, 'reg_day', 'all', 86400000, Infinity); // 成功した登録だけを日次の上限に数える
  send(res, 200, { username }, { 'Set-Cookie': A.sessionCookie(Number(rows[0].id)) });
});

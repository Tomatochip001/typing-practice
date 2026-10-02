const { db } = require('./_lib/db');
const { api, send, clientIp } = require('./_lib/http');
const A = require('./_lib/auth');

module.exports = api('POST', async (req, res, body) => {
  const sql = await db();
  const username = A.normUsername(body.username), password = body.password;
  const err = A.checkUsername(username) || A.checkPassword(password, username);
  if (err) return send(res, 400, { error: 'invalid', message: err });

  // 同じIPからの連続登録を制限(1時間に10回まで)
  const ip = clientIp(req), now = Date.now();
  const [{ n }] = await sql`SELECT count(*)::int AS n FROM login_fails WHERE username = '*register' AND ip = ${ip} AND at > ${now - 3600000}`;
  if (n >= 10) return send(res, 429, { error: 'rate_limited', message: '登録の回数が多すぎます。しばらくしてからやり直してください。' });
  await sql`INSERT INTO login_fails (username, ip, at) VALUES ('*register', ${ip}, ${now})`;

  const { salt, hash } = await A.hashPassword(password);
  const rows = await sql`INSERT INTO users (username, salt, hash, created_at) VALUES (${username}, ${salt}, ${hash}, ${now})
                         ON CONFLICT (username) DO NOTHING RETURNING id`;
  if (!rows.length) return send(res, 409, { error: 'taken', message: 'そのユーザー名は使われています。' });
  send(res, 200, { username }, { 'Set-Cookie': A.sessionCookie(Number(rows[0].id)) });
});

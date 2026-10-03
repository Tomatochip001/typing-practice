const { db } = require('./_lib/db');
const { api, send, clientIp } = require('./_lib/http');
const A = require('./_lib/auth');

const WINDOW = 15 * 60 * 1000, MAX_USER = 5, MAX_IP = 30;

module.exports = api('POST', async (req, res, body) => {
  A.ensureConfigured();
  const sql = await db();
  const username = A.normUsername(body.username), password = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
  const ip = clientIp(req), now = Date.now(), since = now - WINDOW;

  const [byUser] = await sql`SELECT count(*)::int AS n, min(at) AS first FROM login_fails WHERE username = ${username} AND at > ${since}`;
  const [byIp] = await sql`SELECT count(*)::int AS n FROM login_fails WHERE ip = ${ip} AND username <> '*register' AND at > ${since}`;
  if (byUser.n >= MAX_USER || byIp.n >= MAX_IP) {
    const mins = byUser.first ? Math.max(1, Math.ceil((Number(byUser.first) + WINDOW - now) / 60000)) : 15;
    return send(res, 429, { error: 'locked', message: `失敗が続いたため一時的にロックしました。${mins}分後にやり直してください。` });
  }

  const rows = username ? await sql`SELECT id, salt, hash FROM users WHERE username = ${username}` : [];
  let ok = false;
  if (rows.length) ok = await A.verifyPassword(password, rows[0].salt, rows[0].hash);
  else await A.burn(password);

  if (!ok) {
    await sql`INSERT INTO login_fails (username, ip, at) VALUES (${username}, ${ip}, ${now})`;
    await sql`DELETE FROM login_fails WHERE at < ${now - 86400000}`;
    return send(res, 401, { error: 'bad_credentials', message: 'ユーザー名かパスワードが違います。' });
  }
  await sql`DELETE FROM login_fails WHERE username = ${username}`;
  send(res, 200, { username }, { 'Set-Cookie': A.sessionCookie(Number(rows[0].id)) });
});

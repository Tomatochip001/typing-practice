const { db } = require('./_lib/db');
const { api, send } = require('./_lib/http');
const A = require('./_lib/auth');

module.exports = api('GET', async (req, res) => {
  const uid = A.userIdOf(req);
  if (!uid) return send(res, 401, { error: 'unauthorized' });
  const sql = await db();
  const rows = await sql`SELECT username FROM users WHERE id = ${uid}`;
  if (!rows.length) return send(res, 401, { error: 'unauthorized' }, { 'Set-Cookie': A.clearCookie() });
  send(res, 200, { username: rows[0].username });
});

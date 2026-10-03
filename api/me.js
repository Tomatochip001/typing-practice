const { db } = require('./_lib/db');
const { api, send } = require('./_lib/http');
const A = require('./_lib/auth');
const { currentUser, quotaInfo } = require('./_lib/session');

module.exports = api('GET', async (req, res) => {
  if (!A.readSession(req)) return send(res, 401, { error: 'unauthorized' });
  const sql = await db();
  const user = await currentUser(sql, req);
  if (!user) return send(res, 401, { error: 'unauthorized' }, { 'Set-Cookie': A.clearCookie() });
  send(res, 200, { username: user.username, mustChange: user.mustChange, hasRecovery: user.hasRecovery, quota: await quotaInfo(sql, user) });
});

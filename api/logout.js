const { api, send } = require('./_lib/http');
const A = require('./_lib/auth');

module.exports = api('POST', async (req, res) => {
  send(res, 200, { ok: true }, { 'Set-Cookie': A.clearCookie() });
});

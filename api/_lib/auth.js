// パスワードのハッシュ化(scrypt)・セッショントークン(HMAC署名)・入力チェック。
const crypto = require('crypto');

const COOKIE = 'dkd_session';
const SESSION_DAYS = 30;

function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 32) { const e = new Error('AUTH_SECRET is missing or shorter than 32 chars'); e.code = 'not_configured'; throw e; }
  return s;
}

const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw.normalize('NFC'), salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => err ? rej(err) : res(key)));

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt);
  return { salt: salt.toString('hex'), hash: key.toString('hex') };
}
async function verifyPassword(pw, saltHex, hashHex) {
  const key = await scrypt(pw, Buffer.from(saltHex, 'hex'));
  const want = Buffer.from(hashHex, 'hex');
  return key.length === want.length && crypto.timingSafeEqual(key, want);
}
// ユーザーが存在しないときも同じ時間だけ計算して、存在の有無を悟られないようにする
const DUMMY = { salt: '00'.repeat(16), hash: '00'.repeat(64) };
async function burn(pw) { await verifyPassword(pw, DUMMY.salt, DUMMY.hash); }

const b64 = buf => Buffer.from(buf).toString('base64url');
const sign = payload => b64(crypto.createHmac('sha256', secret()).update(payload).digest());

function makeToken(uid) {
  const payload = `${uid}.${Date.now() + SESSION_DAYS * 86400000}`;
  return `${payload}.${sign(payload)}`;
}
function readToken(token) {
  if (typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const payload = token.slice(0, i), sig = token.slice(i + 1);
  const a = Buffer.from(sig), b = Buffer.from(sign(payload));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const [uid, exp] = payload.split('.');
  if (!/^\d+$/.test(uid) || !(Number(exp) > Date.now())) return null;
  return Number(uid);
}

function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (_) {} }
  });
  return out;
}
const cookieAttrs = 'Path=/; HttpOnly; SameSite=Lax' + (process.env.NODE_ENV === 'test' ? '' : '; Secure');
const sessionCookie = uid => `${COOKIE}=${makeToken(uid)}; ${cookieAttrs}; Max-Age=${SESSION_DAYS * 86400}`;
const clearCookie = () => `${COOKIE}=; ${cookieAttrs}; Max-Age=0`;
const userIdOf = req => readToken(parseCookies(req.headers.cookie)[COOKIE]);

/* ---- 入力チェック ---- */
const WEAK = new Set(['password', 'password1', '12345678', '123456789', 'qwertyui', 'qwerty123', 'abcd1234', 'iloveyou', '11111111', 'asdfghjk']);

function normUsername(u) {
  return typeof u === 'string' ? u.trim().toLowerCase() : '';
}
function checkUsername(u) {
  return /^[a-z0-9_.-]{3,20}$/.test(u) ? null : 'ユーザー名は半角の英数字と _ - . で3〜20文字にしてください。';
}
// 英字・数字・記号のうち2種類以上、8〜128文字
function checkPassword(pw, username) {
  if (typeof pw !== 'string' || pw.length < 8 || pw.length > 128) return 'パスワードは8〜128文字にしてください。';
  const kinds = [/[A-Za-z]/.test(pw), /[0-9]/.test(pw), /[^A-Za-z0-9\s]/.test(pw)].filter(Boolean).length;
  if (kinds < 2) return 'パスワードは英字・数字・記号のうち2種類以上を混ぜてください。';
  if (WEAK.has(pw.toLowerCase()) || pw.toLowerCase() === username) return 'そのパスワードは推測されやすいので使えません。';
  return null;
}

// 設定漏れ(AUTH_SECRET)は、DBに書き込む前に分かるようにする
const ensureConfigured = () => { secret(); };

module.exports = { ensureConfigured, hashPassword, verifyPassword, burn, sessionCookie, clearCookie, userIdOf, normUsername, checkUsername, checkPassword };

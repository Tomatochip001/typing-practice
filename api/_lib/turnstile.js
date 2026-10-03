// Cloudflare Turnstile のトークン検証。
// verify() は 'ok' | 'fail' | 'unavailable'(Cloudflareに接続できない)のどれかを返す。
const ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
let override = null;

// TURNSTILE_SECRET が無いときは登録を閉じる(設定漏れで、ボット対策なしのまま開かないように)
function ensureConfigured() {
  if (!process.env.TURNSTILE_SECRET) { const e = new Error('TURNSTILE_SECRET is not set'); e.code = 'not_configured'; throw e; }
}

async function verify(token, ip) {
  if (override) return override(token, ip);
  const body = new URLSearchParams({ secret: process.env.TURNSTILE_SECRET, response: token });
  if (ip && ip !== 'unknown') body.set('remoteip', ip);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 5000);
  try {
    const r = await fetch(ENDPOINT, { method: 'POST', body, signal: ctl.signal });
    if (!r.ok) return 'unavailable';
    const j = await r.json();
    return j && j.success === true ? 'ok' : 'fail';
  } catch (_) {
    return 'unavailable';
  } finally {
    clearTimeout(timer);
  }
}

// テスト用: 検証関数を差し替える
function __setVerify(fn) { override = fn; }

module.exports = { ensureConfigured, verify, __setVerify };

// 運営(管理者)への通知。Discord の Webhook に送る。DISCORD_WEBHOOK_URL が無ければ何もしない。
// 通知の失敗は、申請そのものを失敗にしない(記録は管理画面に残る)。
const HOOK = /^https:\/\/(?:[a-z0-9-]+\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+$/i;
let override = null;

const clip = (s, n) => { const a = Array.from(String(s == null ? '' : s)); return a.length > n ? a.slice(0, n - 1).join('') + '…' : a.join(''); };

// fields: [{ name, value }]。ユーザーが書いた文字列が入るので、メンション(@everyone 等)が動かないようにする
async function notifyAdmin({ title, fields, link }) {
  const payload = {
    username: '打鍵道場',
    allowed_mentions: { parse: [] },
    embeds: [{
      title: clip(title, 200),
      description: link ? `[管理画面を開く](${link})` : undefined,
      color: 0x3346c9,
      fields: (fields || []).slice(0, 10).map(f => ({ name: clip(f.name, 200), value: clip(f.value || '(なし)', 900), inline: false })),
      timestamp: new Date().toISOString()
    }]
  };
  if (override) return override(payload);
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url || !HOOK.test(url)) return false;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 4000);
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: ctl.signal });
    return r.ok;
  } catch (e) {
    console.error('[notify] failed:', e && e.name);
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// テスト用
function __setSender(fn) { override = fn; }

module.exports = { notifyAdmin, __setSender, clip };

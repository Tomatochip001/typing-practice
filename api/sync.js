// 端末 <-> クラウドの同期。
//  受信: 未送信の履歴(runs)・キー統計の増分(kd)・設定(prefs、変更があったときだけ)
//  返信: 自分の端末がまだ知らない履歴(after より後)・キー統計の合計・設定
const { db } = require('./_lib/db');
const { api, send } = require('./_lib/http');
const A = require('./_lib/auth');
const C = require('./_lib/config');
const R = require('./_lib/ratelimit');
const { currentUser, quotaInfo } = require('./_lib/session');

const MAX_RUNS_IN = 5000, PAGE = 20000;
const MAX_KEYS = 200, MAX_PREFS_BYTES = 64 * 1024, MAX_TEXT_BYTES = 28 * 1024;
const MIN_T = Date.UTC(2024, 0, 1), DAY = 86400000;
const num = (v, min, max) => typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max;
const int = (v, min, max) => num(v, min, max) ? Math.round(v) : null;

// 範囲外の値は保存せずに捨てる(捨てた分は、端末側のローカル記録には残る)
function cleanRuns(list, now) {
  const out = { t: [], mode: [], spd: [], acc: [], sec: [], miss: [], w: [] };
  if (!Array.isArray(list)) return out;
  for (const r of list.slice(0, MAX_RUNS_IN)) {
    if (!r || typeof r.mode !== 'string' || !/^[a-z]{1,10}(:[a-z]{1,10})?$/.test(r.mode)) continue;
    const t = int(r.t, MIN_T, now + DAY), spd = int(r.spd, 0, 3000), sec = int(r.sec, 0, 86400), miss = int(r.miss, 0, 100000);
    const w = r.w == null ? 0 : int(r.w, 0, 100000); // ラッシュの語数。無いときは0
    if (t === null || spd === null || sec === null || miss === null || w === null || !num(r.acc, 0, 1)) continue;
    out.t.push(t); out.mode.push(r.mode); out.spd.push(spd); out.acc.push(r.acc); out.sec.push(sec); out.miss.push(miss); out.w.push(w);
  }
  return out;
}
// キー統計の増分。クライアントの rec() が必ず満たす関係(ミスm + 速度を測れたc <= 打鍵n、遅延は1打あたり2秒未満)を守らないものは捨てる
function cleanKeys(kd) {
  const out = { k: [], n: [], m: [], t: [], c: [] };
  if (!kd || typeof kd !== 'object') return out;
  for (const [k, v] of Object.entries(kd).slice(0, MAX_KEYS)) {
    if (!v || k.length < 1 || k.length > 2) continue;
    const n = int(v.n, 0, 2e6), m = int(v.m, 0, 2e6), c = int(v.c, 0, 2e6), t = int(v.t, 0, 4e9);
    if (n === null || m === null || t === null || c === null) continue;
    if (m + c > n || t > c * 2000) continue;
    out.k.push(k); out.n.push(n); out.m.push(m); out.t.push(t); out.c.push(c);
  }
  return out;
}
// 設定はホワイトリスト: 決めた項目・型・値だけを保存する(DBを任意のJSONの置き場にされないように)
const bytes = s => Buffer.byteLength(s, 'utf8');
function cleanPrefs(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const out = {};
  const s = d.settings;
  if (s && typeof s === 'object' && !Array.isArray(s)) {
    out.settings = {};
    for (const k of ['skip', 'sound', 'retry']) if (typeof s[k] === 'boolean') out.settings[k] = s[k];
    if (['s', 'n', 'l'].includes(s.len)) out.settings.len = s.len;
  }
  if (d.layout === 'jis' || d.layout === 'us') out.layout = d.layout;
  if (d.kbMode === 'miss' || d.kbMode === 'speed') out.kbMode = d.kbMode;
  for (const k of ['customCode', 'customIme']) if (typeof d[k] === 'string' && bytes(d[k]) <= MAX_TEXT_BYTES) out[k] = d[k];
  return bytes(JSON.stringify(out)) <= MAX_PREFS_BYTES ? out : null;
}

module.exports = api('POST', async (req, res, body) => {
  if (!A.readSession(req)) return send(res, 401, { error: 'unauthorized' });
  const sql = await db();
  const user = await currentUser(sql, req);
  if (!user) return send(res, 401, { error: 'unauthorized' }, { 'Set-Cookie': A.clearCookie() });
  const uid = user.id;
  // 運営が発行した仮パスワードのままでは、同期できない(先にパスワードを変えてもらう)
  if (user.mustChange) return send(res, 403, { error: 'must_change_password' });

  // 同期の回数制限と、最終アクセス時刻の更新(1時間に1回まで)
  const lim = await R.hit(sql, 'sync_user', String(uid), 600000, C.syncPerUserPer10Min());
  if (!lim.ok) return send(res, 429, { error: 'rate_limited', retryAfterSec: lim.retryAfterSec }, { 'Retry-After': String(lim.retryAfterSec) });
  const nowMs = Date.now();
  await sql`UPDATE users SET last_seen = ${nowMs} WHERE id = ${uid} AND (last_seen IS NULL OR last_seen < ${nowMs - 3600000})`;

  const runs = cleanRuns(body.runs, nowMs), keys = cleanKeys(body.kd);
  if (runs.t.length) {
    await sql`INSERT INTO runs (user_id, t, mode, spd, acc, sec, miss, score)
              SELECT ${uid}, t, mode, spd, acc, sec, miss, score
              FROM unnest(${runs.t}::bigint[], ${runs.mode}::text[], ${runs.spd}::int[], ${runs.acc}::float8[], ${runs.sec}::int[], ${runs.miss}::int[], ${runs.w}::int[])
                   AS x(t, mode, spd, acc, sec, miss, score)
              ON CONFLICT (user_id, t, mode) DO NOTHING`;
  }
  if (keys.k.length) {
    await sql`INSERT INTO key_stats (user_id, k, n, m, t, c)
              SELECT ${uid}, k, n, m, t, c
              FROM unnest(${keys.k}::text[], ${keys.n}::bigint[], ${keys.m}::bigint[], ${keys.t}::bigint[], ${keys.c}::bigint[])
                   AS x(k, n, m, t, c)
              ON CONFLICT (user_id, k) DO UPDATE SET
                n = key_stats.n + EXCLUDED.n, m = key_stats.m + EXCLUDED.m,
                t = key_stats.t + EXCLUDED.t, c = key_stats.c + EXCLUDED.c`;
  }

  const p = body.prefs, prefs = p && typeof p === 'object' ? cleanPrefs(p.data) : null;
  if (prefs && num(p.updatedAt, MIN_T, nowMs + DAY)) {
    await sql`INSERT INTO user_data (user_id, prefs, updated_at) VALUES (${uid}, ${JSON.stringify(prefs)}::jsonb, ${Math.round(p.updatedAt)})
              ON CONFLICT (user_id) DO UPDATE SET prefs = EXCLUDED.prefs, updated_at = EXCLUDED.updated_at
              WHERE EXCLUDED.updated_at > user_data.updated_at`;
  }

  // ユーザーごとの総量の上限: 履歴は古い順に、キー統計は打鍵数の少ない順に削る
  // 履歴の上限は、運営が承認した倍率で変わる(null = 無制限)
  const cap = C.runsCap(user.mult);
  if (runs.t.length && cap !== null) {
    const [{ n }] = await sql`SELECT count(*)::int AS n FROM runs WHERE user_id = ${uid}`;
    if (n > cap) {
      await sql`DELETE FROM runs WHERE user_id = ${uid} AND (t, mode) IN
                (SELECT t, mode FROM runs WHERE user_id = ${uid} ORDER BY t DESC, mode OFFSET ${cap})`;
    }
  }
  if (keys.k.length) {
    const [{ n }] = await sql`SELECT count(*)::int AS n FROM key_stats WHERE user_id = ${uid}`;
    if (n > MAX_KEYS) {
      await sql`DELETE FROM key_stats WHERE user_id = ${uid} AND k IN
                (SELECT k FROM key_stats WHERE user_id = ${uid} ORDER BY n DESC, k OFFSET ${MAX_KEYS})`;
    }
  }

  const after = int(body.after, 0, 9e15) || 0;
  const rows = await sql`SELECT id, t, mode, spd, acc, sec, miss, score FROM runs WHERE user_id = ${uid} AND id > ${after} ORDER BY id LIMIT ${PAGE + 1}`;
  const more = rows.length > PAGE;
  const page = more ? rows.slice(0, PAGE) : rows;
  const keyRows = await sql`SELECT k, n, m, t, c FROM key_stats WHERE user_id = ${uid}`;
  const pref = await sql`SELECT prefs, updated_at FROM user_data WHERE user_id = ${uid}`;

  const keyOut = {};
  keyRows.forEach(r => { keyOut[r.k] = { n: Number(r.n), m: Number(r.m), t: Number(r.t), c: Number(r.c) }; });
  send(res, 200, {
    runs: page.map(r => ({ t: Number(r.t), mode: r.mode, spd: r.spd, acc: r.acc, sec: r.sec, miss: r.miss, ...(r.score ? { w: r.score } : {}) })),
    cursor: page.length ? Number(page[page.length - 1].id) : after,
    more,
    keys: keyOut,
    prefs: pref.length ? { updatedAt: Number(pref[0].updated_at), data: pref[0].prefs } : null,
    quota: await quotaInfo(sql, user)
  });
}, { maxBytes: 1024 * 1024 });

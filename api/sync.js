// 端末 <-> クラウドの同期。
//  受信: 未送信の履歴(runs)・キー統計の増分(kd)・設定(prefs、変更があったときだけ)
//  返信: 自分の端末がまだ知らない履歴(after より後)・キー統計の合計・設定
const { db } = require('./_lib/db');
const { api, send } = require('./_lib/http');
const A = require('./_lib/auth');

const MAX_RUNS_IN = 20000, PAGE = 20000, MAX_KEYS = 200, MAX_PREFS_BYTES = 150 * 1024;
const num = (v, min, max) => typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max;
const int = (v, min, max) => num(v, min, max) ? Math.round(v) : null;
// 範囲外の数値は捨てずに範囲内へ丸める(記録が黙って消えないように)
const clamp = (v, min, max) => typeof v === 'number' && Number.isFinite(v) ? Math.round(Math.min(max, Math.max(min, v))) : null;

function cleanRuns(list) {
  const out = { t: [], mode: [], spd: [], acc: [], sec: [], miss: [] };
  if (!Array.isArray(list)) return out;
  for (const r of list.slice(0, MAX_RUNS_IN)) {
    if (!r || typeof r.mode !== 'string' || !/^[a-z]{1,10}(:[a-z]{1,10})?$/.test(r.mode)) continue;
    const t = int(r.t, 1e12, 4e12), spd = clamp(r.spd, 0, 100000), sec = clamp(r.sec, 0, 86400), miss = clamp(r.miss, 0, 1000000);
    if (t === null || spd === null || sec === null || miss === null || !num(r.acc, 0, 1)) continue;
    out.t.push(t); out.mode.push(r.mode); out.spd.push(spd); out.acc.push(r.acc); out.sec.push(sec); out.miss.push(miss);
  }
  return out;
}
function cleanKeys(kd) {
  const out = { k: [], n: [], m: [], t: [], c: [] };
  if (!kd || typeof kd !== 'object') return out;
  for (const [k, v] of Object.entries(kd).slice(0, MAX_KEYS)) {
    if (!v || k.length < 1 || k.length > 2) continue;
    const n = int(v.n, 0, 1e9), m = int(v.m, 0, 1e9), t = int(v.t, 0, 1e13), c = int(v.c, 0, 1e9);
    if (n === null || m === null || t === null || c === null) continue;
    out.k.push(k); out.n.push(n); out.m.push(m); out.t.push(t); out.c.push(c);
  }
  return out;
}

module.exports = api('POST', async (req, res, body) => {
  const uid = A.userIdOf(req);
  if (!uid) return send(res, 401, { error: 'unauthorized' });
  const sql = await db();
  const exists = await sql`SELECT 1 FROM users WHERE id = ${uid}`;
  if (!exists.length) return send(res, 401, { error: 'unauthorized' }, { 'Set-Cookie': A.clearCookie() });

  const runs = cleanRuns(body.runs), keys = cleanKeys(body.kd);
  if (runs.t.length) {
    await sql`INSERT INTO runs (user_id, t, mode, spd, acc, sec, miss)
              SELECT ${uid}, t, mode, spd, acc, sec, miss
              FROM unnest(${runs.t}::bigint[], ${runs.mode}::text[], ${runs.spd}::int[], ${runs.acc}::float8[], ${runs.sec}::int[], ${runs.miss}::int[])
                   AS x(t, mode, spd, acc, sec, miss)
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

  const p = body.prefs;
  if (p && typeof p === 'object' && p.data && typeof p.data === 'object' && num(p.updatedAt, 1e12, 4e12)) {
    const json = JSON.stringify(p.data);
    if (json.length <= MAX_PREFS_BYTES) {
      await sql`INSERT INTO user_data (user_id, prefs, updated_at) VALUES (${uid}, ${json}::jsonb, ${Math.round(p.updatedAt)})
                ON CONFLICT (user_id) DO UPDATE SET prefs = EXCLUDED.prefs, updated_at = EXCLUDED.updated_at
                WHERE EXCLUDED.updated_at > user_data.updated_at`;
    }
  }

  const after = int(body.after, 0, 9e15) || 0;
  const rows = await sql`SELECT id, t, mode, spd, acc, sec, miss FROM runs WHERE user_id = ${uid} AND id > ${after} ORDER BY id LIMIT ${PAGE + 1}`;
  const more = rows.length > PAGE;
  const page = more ? rows.slice(0, PAGE) : rows;
  const keyRows = await sql`SELECT k, n, m, t, c FROM key_stats WHERE user_id = ${uid}`;
  const pref = await sql`SELECT prefs, updated_at FROM user_data WHERE user_id = ${uid}`;

  const keyOut = {};
  keyRows.forEach(r => { keyOut[r.k] = { n: Number(r.n), m: Number(r.m), t: Number(r.t), c: Number(r.c) }; });
  send(res, 200, {
    runs: page.map(r => ({ t: Number(r.t), mode: r.mode, spd: r.spd, acc: r.acc, sec: r.sec, miss: r.miss })),
    cursor: page.length ? Number(page[page.length - 1].id) : after,
    more,
    keys: keyOut,
    prefs: pref.length ? { updatedAt: Number(pref[0].updated_at), data: pref[0].prefs } : null
  });
});

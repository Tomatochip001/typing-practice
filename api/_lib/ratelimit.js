// 固定窓のレート制限。カウントはDBに置く(サーバーレスはインスタンス間でメモリを共有できないため)。
// hit: 1回数えて、上限を超えたか返す。peek: 数えずに現在値だけ見る。
async function hit(sql, bucket, key, windowMs, limit) {
  const now = Date.now(), win = Math.floor(now / windowMs);
  const rows = await sql`INSERT INTO rate_limits (bucket, key, win, n) VALUES (${bucket}, ${key}, ${win}, 1)
                         ON CONFLICT (bucket, key, win) DO UPDATE SET n = rate_limits.n + 1
                         RETURNING n`;
  const n = Number(rows[0].n);
  return { ok: n <= limit, n, retryAfterSec: Math.max(1, Math.ceil(((win + 1) * windowMs - now) / 1000)) };
}

async function peek(sql, bucket, key, windowMs) {
  const win = Math.floor(Date.now() / windowMs);
  const rows = await sql`SELECT n FROM rate_limits WHERE bucket = ${bucket} AND key = ${key} AND win = ${win}`;
  return rows.length ? Number(rows[0].n) : 0;
}

module.exports = { hit, peek };

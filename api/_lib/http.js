// APIハンドラ共通: メソッド確認・Origin確認・JSON入出力・エラー処理。
function send(res, status, body, headers) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  if (headers) Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (_) { return null; } }
    return req.body;
  }
  const chunks = [];
  let size = 0;
  for await (const c of req) { size += c.length; if (size > 4 * 1024 * 1024) return null; chunks.push(c); }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text.trim()) return {};
  try { return JSON.parse(text); } catch (_) { return null; }
}

function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || String(req.headers['x-real-ip'] || '') || 'unknown';
}

// method: 'POST' など。成功時は handler(req, res, body) を呼ぶ
function api(method, handler) {
  return async (req, res) => {
    try {
      if (req.method !== method) return send(res, 405, { error: 'method_not_allowed' }, { Allow: method });
      const origin = req.headers.origin;
      if (origin) {
        let host = '';
        try { host = new URL(origin).host; } catch (_) {}
        if (host !== req.headers.host) return send(res, 403, { error: 'bad_origin' });
      }
      const body = method === 'GET' ? null : await readBody(req);
      if (method !== 'GET' && (body === null || typeof body !== 'object')) return send(res, 400, { error: 'bad_json' });
      await handler(req, res, body);
    } catch (e) {
      if (e && e.code === 'not_configured') {
        console.error('[api] not configured:', e.message);
        return send(res, 503, { error: 'not_configured' });
      }
      console.error('[api] error:', e);
      send(res, 500, { error: 'server_error' });
    }
  };
}

module.exports = { api, send, clientIp };

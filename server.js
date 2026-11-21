// Local server: serves the app and stores the encrypted vault blob. It never sees plaintext or keys.
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

const PORT = Number(process.env.PORT) || 4848;
const DATA = path.resolve(process.env.VAULT_FILE || path.join(import.meta.dirname, 'data', 'vault.json'));
const PUB = path.join(import.meta.dirname, 'public');
const MAX_BODY = 5 * 1024 * 1024;
const ALLOWED_HOSTS = new Set([`localhost:${PORT}`, `127.0.0.1:${PORT}`]);
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };

const isBox = (b) => typeof b?.iv === 'string' && typeof b?.ct === 'string';
const isVault = (f) =>
  f?.v === 1 && Number.isInteger(f.rev) && typeof f.kdf?.salt === 'string' &&
  Number.isInteger(f.kdf?.iterations) && isBox(f.key) && (f.data === null || isBox(f.data));

async function readVault() {
  try {
    return await fs.readFile(DATA, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

async function handle(req, res) {
  const send = (code, body = '', type = 'application/json') => {
    res.writeHead(code, {
      'content-type': type,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'self'",
    });
    res.end(body);
  };
  // Blocks DNS-rebinding: a malicious site pointing its domain at 127.0.0.1 sends its own Host.
  if (!ALLOWED_HOSTS.has(req.headers.host)) return send(403, '{"error":"host not allowed"}');

  const { pathname } = new URL(req.url, 'http://localhost');
  if (pathname === '/api/vault') {
    if (req.method === 'GET') {
      const vault = await readVault();
      return vault ? send(200, vault) : send(404, '{"error":"no vault"}');
    }
    if (req.method === 'PUT') {
      // A custom header forces a CORS preflight, which this server never approves: other sites cannot write.
      if (req.headers['x-pwdkeepr'] !== '1') return send(403, '{"error":"missing header"}');
      let size = 0;
      const chunks = [];
      for await (const c of req) {
        if ((size += c.length) > MAX_BODY) return send(413, '{"error":"too large"}');
        chunks.push(c);
      }
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks));
      } catch {
        return send(400, '{"error":"invalid json"}');
      }
      if (!isVault(body)) return send(400, '{"error":"invalid vault"}');

      const current = await readVault();
      const currentRev = current ? JSON.parse(current).rev : 0;
      // Optimistic lock: a stale tab must not overwrite newer data.
      if (body.rev !== currentRev) return send(409, '{"error":"vault changed elsewhere"}');

      const next = JSON.stringify({ ...body, rev: currentRev + 1 });
      await fs.mkdir(path.dirname(DATA), { recursive: true });
      if (current) await fs.writeFile(DATA + '.bak', current);
      await fs.writeFile(DATA + '.tmp', next);
      await fs.rename(DATA + '.tmp', DATA); // atomic replace, no half-written vault on crash
      return send(200, JSON.stringify({ rev: currentRev + 1 }));
    }
    return send(405, '{"error":"method not allowed"}');
  }

  if (req.method !== 'GET') return send(405, '{"error":"method not allowed"}');
  const file = path.join(PUB, pathname === '/' ? 'index.html' : pathname);
  if (!file.startsWith(PUB + path.sep)) return send(404, 'not found', 'text/plain');
  try {
    return send(200, await fs.readFile(file), TYPES[path.extname(file)] || 'application/octet-stream');
  } catch {
    return send(404, 'not found', 'text/plain');
  }
}

http
  .createServer((req, res) =>
    handle(req, res).catch((e) => {
      console.error(e);
      if (!res.headersSent) res.writeHead(500).end('{"error":"server error"}');
    }),
  )
  .listen(PORT, '127.0.0.1', () => console.log(`pwdkeepr running at http://localhost:${PORT}`));

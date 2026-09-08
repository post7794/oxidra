import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve, extname } from 'node:path';

export const webRoot = fileURLToPath(new URL('./', import.meta.url));
const repoRoot = resolve(webRoot, '..');
export const publicFiles = ['index.html', 'styles.css', 'app.js', 'content.js', 'assets/mark.svg'];
export const referenceFiles = ['README.md', 'docs/oxidra-mvp.md', 'docs/m4-m5-roadmap.md', 'docs/mcp-roadmap.md'];
const contentTypes = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml',
  '.md': 'text/plain; charset=utf-8',
};

// Exact route allowlist: never expose the repository, session state or credentials.
export function createSiteServer({ production = false } = {}) {
  const root = production ? resolve(webRoot, 'dist') : webRoot;
  const routes = new Map(publicFiles.map(file => [`/${file}`, resolve(root, file)]));
  routes.set('/', resolve(root, 'index.html'));
  routes.set('/favicon.ico', resolve(root, 'assets/mark.svg'));
  for (const file of referenceFiles) {
    routes.set(`/reference/${file}`, production ? resolve(root, 'reference', file) : resolve(repoRoot, file));
  }
  return createServer(async (request, response) => {
    const headers = {
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-cache',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    };
    const reply = (status, text, extra = {}) => {
      const body = Buffer.from(text);
      response.writeHead(status, { ...headers, 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length, ...extra });
      response.end(request.method === 'HEAD' ? undefined : body);
    };
    if (!['GET', 'HEAD'].includes(request.method)) return reply(405, 'Method not allowed', { Allow: 'GET, HEAD' });
    let pathname;
    try {
      // Do not normalize dot segments: even encoded traversal must miss the allowlist.
      pathname = decodeURIComponent((request.url || '/').split('?')[0]);
    } catch {
      return reply(400, 'Invalid request path');
    }
    const file = routes.get(pathname);
    if (!file) return reply(404, 'Not found');
    try {
      const body = await readFile(file);
      response.writeHead(200, { ...headers, 'Content-Type': contentTypes[extname(file)], 'Content-Length': body.length });
      response.end(request.method === 'HEAD' ? undefined : body);
    } catch (error) {
      if (error.code === 'ENOENT') return reply(404, 'Not found');
      return reply(500, 'Unable to read the requested asset');
    }
  });
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  const portIndex = process.argv.indexOf('--port');
  const port = Number(portIndex >= 0 ? process.argv[portIndex + 1] : process.env.PORT || 5173);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be an integer between 1 and 65535');
  const server = createSiteServer({ production: process.argv.includes('--dist') });
  server.on('error', error => {
    console.error(['EADDRINUSE', 'EACCES'].includes(error.code) ? `Port ${port} is occupied or reserved by the OS. Try: npm run dev -- --port ${port + 1}` : error.message);
    process.exitCode = 1;
  });
  server.listen(port, '127.0.0.1', () => {
    console.log(`\n  oxidra.  ·  introduction website\n\n  Local: http://127.0.0.1:${port}\n  Static demo only — no model calls, no command execution.\n`);
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
    server.close();
    server.closeIdleConnections();
  });
}

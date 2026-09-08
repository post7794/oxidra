import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { once } from 'node:events';
import { tools, installs, documents, escapeHtml, renderCodeLines, renderCommand } from '../content.js';
import { createSiteServer, webRoot, publicFiles, referenceFiles } from '../server.mjs';
import { buildSite } from '../scripts/build.mjs';

let server;
let origin;
before(async () => {
  server = createSiteServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  origin = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  const closed = new Promise(resolveClose => server.close(resolveClose));
  server.closeAllConnections();
  await closed;
});

function rawRequest(path, method = 'GET') {
  return new Promise((resolveResponse, reject) => {
    const req = request(origin, { path, method }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolveResponse({ status: response.statusCode, body, headers: response.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('editorial toolbox matches the actual five builtin definitions', async () => {
  const source = await readFile(resolve(webRoot, '../src/tools.rs'), 'utf8');
  const section = source.slice(source.indexOf('fn tool_definitions()'));
  const names = [...section.matchAll(/name: "([a-z]+)"\.to_owned\(\)/g)].slice(0, 5).map(match => match[1]);
  assert.deepEqual(Object.keys(tools).sort(), names.sort());
  for (const [key, tool] of Object.entries(tools)) {
    assert.ok(tool.title && tool.description && tool.filename && tool.footnote, key);
    assert.equal(tool.lines.length, 6);
  }
});

test('all document triggers resolve to authored content and allowlisted source files', async () => {
  const html = await readFile(resolve(webRoot, 'index.html'), 'utf8');
  for (const [, key] of html.matchAll(/data-doc(?:-page)?="([a-z]+)"/g)) assert.ok(documents[key], key);
  for (const doc of Object.values(documents)) assert.ok(referenceFiles.includes(doc.source), doc.source);
  assert.match(documents.mcp.body, /还不能接入 MCP/);
  assert.match(documents.context.body, /显式开启/);
  assert.match(documents.budget.body, /不是已生效/);
});

test('installation commands are copyable, and do not silently enable full-auto', () => {
  assert.equal(Object.keys(installs).length, 3);
  assert.match(installs.source.command, /cargo install --path \./);
  assert.match(installs.windows.command, /powershell -NoProfile/);
  assert.match(installs.run.command, /oxidra auth login/);
  for (const install of Object.values(installs)) assert.doesNotMatch(install.command, /--full-auto/);
});

test('renderers escape markup and do not trust syntax-tone values', () => {
  const input = '<script>alert("x")</script>&\'';
  assert.equal(escapeHtml(input), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;');
  const code = renderCodeLines([{ text: input, tone: '" onclick="evil' }]);
  assert.doesNotMatch(code, /<script>|onclick/);
  assert.match(code, /&lt;script&gt;/);
  assert.match(renderCommand('# safe comment\n<img src=x>'), /&lt;img src=x&gt;/);
});

test('all static assets and raw reference documents respond successfully', async () => {
  for (const path of ['/', ...publicFiles.map(file => `/${file}`), ...referenceFiles.map(file => `/reference/${file}`)]) {
    const response = await rawRequest(path);
    assert.equal(response.status, 200, path);
    assert.ok(response.body.length > 0, path);
  }
});

test('HTTP uses explicit MIME, no-sniff and no outbound connection CSP', async () => {
  const page = await rawRequest('/');
  assert.match(page.headers['content-type'], /text\/html/);
  assert.equal(page.headers['x-content-type-options'], 'nosniff');
  assert.match(page.headers['content-security-policy'], /connect-src 'none'/);
  const doc = await rawRequest('/reference/README.md');
  assert.equal(doc.headers['content-type'], 'text/plain; charset=utf-8');
  const js = await rawRequest('/app.js');
  assert.match(js.headers['content-type'], /text\/javascript/);
});

test('HEAD returns the same metadata without a body', async () => {
  const get = await rawRequest('/styles.css');
  const head = await rawRequest('/styles.css', 'HEAD');
  assert.equal(head.status, 200);
  assert.equal(head.body, '');
  assert.equal(head.headers['content-length'], get.headers['content-length']);
});

test('the preview server is read-only', async () => {
  for (const method of ['POST', 'PUT', 'DELETE']) {
    const result = await rawRequest('/', method);
    assert.equal(result.status, 405);
    assert.equal(result.headers.allow, 'GET, HEAD');
  }
});

test('unknown and traversal paths never expose arbitrary workspace files', async () => {
  for (const path of [
    '/server.mjs', '/package.json', '/.git/config', '/src/auth.rs', '/.env',
    '/../Cargo.toml', '/%2e%2e/Cargo.toml', '/reference/../../Cargo.toml',
    '/reference/%2e%2e/%2e%2e/Cargo.toml', '/assets/..%5c..%5cCargo.toml',
    '/reference/docs/not-in-the-allowlist.md', '/index.html/extra',
  ]) {
    const result = await rawRequest(path);
    assert.equal(result.status, 404, path);
    assert.equal(result.body, 'Not found', path);
  }
  assert.equal((await rawRequest('/%ZZ')).status, 400);
  assert.equal((await rawRequest('/styles.css?v=1')).status, 200);
});

test('all local HTML anchors, SVG symbols and ARIA control targets exist', async () => {
  const html = await readFile(resolve(webRoot, 'index.html'), 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(ids.length, new Set(ids).size, 'duplicate HTML IDs');
  for (const [, target] of html.matchAll(/(?:href="#|aria-controls=")([^"\s]+)"/g)) {
    assert.ok(ids.includes(target), `missing target: ${target}`);
  }
  assert.match(html, /<html lang="zh-CN">/);
  assert.match(html, /<noscript>/);
  assert.match(html, /流程示意 · 不连接模型，不执行本地命令/);
});

test('production output is a self-contained, byte-identical static snapshot', async () => {
  const build = await buildSite();
  assert.equal(build.files.length, publicFiles.length + referenceFiles.length);
  for (const file of publicFiles) {
    const source = await readFile(resolve(webRoot, file));
    const built = await readFile(resolve(build.output, file));
    assert.deepEqual(built, source, file);
  }
  const production = createSiteServer({ production: true });
  production.listen(0, '127.0.0.1');
  await once(production, 'listening');
  try {
    const response = await fetch(`http://127.0.0.1:${production.address().port}/reference/docs/mcp-roadmap.md`);
    assert.equal(response.status, 200);
    assert.match(await response.text(), /Agent 与 CLI 参数仍未接入/);
  } finally {
    const closed = new Promise(resolveClose => production.close(resolveClose));
    production.closeAllConnections();
    await closed;
  }
});

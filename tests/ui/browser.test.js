// M4: the console's main flows in a real headless Chrome, driven over the
// Chrome DevTools Protocol with node's built-in WebSocket and fetch (no
// packages to install). Starts a primary and a standby (target/debug/rust-dns
// or $RUST_DNS_BIN) on free loopback ports with throwaway configs.
//
//   node tests/ui/browser.test.js
//
// Flows: sign in; create a zone; add, edit and delete a record; a viewer
// sees the zone but no enabled write control (and the server agrees); the
// standby's zone page is read-only (controls disabled with the reason, a
// forced click opens nothing); a scoped API token created from the tokens
// page (M1). Any uncaught page exception fails the test.
//
// Skips (exit 0) when Chrome or the binary is missing, unless
// REQUIRE_BROWSER_TEST=1 (CI). Chrome: $CHROME_BIN, else the usual places.
'use strict';
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const REQUIRED = !!process.env.REQUIRE_BROWSER_TEST && process.env.REQUIRE_BROWSER_TEST !== '0';
const ROOT = path.join(__dirname, '../..');
const BIN = process.env.RUST_DNS_BIN || path.join(ROOT, 'target/debug/rust-dns');

function skip(why) {
  if (REQUIRED) { console.error(`FAIL: ${why} (REQUIRE_BROWSER_TEST is set)`); process.exit(1); }
  console.log(`skip: ${why}`); process.exit(0);
}

function findChrome() {
  const cands = [process.env.CHROME_BIN,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium'].filter(Boolean);
  for (const c of cands) if (fs.existsSync(c)) return c;
  for (const n of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'chrome']) {
    const r = spawnSync('sh', ['-c', `command -v ${n}`], { encoding: 'utf8' });
    if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  }
  return null;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const freePort = () => new Promise((res, rej) => {
  const s = net.createServer(); s.unref(); s.on('error', rej);
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
});
async function waitUntil(what, fn, ms = 15000) {
  const end = Date.now() + ms; let last;
  while (Date.now() < end) {
    try { last = await fn(); if (last) return last; } catch (e) { last = e.message; }
    await sleep(100);
  }
  throw new Error(`timed out: ${what} (last: ${JSON.stringify(last)})`);
}

// ---- servers ------------------------------------------------------------------
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rust-dns-browser-'));
const children = [];
function cleanup() {
  for (const c of children) { try { c.kill('SIGKILL'); } catch {} }
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
}
process.on('exit', cleanup);
process.on('SIGINT', () => process.exit(130));

async function startServer(name, password, extra = '') {
  const dir = path.join(tmp, name); fs.mkdirSync(dir, { recursive: true });
  const dns = await freePort(), web = await freePort();
  fs.writeFileSync(path.join(dir, 'rust-dns.toml'), `
[server]
bind = ["127.0.0.1"]
port = ${dns}
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "${path.join(dir, 'data.db')}"
[web_console]
bind = "127.0.0.1:${web}"
login_attempts_per_minute = 10000
login_backoff_after = 100000
[root]
username = "root"
password = "${password}"
[logging]
level = "warn"
file = "${path.join(dir, 'server.log')}"
[backup]
dir = ""
${extra}
`);
  const child = spawn(BIN, ['--config', path.join(dir, 'rust-dns.toml')], { stdio: 'ignore' });
  children.push(child);
  const url = `http://127.0.0.1:${web}`;
  await waitUntil(`${name} up`, async () => (await fetch(`${url}/api/health`)).ok, 20000);
  return { name, url, password };
}

// A minimal API client with a session cookie.
async function apiLogin(srv, user, pw) {
  const r = await fetch(`${srv.url}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-requested-with': 'rust-dns' }, body: JSON.stringify({ username: user, password: pw }) });
  if (!r.ok) throw new Error(`login ${user}: ${r.status}`);
  const cookie = r.headers.get('set-cookie').split(';')[0];
  return async (method, p, body) => {
    const res = await fetch(`${srv.url}/api${p}`, { method, headers: { cookie, 'x-requested-with': 'rust-dns', ...(body ? { 'content-type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, json };
  };
}

// ---- Chrome over CDP ------------------------------------------------------------
class Browser {
  static async launch(bin) {
    const dir = path.join(tmp, 'chrome'); fs.mkdirSync(dir, { recursive: true });
    const args = ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${dir}`, '--no-first-run',
      '--no-default-browser-check', '--disable-gpu', '--disable-extensions', '--window-size=1400,1000', 'about:blank'];
    if (process.platform === 'linux') args.unshift('--no-sandbox'); // CI runners restrict user namespaces
    const child = spawn(bin, args, { stdio: 'ignore' });
    children.push(child);
    const portFile = path.join(dir, 'DevToolsActivePort');
    const port = await waitUntil('Chrome DevTools port', () => fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').split('\n')[0], 20000);
    const v = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
    const b = new Browser();
    b.ws = new WebSocket(v.webSocketDebuggerUrl);
    b.next = 1; b.pending = new Map(); b.listeners = [];
    b.ws.onmessage = ev => {
      const m = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString());
      if (m.id && b.pending.has(m.id)) { const { res, rej } = b.pending.get(m.id); b.pending.delete(m.id); m.error ? rej(new Error(`${m.error.message}`)) : res(m.result); }
      else for (const l of b.listeners) l(m);
    };
    await new Promise((res, rej) => { b.ws.onopen = res; b.ws.onerror = rej; });
    return b;
  }
  send(method, params = {}, sessionId) {
    const id = this.next++;
    this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    return new Promise((res, rej) => this.pending.set(id, { res, rej }));
  }
  // A page in its own browser context (own cookies: one user per page).
  async page(label) {
    const { browserContextId } = await this.send('Target.createBrowserContext');
    const { targetId } = await this.send('Target.createTarget', { url: 'about:blank', browserContextId });
    const { sessionId } = await this.send('Target.attachToTarget', { targetId, flatten: true });
    const p = new Page(this, sessionId, label);
    this.listeners.push(m => {
      if (m.sessionId !== sessionId) return;
      if (m.method === 'Runtime.exceptionThrown') p.errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
      if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') p.errors.push(m.params.args.map(a => a.value ?? a.description).join(' '));
    });
    await p.send('Runtime.enable'); await p.send('Page.enable');
    return p;
  }
}

class Page {
  constructor(b, sessionId, label) { this.b = b; this.sessionId = sessionId; this.label = label; this.errors = []; }
  send(m, p) { return this.b.send(m, p, this.sessionId); }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`${this.label}: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
    return r.result.value;
  }
  async goto(url) {
    await this.send('Page.navigate', { url });
    await waitUntil(`${this.label}: load ${url}`, () => this.eval(`return document.readyState === 'complete' && location.href.startsWith(${JSON.stringify(url.split('#')[0])})`));
  }
  wait(what, expr, ms) { return waitUntil(`${this.label}: ${what}`, () => this.eval(expr), ms); }
  // Set a field the way typing does (input + change events).
  fill(sel, value) {
    return this.eval(`const e = document.querySelector(${JSON.stringify(sel)}); if (!e) throw new Error('no ' + ${JSON.stringify(sel)});
      e.value = ${JSON.stringify(value)}; e.dispatchEvent(new Event('input', { bubbles: true })); e.dispatchEvent(new Event('change', { bubbles: true })); return true;`);
  }
  click(sel) {
    return this.eval(`const e = document.querySelector(${JSON.stringify(sel)}); if (!e) throw new Error('no ' + ${JSON.stringify(sel)});
      if (e.disabled) throw new Error(${JSON.stringify(sel)} + ' is disabled: ' + e.title); e.click(); return true;`);
  }
  async signIn(srv, user, pw) {
    await this.goto(srv.url + '/');
    await this.wait('login form', `return !!document.querySelector('#li-user') && !document.querySelector('#login').classList.contains('hidden')`);
    await this.fill('#li-user', user); await this.fill('#li-pass', pw); await this.click('#li-btn');
    await this.wait('signed in', `return !document.querySelector('#app').classList.contains('hidden')`);
  }
  async route(hash, readyExpr) {
    await this.eval(`location.hash = ${JSON.stringify(hash)}; return true`);
    await this.wait(`route ${hash}`, readyExpr);
  }
}

// ---- checks ---------------------------------------------------------------------------
let fails = 0;
const ok = (name, cond, detail = '') => { if (cond) console.log(`ok   ${name}`); else { fails++; console.log(`FAIL ${name} ${detail}`); } };

async function main() {
  const chrome = findChrome();
  if (!chrome) skip('Chrome/Chromium not found (set CHROME_BIN)');
  if (!fs.existsSync(BIN)) skip(`${BIN} not built (cargo build)`);

  const p = await startServer('primary', 'rootpass-primary');
  const rootApi = await apiLogin(p, 'root', 'rootpass-primary');
  const repl = (await rootApi('POST', '/tokens', { name: 'repl' })).json.token;
  const s = await startServer('standby', 'rootpass-standby', `[follow]\nprimary = "${p.url}"\ninstance_id = "dns2"\ntoken = "${repl}"\nreconcile_interval_secs = 2\ntimeout_secs = 5\n`);
  const b = await Browser.launch(chrome);

  // ---- admin on the primary: zone and record lifecycle ----
  const admin = await b.page('admin@primary');
  await admin.signIn(p, 'root', 'rootpass-primary');
  ok('sign in', true);
  await admin.route('#/zones', `return !!document.querySelector('#z-new')`);
  await admin.click('#z-new');
  await admin.wait('new zone dialog', `return !!document.querySelector('#modal [name=name]')`);
  await admin.fill('#modal [name=name]', 'ui.test');
  await admin.click('#m-ok');
  await admin.wait('zone page', `return location.hash === '#/zones/ui.test' && !!document.querySelector('#r-add')`);
  ok('create zone', (await rootApi('GET', '/zones/ui.test')).status === 200);

  await admin.click('#r-add');
  await admin.wait('record dialog', `return !!document.querySelector('#rf-value')`);
  await admin.fill('#rf-name', 'www');
  await admin.fill('#rf-type', 'A');
  await admin.wait('value field for A', `return !!document.querySelector('#rf-value')`);
  await admin.fill('#rf-value', '192.0.2.10');
  await admin.click('#rf-save');
  await admin.wait('record listed', `return document.querySelector('#records')?.textContent.includes('192.0.2.10')`);
  let recs = (await rootApi('GET', '/zones/ui.test/records')).json.records;
  ok('add record', recs.length === 1 && recs[0].value === '192.0.2.10', JSON.stringify(recs));

  await admin.eval(`document.querySelector('#records [data-edit]').click(); return true`);
  await admin.wait('edit dialog', `return document.querySelector('#rf-value')?.value === '192.0.2.10'`);
  await admin.fill('#rf-value', '192.0.2.11');
  await admin.click('#rf-save');
  await admin.wait('record changed', `return document.querySelector('#records')?.textContent.includes('192.0.2.11')`);
  recs = (await rootApi('GET', '/zones/ui.test/records')).json.records;
  ok('edit record', recs.length === 1 && recs[0].value === '192.0.2.11', JSON.stringify(recs));

  await admin.eval(`document.querySelector('#records [data-del]').click(); return true`);
  await admin.wait('confirm dialog', `return !!document.querySelector('#cf-ok')`);
  await admin.click('#cf-ok');
  await admin.wait('record gone', `return !document.querySelector('#records')?.textContent.includes('192.0.2.11')`);
  recs = (await rootApi('GET', '/zones/ui.test/records')).json.records;
  ok('delete record', recs.length === 0, JSON.stringify(recs));

  // A record for the other checks.
  await rootApi('POST', '/zones/ui.test/records', { name: 'keep', type: 'A', value: '192.0.2.20' });

  // ---- a viewer: sees the zone, no enabled write control ----
  await rootApi('POST', '/users', { username: 'vera', password: 'vera-password-1' });
  const m = await rootApi('PUT', '/zones/ui.test/members/vera', { role: 'viewer' });
  ok('viewer granted', m.status < 300, JSON.stringify(m));
  const viewer = await b.page('viewer@primary');
  await viewer.signIn(p, 'vera', 'vera-password-1');
  await viewer.route('#/zones/ui.test', `return document.querySelector('#records')?.textContent.includes('192.0.2.20')`);
  const vstate = await viewer.eval(`
    const write = [...document.querySelectorAll('#main [data-perm]')].filter(e => !['view', 'export'].includes(e.dataset.perm));
    return { writes: write.length, enabled: write.filter(e => !e.disabled).map(e => e.id || e.dataset.perm),
             add: document.querySelector('#r-add') ? document.querySelector('#r-add').disabled : 'absent' };`);
  ok('viewer: no enabled write control', vstate.enabled.length === 0, JSON.stringify(vstate));
  ok('viewer: add record not usable', vstate.add === true || vstate.add === 'absent', JSON.stringify(vstate));
  const veraApi = await apiLogin(p, 'vera', 'vera-password-1');
  const vr = await veraApi('POST', '/zones/ui.test/records', { name: 'x', type: 'A', value: '192.0.2.1' });
  ok('viewer: the server refuses too', vr.status === 403, JSON.stringify(vr));

  // ---- the standby: read-only ----
  const sApi = await apiLogin(s, 'root', 'rootpass-standby');
  await waitUntil('standby has the zone', async () => (await sApi('GET', '/zones/ui.test/records')).json?.records?.length === 1, 30000);
  const st = await b.page('admin@standby');
  await st.signIn(s, 'root', 'rootpass-standby');
  await st.route('#/zones/ui.test', `return document.querySelector('#records')?.textContent.includes('192.0.2.20') && !!document.querySelector('#r-add')`);
  await st.wait('standby banner', `return document.querySelector('#repl-banner')?.textContent.includes('Standby of')`);
  const sstate = await st.eval(`
    const add = document.querySelector('#r-add');
    const writes = [...document.querySelectorAll('#main [data-perm]')].filter(e => !e.matches('[data-ro-ok]'));
    return { addDisabled: add.disabled, title: add.title, enabled: writes.filter(e => !e.disabled).map(e => e.id || e.dataset.perm) };`);
  ok('standby: add record disabled', sstate.addDisabled && /Read-only standby/.test(sstate.title), JSON.stringify(sstate));
  ok('standby: no enabled write control', sstate.enabled.length === 0, JSON.stringify(sstate));
  const forced = await st.eval(`const add = document.querySelector('#r-add'); add.disabled = false; add.click(); await new Promise(r => setTimeout(r, 300));
    return !!document.querySelector('#rf-value');`);
  ok('standby: a forced click opens nothing', forced === false);

  // ---- tokens page: a scoped token (M1) ----
  await admin.route('#/tokens', `return !!document.querySelector('#t-new')`);
  await admin.click('#t-new');
  await admin.wait('token dialog', `return !!document.querySelector('#m-scope [name=sc-role]')`);
  await admin.fill('#modal [name=name]', 'ui-scoped');
  await admin.eval(`document.querySelector('#m-scope-d').open = true; document.querySelector('[name=sc-all][value=some]').checked = true;
    document.querySelector('[name=sc-zone][value="ui.test"]').checked = true; return true`);
  await admin.fill('#m-scope [name=sc-role]', 'viewer');
  await admin.click('#m-ok');
  await admin.wait('token shown once', `return document.querySelector('#modal')?.textContent.includes('Token created')`);
  const tk = (await rootApi('GET', '/tokens')).json.tokens.find(t => t.name === 'ui-scoped');
  ok('scoped token created', tk && JSON.stringify(tk.scope) === JSON.stringify({ zones: ['ui.test'], max_role: 'viewer' }), JSON.stringify(tk));
  await admin.eval(`document.querySelector('#modal [data-close]').click(); return true`);
  await admin.wait('token listed with its scope', `return document.querySelector('#main')?.textContent.includes('≤ viewer')`);

  for (const pg of [admin, viewer, st]) ok(`no page errors (${pg.label})`, pg.errors.length === 0, JSON.stringify(pg.errors));
  b.ws.close();
}

main().then(() => {
  if (fails) { console.log(`${fails} failed`); process.exit(1); }
  console.log('all passed'); process.exit(0);
}, e => { console.error(`FAIL ${e.stack || e}`); process.exit(1); });

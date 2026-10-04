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
  // O0c: stdin is a pipe held by this process; the server exits when it
  // closes (this script ended, however), so no server outlives the test.
  const child = spawn(BIN, ['--config', path.join(dir, 'rust-dns.toml')], { stdio: ['pipe', 'ignore', 'ignore'], env: { ...process.env, RUST_DNS_EXIT_WITH_STDIN: '1' } });
  children.push(child);
  const url = `http://127.0.0.1:${web}`;
  await waitUntil(`${name} up`, async () => (await fetch(`${url}/api/health`)).ok, 20000);
  return { name, url, password };
}

// A minimal API client with a session cookie.
async function apiLogin(srv, user, pw) {
  const r = await fetch(`${srv.url}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-requested-with': 'rust-dns' }, body: JSON.stringify({ username: user, password: pw }) });
  if (!r.ok) throw new Error(`login ${user}: ${r.status}`);
  const cookie = r.headers.getSetCookie().find(c => /rdns_session=/.test(c)).split(';')[0];
  const csrf = (await r.json()).csrf_token || '';
  return async (method, p, body) => {
    const res = await fetch(`${srv.url}/api${p}`, { method, headers: { cookie, 'x-requested-with': 'rust-dns', 'x-csrf-token': csrf, ...(body ? { 'content-type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
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

  // ---- Phase O: account security and console productivity ----
  const pages = [admin, viewer, st];
  pages.push(...(await phaseO(b, p, rootApi, admin)));

  // ---- N1: the key rollover wizard, every step, with shortened timers ----
  pages.push(...(await rolloverWalk(b, rootApi)));

  for (const pg of pages) ok(`no page errors (${pg.label})`, pg.errors.length === 0, JSON.stringify(pg.errors));
  b.ws.close();
}

// Phase O flows on the primary `p` (root's API client `rootApi`, root's page `admin`).
async function phaseO(b, p, rootApi, admin) {
  const bearer = async (tok, method, pth) => (await fetch(`${p.url}/api${pth}`, { method, headers: { authorization: `Bearer ${tok}` } })).status;
  // O1: change own password and revoke own API tokens from the account page.
  await rootApi('POST', '/users', { username: 'olive', password: 'olive-password-1' });
  const oliveApi = await apiLogin(p, 'olive', 'olive-password-1');
  const otok = (await oliveApi('POST', '/tokens', { name: 'olive-ci' })).json.token;
  ok('O1: token works before', (await bearer(otok, 'GET', '/me')) === 200);
  const olive = await b.page('olive@primary');
  await olive.signIn(p, 'olive', 'olive-password-1');
  await olive.route('#/account', `return !!document.querySelector('#pw-revoke')`);
  await olive.fill('#pw-cur', 'olive-password-1'); await olive.fill('#pw-new', 'olive-password-2');
  await olive.eval(`document.querySelector('#pw-revoke').checked = true; return true`);
  await olive.click('#pw-btn');
  await olive.wait('password changed', `return document.querySelector('#toasts').textContent.includes('API tokens revoked') || document.querySelector('#pw-err').textContent`);
  const after = await bearer(otok, 'GET', '/me'); ok('O1: password change from the console revokes the tokens', after === 401, String(after));

  // O4: the sign-in log, filtered on user and result.
  await fetch(`${p.url}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'olive', password: 'not-olive-password' }) });
  await admin.route('#/audit', `return !!document.querySelector('#au-signins')`);
  await admin.click('#au-signins');
  await admin.wait('sign-in log', `return location.hash === '#/audit/sign-ins' && !!document.querySelector('#si-go') && !document.querySelector('#si-body').textContent.includes('Loading')`);
  await admin.fill('#si-user', 'olive');
  await admin.fill('#si-result', 'failure');
  await admin.click('#si-go');
  const rowsSi = await admin.wait('filtered rows', `const r = [...document.querySelectorAll('#si-body tr')].map(t => t.textContent); return r.length && r.every(x => x.includes('olive') && x.includes('failure')) && !r.some(x => x.includes('success')) ? r : null`);
  ok('O4: sign-in log shows the failed password for the filtered user', rowsSi.length >= 1 && rowsSi.some(r => r.includes('password')) && !rowsSi.join().includes('not-olive-password'), JSON.stringify(rowsSi));

  // O5: administrator-only MFA enrollment, and a user's authenticator set up by the administrator.
  await admin.route('#/users', `return !!document.querySelector('#sec-mfa')`);
  await admin.fill('#sec-mfa', 'admin');
  await admin.click('#sec-save');
  await admin.wait('security saved', `return document.querySelector('#sec-card')?.textContent.includes('saved')`);
  ok('O5: enrollment set to administrators only', (await rootApi('GET', '/settings/security')).json.settings.mfa_enrollment === 'admin');
  const oliveId = (await rootApi('GET', '/users')).json.users.find(u => u.username === 'olive').id;
  await admin.eval(`document.querySelector('[data-edit="${oliveId}"]').click(); return true`);
  await admin.wait('user dialog', `return !!document.querySelector('#u-admin-mfa')`);
  await admin.click('#u-admin-mfa');
  await admin.wait('confirm', `return !!document.querySelector('#cf-ok')`);
  await admin.click('#cf-ok');
  const secret = await admin.wait('QR shown once', `return document.querySelector('#ae-qr svg') ? [...document.querySelectorAll('#modal code')].map(c => c.textContent).find(t => /^[A-Z2-7]{16,}$/.test(t)) : null`);
  await admin.eval(`document.querySelector('#modal [data-close]').click(); return true`);
  const login = await fetch(`${p.url}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'olive', password: 'olive-password-2' }) });
  const lj = await login.json();
  ok('O5: the user now needs a code from the administrator\'s QR', lj.status === 'mfa_required' && !!secret, JSON.stringify(lj));
  await rootApi('DELETE', '/settings/security');

  // O6: a password policy from the console; a too short password is refused.
  await admin.route('#/users', `return !!document.querySelector('#sec-len') && document.querySelector('#sec-card').textContent.includes('defaults')`);
  await admin.fill('#sec-len', '14'); await admin.fill('#sec-classes', '3'); await admin.fill('#sec-hist', '2');
  await admin.click('#sec-save');
  await admin.wait('policy saved', `return document.querySelector('#sec-card')?.textContent.includes('saved') && document.querySelector('#sec-len').value === '14'`);
  const pol = await waitUntil('policy stored', async () => { const v = (await rootApi('GET', '/settings/security')).json.settings; return v.password_min_length === 14 ? v : null; }, 5000).catch(async () => (await rootApi('GET', '/settings/security')).json.settings);
  ok('O6: password policy saved from the console', pol.password_min_length === 14 && pol.password_min_classes === 3 && pol.password_history === 2, JSON.stringify(pol));
  await admin.click('#u-new');
  await admin.wait('new user dialog', `return !!document.querySelector('#modal [name=username]')`);
  await admin.fill('#modal [name=username]', 'shorty'); await admin.fill('#modal [name=password]', 'Short-pw-1');
  await admin.click('#m-ok');
  const perr = await admin.wait('policy error shown', `return document.querySelector('#m-err')?.textContent`);
  ok('O6: the console shows the policy refusal', /at least 14 characters/.test(perr), perr);
  await admin.eval(`document.querySelector('#modal [data-close]').click(); return true`);
  await rootApi('DELETE', '/settings/security');

  // O7: the console sends the CSRF token; a cookie write without it is refused.
  const csrf = await admin.eval(`const a = await fetch('/api/zones', { method: 'POST', headers: { 'x-requested-with': 'rust-dns', 'content-type': 'application/json' }, body: JSON.stringify({ name: 'nocsrf.test' }) });
    return { status: a.status, code: (await a.json()).code };`);
  ok('O7: a cookie write without the CSRF token is refused', csrf.status === 403 && csrf.code === 'csrf', JSON.stringify(csrf));

  // O9: search across zones, jump to the record.
  await rootApi('POST', '/zones', { name: 'other.test' });
  await rootApi('POST', '/zones/other.test/records', { name: 'findme', type: 'TXT', value: 'needle-42' });
  await admin.route('#/zones', `return !!document.querySelector('#s-q')`);
  await admin.fill('#s-q', 'needle-42');
  await admin.click('#s-go');
  await admin.wait('search hit', `return document.querySelectorAll('#s-table [data-hit]').length === 1`);
  await admin.eval(`document.querySelector('#s-table [data-hit]').click(); return true`);
  await admin.wait('jumped to the record', `return location.hash === '#/zones/other.test' && !!document.querySelector('#records tr.flash')`);
  ok('O9: search finds the record and jumps to it', true);
  const vSearch = await (await apiLogin(p, 'vera', 'vera-password-1'))('GET', '/search?q=needle-42');
  ok('O9: a viewer of another zone does not find it', vSearch.status === 200 && vSearch.json.hits.length === 0, JSON.stringify(vSearch.json));

  // O10: paste several records with a preview, then delete two with multi-select.
  await admin.route('#/zones/other.test', `return !!document.querySelector('#r-bulk')`);
  await admin.click('#r-bulk');
  await admin.wait('bulk dialog', `return !!document.querySelector('#bk-text')`);
  await admin.fill('#bk-text', 'p1 A 192.0.2.101\np2 A 192.0.2.102\nbad A nope');
  await admin.click('#bk-preview');
  await admin.wait('preview shows the bad line', `return /line 3/.test(document.querySelector('#bk-out')?.textContent || '')`);
  ok('O10: preview names the bad line and changes nothing', (await rootApi('GET', '/zones/other.test/records')).json.records.length === 1);
  await admin.fill('#bk-text', 'p1 A 192.0.2.101\np2 A 192.0.2.102');
  await admin.click('#bk-preview');
  await admin.wait('clean preview', `return /2 to add/.test(document.querySelector('#bk-out')?.textContent || '') && !document.querySelector('#bk-apply').disabled`);
  await admin.click('#bk-apply');
  await admin.wait('applied', `return document.querySelector('#records')?.textContent.includes('192.0.2.102')`);
  ok('O10: pasted records applied', (await rootApi('GET', '/zones/other.test/records')).json.records.length === 3);
  await admin.eval(`for (const v of ['192.0.2.101', '192.0.2.102']) [...document.querySelectorAll('#records tr')].find(t => t.textContent.includes(v)).querySelector('[data-sel]').click(); return true`);
  await admin.click('#r-del-sel');
  await admin.wait('confirm', `return !!document.querySelector('#cf-ok')`);
  await admin.click('#cf-ok');
  await admin.wait('deleted', `return !document.querySelector('#records')?.textContent.includes('192.0.2.101')`);
  ok('O10: multi-select delete', (await rootApi('GET', '/zones/other.test/records')).json.records.length === 1);

  // O12: sort by a column; keyboard shortcuts.
  await rootApi('POST', '/zones/other.test/records/bulk', { add: 'zz A 192.0.2.1\naa A 192.0.2.3\nmm A 192.0.2.2' });
  await admin.route('#/zones/other.test', `return document.querySelectorAll('#records tbody tr').length === 4`);
  const order = () => admin.eval(`return [...document.querySelectorAll('#records tbody .c-name')].map(t => t.textContent)`);
  await admin.click('#records [data-sort="name"]');
  const asc = await order();
  await admin.click('#records [data-sort="name"]');
  const desc = await order();
  ok('O12: sorting by name, both directions', JSON.stringify(asc) === JSON.stringify(['aa', 'findme', 'mm', 'zz']) && JSON.stringify(desc) === JSON.stringify(['zz', 'mm', 'findme', 'aa']), JSON.stringify([asc, desc]));
  await admin.eval(`document.activeElement?.blur(); document.dispatchEvent(new KeyboardEvent('keydown', { key: 'n', bubbles: true })); return true`);
  await admin.wait('n opens the record dialog', `return !!document.querySelector('#rf-value')`);
  await admin.eval(`document.querySelector('#modal [data-close]')?.click(); document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); return true`);
  await admin.wait('dialog closed', `return !document.querySelector('#modal-root').classList.contains('open')`);
  await admin.eval(`document.dispatchEvent(new KeyboardEvent('keydown', { key: '/', bubbles: true })); return true`);
  ok('O12: "/" focuses the filter', await admin.eval(`return document.activeElement?.id === 'r-filter'`));
  await admin.eval(`document.activeElement.blur(); document.dispatchEvent(new KeyboardEvent('keydown', { key: '?', bubbles: true })); return true`);
  ok('O12: "?" lists the shortcuts', await admin.wait('help', `return !!document.querySelector('#kb-help')`));
  await admin.eval(`document.querySelector('#modal [data-close]').click(); return true`);

  // O11: clone and rename from the console.
  await admin.click('#z-clone');
  await admin.wait('clone dialog', `return !!document.querySelector('#zn-name')`);
  await admin.fill('#zn-name', 'copy.other.test');
  await admin.click('#m-ok');
  await admin.wait('clone opened', `return location.hash === '#/zones/copy.other.test' && document.querySelectorAll('#records tbody tr').length === 4`);
  ok('O11: zone cloned with its records', (await rootApi('GET', '/zones/copy.other.test/records')).json.records.length === 4);
  await admin.click('#z-rename');
  await admin.wait('rename dialog', `return !!document.querySelector('#zn-name')`);
  await admin.fill('#zn-name', 'renamed.test');
  await admin.click('#m-ok');
  await admin.wait('renamed', `return location.hash === '#/zones/renamed.test'`);
  ok('O11: zone renamed', (await rootApi('GET', '/zones/renamed.test/records')).json.records.length === 4 && (await rootApi('GET', '/zones/copy.other.test')).status === 404);

  // O15: rate limiting from the Server page (empty field = the file's value).
  await admin.route('#/server', `return !!document.querySelector('#rl-max')`);
  await admin.fill('#rl-max', '123');
  await admin.fill('#rl-ck', 'on');
  await admin.click('#rl-save');
  await admin.wait('rate limit saved', `return document.querySelector('#ratelimit-card')?.textContent.includes('set in the console') && document.querySelector('#rl-max').value === '123'`);
  const rl = (await rootApi('GET', '/settings/rate-limit')).json;
  ok('O15: rate limiting saved and in effect', rl.in_effect.max_resolutions_per_second_per_address === 123 && rl.in_effect.exempt_valid_cookies === true && rl.settings.slip === null, JSON.stringify(rl));
  await admin.click('#rl-reset');
  await admin.wait('rate limit reset', `return document.querySelector('#ratelimit-card')?.textContent.includes('config file') && document.querySelector('#rl-max').value === ''`);
  ok('O15: reset to the configuration file', (await rootApi('GET', '/settings/rate-limit')).json.source === 'config');

  // O16: a zone's own transfer ACL, NOTIFY targets and automatic PTR.
  await admin.route('#/zones/renamed.test', `return !!document.querySelector('#z-xfer')`);
  await admin.click('#z-xfer');
  await admin.wait('zone settings dialog', `return !!document.querySelector('#zs-acl')`);
  await admin.fill('#zs-ptr', 'off');
  await admin.eval(`document.querySelector('#zs-acl-own').checked = true; document.querySelector('#zs-nt-own').checked = true; return true`);
  await admin.fill('#zs-acl', '192.0.2.53\n2001:db8::/64');
  await admin.fill('#zs-nt', '192.0.2.53');
  await admin.click('#m-ok');
  await admin.wait('dialog closed', `return !document.querySelector('#zs-acl')`);
  const zs = (await rootApi('GET', '/zones/renamed.test')).json.settings;
  ok('O16: zone transfer, NOTIFY and PTR settings saved', JSON.stringify(zs) === JSON.stringify({ auto_ptr: false, transfer_allow: ['192.0.2.53/32', '2001:db8::/64'], notify: [{ address: '192.0.2.53:53' }] }), JSON.stringify(zs));
  await admin.click('#z-xfer');
  await admin.wait('zone settings dialog', `return !!document.querySelector('#zs-clear')`);
  await admin.click('#zs-clear');
  await admin.wait('dialog closed', `return !document.querySelector('#zs-acl')`);
  ok('O16: back to the server\'s settings', !(await rootApi('GET', '/zones/renamed.test')).json.settings);
  return [olive];
}

// Screenshots of the drawer when SCREENSHOT_DIR is set (for a human look).
async function shot(page, name) {
  if (!process.env.SCREENSHOT_DIR) return;
  await page.eval(`document.querySelector('#sec-roll')?.previousElementSibling?.scrollIntoView(); return true`);
  const r = await page.send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(process.env.SCREENSHOT_DIR, `${name}.png`), Buffer.from(r.data, 'base64'));
}

// A parent server hosting `test.` (its DS records edited through its API,
// as at a registrar), a primary signing `roll.test.` that finds the parent
// through forwarding, and a standby. Waits capped at 2 s.
async function rolloverWalk(b) {
  const dnsPort = srv => Number(fs.readFileSync(path.join(tmp, srv.name, 'rust-dns.toml'), 'utf8').match(/^port = (\d+)/m)[1]);
  const par = await startServer('rparent', 'rootpass-parent');
  const parApi = await apiLogin(par, 'root', 'rootpass-parent');
  const pport = dnsPort(par);
  await parApi('POST', '/zones', { name: 'test' });
  const prec = async (name, type, value) => (await parApi('POST', '/zones/test/records', { name, type, value })).json.id;
  await prec('@', 'NS', 'ns1.test.'); await prec('ns1', 'A', '127.0.0.1');
  await prec('roll', 'NS', 'ns1.roll.test.'); await prec('ns1.roll', 'A', '127.0.0.1');
  const rp = await startServer('rprimary', 'rootpass-rp', `[forwarding]\nupstreams = ["127.0.0.1:${pport}"]\nallowed_clients = ["127.0.0.0/8"]\n[dnssec]\nrollover_check_secs = 1\nrollover_max_wait_secs = 2\nparent_port = ${pport}\n`);
  const rpApi = await apiLogin(rp, 'root', 'rootpass-rp');
  await rpApi('POST', '/zones', { name: 'roll.test' });
  for (const [n, t, v] of [['@', 'NS', 'ns1.roll.test.'], ['ns1', 'A', '127.0.0.1'], ['www', 'A', '192.0.2.80']]) await rpApi('POST', '/zones/roll.test/records', { name: n, type: t, value: v });
  const on = (await rpApi('PUT', '/zones/roll.test/dnssec', { enabled: true })).json;
  const dsOf = r => r.record.split(' IN DS ')[1];
  const oldDsId = await prec('roll', 'DS', dsOf(on.ds.find(d => d.recommended)));
  const repl = (await rpApi('POST', '/tokens', { name: 'repl' })).json.token;
  const rs = await startServer('rstandby', 'rootpass-rs', `[follow]\nprimary = "${rp.url}"\ninstance_id = "dns2"\ntoken = "${repl}"\nreconcile_interval_secs = 2\ntimeout_secs = 5\n`);

  const pg = await b.page('rollover@primary');
  await pg.signIn(rp, 'root', 'rootpass-rp');
  const openTab = async (page) => {
    await page.route('#/zones/roll.test', `return !!document.querySelector('[data-panel=dnssec]')`);
    await page.eval(`document.querySelector('[data-panel=dnssec]').click(); return true`);
    await page.wait('DNSSEC tab with the rollover section', `return !!document.querySelector('#sec-roll')`);
  };
  const text = page => page.eval(`return document.querySelector('#sec-roll')?.textContent || ''`);
  await openTab(pg);
  await pg.click('#roll-start');
  await pg.wait('confirm', `return !!document.querySelector('#cf-ok')`);
  await pg.click('#cf-ok');
  await pg.wait('step 1 shown', `return (document.querySelector('#sec-roll')?.textContent || '').includes('1. New key published')`);
  ok('rollover: started from the console', (await rpApi('GET', '/zones/roll.test/dnssec/rollover')).json.stage === 'prepublish');
  const early = await pg.eval(`const b = document.querySelector('#roll-added'); return b ? { disabled: b.disabled, title: b.title, text: document.querySelector('#sec-roll').textContent } : null`);
  ok('rollover: "I\'ve added it" waits for the DNSKEY TTL', early && (!early.text.includes('Wait ') || (early.disabled && /DNSKEY TTL/.test(early.title))), JSON.stringify(early).slice(0, 300));
  await shot(pg, 'rollover-1-prepublish');
  await pg.wait('the new DS to add is shown', `return (document.querySelector('#sec-roll')?.textContent || '').includes('ADD this DS') && !document.querySelector('#roll-added').disabled`, 15000);
  await shot(pg, 'rollover-2-add-ds');
  const r1 = (await rpApi('GET', '/zones/roll.test/dnssec/rollover')).json;
  const shown = await text(pg);
  const nd = r1.new_key.ds.find(d => d.recommended);
  ok('rollover: every DS field shown with the record', shown.includes(nd.digest) && shown.includes(String(nd.key_tag)) && shown.includes('do not remove the old DS'), shown.slice(0, 300));

  // The standby: same stage, read-only.
  const sp = await b.page('rollover@standby');
  await sp.signIn(rs, 'root', 'rootpass-rs');
  await waitUntil('standby has the rollover', async () => (await (await apiLogin(rs, 'root', 'rootpass-rs'))('GET', '/zones/roll.test/dnssec/rollover')).json?.stage === 'prepublish', 20000);
  await openTab(sp);
  const sv = await sp.eval(`return { text: document.querySelector('#sec-roll').textContent, buttons: [...document.querySelectorAll('#sec-roll [id^=roll-]')].map(b => b.id) }`);
  ok('rollover: the standby shows the stage, no wizard buttons', sv.text.includes('New key published') && sv.text.includes('the primary runs the wizard') && sv.buttons.length === 0, JSON.stringify(sv).slice(0, 300));

  // A mistyped DS at the "registrar": the console names the field.
  const bad = nd.digest.slice(0, -1) + (nd.digest.endsWith('0') ? '1' : '0');
  const badId = await prec('roll', 'DS', `${nd.key_tag} 13 2 ${bad}`);
  await pg.click('#roll-added');
  await pg.wait('the mistyped DS is reported', `return [...document.querySelectorAll('#sec-roll .badge.bad')].some(e => e.textContent === 'matches neither key')`, 20000);
  const mt = await text(pg);
  ok('rollover: mistyped DS names the differing field', mt.includes('differs: digest'), mt.slice(mt.indexOf('Parent server')));
  await parApi('DELETE', `/zones/test/records/${badId}`);
  await prec('roll', 'DS', dsOf(nd));
  await pg.wait('switched: the old DS to delete is shown', `return (document.querySelector('#sec-roll')?.textContent || '').includes('DELETE this DS')`, 30000);
  await shot(pg, 'rollover-4-switched');
  const t4 = await text(pg);
  ok('rollover: after the switch the self-check passed and cancel is gone', t4.includes('Self-check after the switch') && !(await pg.eval(`return !!document.querySelector('#roll-cancel')`)), t4.slice(0, 300));
  await parApi('DELETE', `/zones/test/records/${oldDsId}`);
  await pg.wait('done: back to "Start key rollover"', `return !!document.querySelector('#roll-start')`, 30000);
  const fin = (await rpApi('GET', '/zones/roll.test/dnssec')).json;
  ok('rollover: done, the new key signs', fin.key.key_tag === nd.key_tag, JSON.stringify(fin.key));
  return [pg, sp];
}

main().then(() => {
  if (fails) { console.log(`${fails} failed`); process.exit(1); }
  console.log('all passed'); process.exit(0);
}, e => { console.error(`FAIL ${e.stack || e}`); process.exit(1); });

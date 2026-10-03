// Tests the console's access decisions exactly as shipped: the code between
// the ACCESS-BEGIN / ACCESS-END markers in src/ui/index.html (path templates,
// the standby request guard, and enabled/disabled + reason for a control
// given the caller's rights and the server state).
//   node tests/ui/access.test.js
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '../../src/ui/index.html'), 'utf8');
const src = html.slice(html.indexOf('/*ACCESS-BEGIN*/'), html.indexOf('/*ACCESS-END*/'));
if (!src) throw new Error('access markers not found in index.html');
const { pathMatches, requestAllowed, rightsIndex, decide, roReason } = new Function(`${src}; return { pathMatches, requestAllowed, rightsIndex, decide, roReason };`)();
let fails = 0;
const check = (name, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g !== w) { fails++; console.log(`FAIL ${name}: got ${g}, want ${w}`); } else console.log(`ok   ${name}`);
};

// ---- path templates ({x} = one non-empty segment; query ignored)
check('template id', pathMatches('/users/{id}/sessions/revoke', '/users/7/sessions/revoke'), true);
check('template extra segment', pathMatches('/me/sessions/{id}', '/me/sessions/12/x'), false);
check('template empty segment', pathMatches('/me/sessions/{id}', '/me/sessions/'), false);
check('template literal differs', pathMatches('/tsig/keys/{name}/reveal', '/tsig/keys/k1./delete'), false);
check('template encoded name', pathMatches('/tsig/keys/{name}/reveal', '/tsig/keys/k1.example./reveal'), true);
check('query ignored', pathMatches('/blocklists/test', '/blocklists/test?x=1'), true);
check('exact', pathMatches('/blocklists', '/blocklists/refresh'), false);

// ---- standby request guard
const allow = [
  { method: 'POST', path: '/auth/login' }, { method: 'DELETE', path: '/me/sessions/{id}' },
  { method: 'POST', path: '/users/{id}/sessions/revoke' }, { method: 'POST', path: '/blocklists/refresh' },
  { method: 'POST', path: '/blocklists/test' }, { method: 'POST', path: '/replication/promote' },
];
const ro = { primary: 'https://dns1.example.net', allow };
check('primary sends everything', requestAllowed('PUT', '/blocklists', null), true);
check('standby GET', requestAllowed('GET', '/zones', ro), true);
check('standby get lowercase', requestAllowed('get', '/zones', ro), true);
check('standby HEAD/OPTIONS', [requestAllowed('HEAD', '/x', ro), requestAllowed('OPTIONS', '/x', ro)], [true, true]);
check('standby refuses PUT /blocklists', requestAllowed('PUT', '/blocklists', ro), false);
check('standby allows refresh', requestAllowed('POST', '/blocklists/refresh', ro), true);
check('standby allows user revoke', requestAllowed('POST', '/users/3/sessions/revoke', ro), true);
check('standby refuses user reset-mfa', requestAllowed('POST', '/users/3/reset-mfa', ro), false);
check('standby method must match', requestAllowed('PUT', '/blocklists/test', ro), false);
check('standby own session', requestAllowed('DELETE', '/me/sessions/abc', ro), true);
check('standby refuses zones', requestAllowed('POST', '/zones', ro), false);
check('empty allowlist refuses', requestAllowed('POST', '/auth/login', { primary: '', allow: [] }), false);
check('reason names primary', roReason(ro), 'Read-only standby: make changes on the primary (https://dns1.example.net)');

// ---- control decisions
const rightsDoc = (isAdmin, zones) => ({
  global: [
    { perm: 'create_zones', label: 'Create zones', allowed: isAdmin, reason: isAdmin ? null : 'administrators only' },
    { perm: 'server_admin', label: 'Server admin', allowed: isAdmin, reason: isAdmin ? null : 'administrators only' },
    { perm: 'manage_own_sessions', label: 'Sign out own sessions', allowed: true, reason: null },
    { perm: 'change_own_password', label: 'Change own password', allowed: false, reason: 'the root password is set in the configuration file' },
  ],
  zones: zones.map(([zone, role, permissions]) => ({ zone, role, permissions })),
  zone_permissions: [
    { perm: 'view', label: 'See records', min_role: 'viewer' },
    { perm: 'edit_records', label: 'Add, change and delete records', min_role: 'editor' },
    { perm: 'import', label: 'Import records', min_role: 'owner' },
    { perm: 'delete_zone', label: 'Delete the zone', min_role: 'owner' },
  ],
});
const admin = rightsIndex(rightsDoc(true, [['a.test', 'owner', ['view', 'edit_records', 'import', 'delete_zone']]]));
const editor = rightsIndex(rightsDoc(false, [['a.test', 'editor', ['view', 'edit_records']], ['b.test', 'viewer', ['view']]]));
const nobody = rightsIndex(rightsDoc(false, []));
const D = (ctl, rights, roState = null) => decide({ safe: false, perm: null, zone: null, block: null, ...ctl }, { rights, ro: roState });

check('undeclared control is denied', D({}, admin), { ok: false, reason: 'This control declares no permission' });
check('safe control allowed', D({ safe: true }, nobody), { ok: true, reason: '' });
check('safe control on standby', D({ safe: true }, nobody, ro), { ok: true, reason: '' });
check('rights not loaded yet', D({ perm: 'server_admin' }, null).ok, false);
check('admin server_admin', D({ perm: 'server_admin' }, admin).ok, true);
check('user server_admin denied', D({ perm: 'server_admin' }, editor), { ok: false, reason: 'Not allowed: Server admin (administrators only)' });
check('root password', D({ perm: 'change_own_password' }, admin).reason, 'Not allowed: Change own password (the root password is set in the configuration file)');
check('editor edits records', D({ perm: 'edit_records', zone: 'a.test' }, editor).ok, true);
check('viewer cannot edit', D({ perm: 'edit_records', zone: 'b.test' }, editor), { ok: false, reason: 'Not allowed: Add, change and delete records needs the editor role on b.test; you are viewer' });
check('non-member cannot edit', D({ perm: 'edit_records', zone: 'c.test' }, editor).reason, 'Not allowed: Add, change and delete records needs the editor role on c.test; you are not a member');
check('editor cannot delete zone', D({ perm: 'delete_zone', zone: 'a.test' }, editor).ok, false);
check('zone perm without zone', D({ perm: 'edit_records' }, admin).ok, false);
check('any zone (*): admin', D({ perm: 'import', zone: '*' }, admin).ok, true);
check('any zone (*): editor', D({ perm: 'import', zone: '*' }, editor), { ok: false, reason: 'Not allowed: Import records needs the owner role on a zone' });
check('unknown permission', D({ perm: 'edit_record', zone: 'a.test' }, admin), { ok: false, reason: 'Unknown permission "edit_record"' });
check('standby denies a write', D({ perm: 'server_admin' }, admin, ro), { ok: false, reason: roReason(ro) });
check('standby allows a declared standby-safe write', D({ perm: 'server_admin', safe: true }, admin, ro).ok, true);
check('standby-safe still needs the permission', D({ perm: 'server_admin', safe: true }, editor, ro).ok, false);
check('own sessions on standby', D({ perm: 'manage_own_sessions', safe: true }, nobody, ro).ok, true);
check('state block', D({ perm: 'server_admin', block: 'You cannot delete your own account' }, admin), { ok: false, reason: 'You cannot delete your own account' });
check('state block on a safe control', D({ safe: true, block: 'Checking…' }, admin), { ok: false, reason: 'Checking…' });
check('permission reason before state', D({ perm: 'server_admin', block: 'x' }, editor).reason, 'Not allowed: Server admin (administrators only)');

console.log(fails ? `${fails} FAILED` : 'all passed'); process.exit(fails ? 1 : 0);

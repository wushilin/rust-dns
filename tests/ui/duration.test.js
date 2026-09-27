// Tests the console's duration parser exactly as shipped: the code between the
// DURATION-BEGIN / DURATION-END markers in src/ui/index.html.
//   node tests/ui/duration.test.js
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '../../src/ui/index.html'), 'utf8');
const src = html.slice(html.indexOf('/*DURATION-BEGIN*/'), html.indexOf('/*DURATION-END*/'));
if (!src) throw new Error('duration markers not found in index.html');
const { parseDuration, formatDuration } = new Function(`${src}; return { parseDuration, formatDuration };`)();
let fails = 0;
const ok = (input, want) => { try { const got = parseDuration(input); if (got !== want) { fails++; console.log(`FAIL ${input}: got ${got}, want ${want}`); } else console.log(`ok   ${input.padEnd(12)} = ${got}s`); } catch (e) { fails++; console.log(`FAIL ${input}: threw ${e.message}`); } };
const bad = (input, fragment) => { try { const got = parseDuration(input); fails++; console.log(`FAIL ${input}: accepted as ${got}`); } catch (e) { if (!e.message.includes(fragment)) { fails++; console.log(`FAIL ${input}: message "${e.message}" lacks "${fragment}"`); } else console.log(`ok   ${input.padEnd(12)} rejected: ${e.message}`); } };
ok('1m', 60); ok('1h', 3600); ok('1d', 86400); ok('45s', 45);
ok('6d12h14s', 6 * 86400 + 12 * 3600 + 14); ok('1d1h1m1s', 90061); ok('2h30m', 9000); ok('1D2H', 93600); ok('100d', 8640000);
bad('5s5s', 'more than once'); bad('5s6m', 'largest to smallest'); bad('1h1d', 'largest to smallest'); bad('1w', 'unknown unit "w"');
bad('10', 'needs a unit'); bad('1h 30m', 'no spaces'); bad('0s', 'longer than 0s'); bad('0d0h', 'longer than 0s'); bad('abc', 'unexpected');
bad('1h-2m', 'unexpected'); bad('h1', 'unexpected'); bad('1ms', 'unknown unit "ms"'); bad('', 'empty'); bad('40000d', 'at most 100 years');
for (const [n, w] of [[59, '59s'], [90, '1m30s'], [3600, '1h'], [93784, '1d2h'], [0, '0s']]) { const g = formatDuration(n); if (g !== w) { fails++; console.log(`FAIL format ${n}: ${g}`); } else console.log(`ok   format ${n} = ${g}`); }
for (const [n, parts, w] of [[561614, 4, '6d12h14s'], [561614, 2, '6d12h'], [86414, 2, '1d'], [86414, 4, '1d14s'], [3599, 2, '59m59s']]) { const g = formatDuration(n, parts); if (g !== w) { fails++; console.log(`FAIL format ${n}/${parts}: ${g}, want ${w}`); } else console.log(`ok   format ${n} (${parts} parts) = ${g}`); }
if (formatDuration(563654, 4) !== '6d12h34m14s') { fails++; console.log('FAIL format 4 parts'); } else console.log('ok   format 563654 (4 parts) = 6d12h34m14s');
console.log(fails ? `${fails} FAILED` : 'all passed'); process.exit(fails ? 1 : 0);

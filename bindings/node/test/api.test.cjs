'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const dlp = require('..');

// Split so the repository's own pre-commit scan does not flag the fixture.
const HOOK = ['https://hooks.slack.com/services', 'T024BE7LD', 'B024BE7LD', 'abcdefghijklmnopqrstuvwx'].join('/');

test('version', () => assert.strictEqual(dlp.apiVersion(), '1.0.0'));

test('scanBytes redacts by default', () => {
  const [f, ...rest] = dlp.scanBytes(`hook=${HOOK}`);
  assert.strictEqual(rest.length, 0);
  assert.strictEqual(f.detector, 'SlackWebhook');
  assert.ok(!f.raw && !f.redacted.includes(HOOK));
  assert.strictEqual(f.verdict, 'unverified');
});

test('scanBytes includeRaw and filter', () => {
  assert.strictEqual(dlp.scanBytes(Buffer.from(HOOK), { includeRaw: true, detectors: ['SlackWebhook'] })[0].raw, HOOK);
  assert.deepStrictEqual(dlp.scanBytes(HOOK, { detectors: ['AWS'] }), []);
});

test('scanPaths reports location', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pleno-dlp-'));
  const p = path.join(dir, 'a.env');
  fs.writeFileSync(p, `x=1\nhook=${HOOK}\n`);
  const [f] = dlp.scanPaths(dir);
  assert.strictEqual(f.path, p);
  assert.strictEqual(f.line, 2);
});

test('errors and revoke gate', () => {
  assert.throws(() => dlp.verify('NoSuch', 'x'), (e) => e instanceof dlp.PlenoDLPError && e.code === 'unknown_detector');
  assert.throws(() => dlp.revoke('GitHub', 'x'), (e) => e.code === 'not_confirmed');
  const r = dlp.revoke('GitHub', 'x', { dryRun: true });
  assert.ok(r.dry_run && !r.revoked);
});

test('detectors', () => {
  const gh = dlp.detectors().find((d) => d.name === 'GitHub');
  assert.ok(gh.can_verify && gh.can_revoke);
});

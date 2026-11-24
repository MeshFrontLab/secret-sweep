import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText, redact, globToRegExp, parseIgnore, isIgnored, isBinary } from '../src/scan.js';
import { entropy, isPlaceholder } from '../src/rules.js';

// Fake secrets are assembled at runtime so this file never contains a
// realistic-looking token (keeps GitHub push protection and our own scan quiet).
const rand = (n, chars = 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz') => {
  let s = '';
  for (let i = 0; i < n; i++) s += chars[(i * 7 + 3) % chars.length];
  return s;
};
const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HEX = '0123456789abcdef';

const cases = [
  ['github-token', 'gh' + 'p_' + rand(36)],
  ['github-fine-grained-pat', 'github' + '_pat_' + rand(60)],
  ['anthropic-key', 'sk-' + 'ant-api03-' + rand(40)],
  ['openai-key', 'sk-' + 'proj-' + rand(40)],
  ['aws-access-key-id', 'AK' + 'IA' + rand(16, UP)],
  ['google-api-key', 'AI' + 'za' + rand(35)],
  ['slack-token', 'xo' + 'xb-' + rand(24)],
  ['stripe-live-key', 'sk' + '_live_' + rand(24)],
  ['npm-token', 'np' + 'm_' + rand(36)],
  ['huggingface-token', 'h' + 'f_' + rand(34)],
  ['twilio-api-key', 'S' + 'K' + rand(32, HEX)],
  ['private-key', '-----BEGIN RSA ' + 'PRIVATE KEY-----'],
  ['jwt', 'ey' + 'J' + rand(20) + '.ey' + 'J' + rand(20) + '.' + rand(20)],
];

for (const [rule, secret] of cases) {
  test(`detects ${rule}`, () => {
    const found = scanText(`const value = "${secret}";`);
    assert.equal(found.length, 1, JSON.stringify(found));
    assert.equal(found[0].rule, rule);
    assert.equal(found[0].line, 1);
  });
}

test('never reports the raw secret', () => {
  const secret = 'gh' + 'p_' + rand(36);
  const [f] = scanText(`token: ${secret}`);
  assert.ok(!JSON.stringify(f).includes(secret));
  assert.equal(f.match, redact(secret));
  assert.match(f.match, /^ghp_\*+$/);
});

test('reports correct line and column', () => {
  const secret = 'AK' + 'IA' + rand(16, UP);
  const [f] = scanText(`line one\n\n   key=${secret}`);
  assert.equal(f.line, 3);
  assert.equal(f.column, 8);
});

test('password in connection URL, but not placeholders', () => {
  const url = 'postgres://app:' + 'Zq8' + 'vT2mPx@db.internal:5432/main';
  assert.equal(scanText(url)[0].rule, 'url-with-password');
  assert.equal(scanText('postgres://user:password@localhost/db').length, 0);
  assert.equal(scanText('postgres://user:${DB_PASS}@localhost/db').length, 0);
  assert.equal(scanText('redis://default:<your-password>@host:6379').length, 0);
});

test('generic hard-coded password is a warning; placeholders are not', () => {
  const [f] = scanText(`const password = "${'Tr0ub4' + 'dor&3xyz'}";`);
  assert.equal(f.rule, 'generic-secret');
  assert.equal(f.severity, 'warning');
  assert.equal(scanText('password = "changeme123"').length, 0);
  assert.equal(scanText('api_key: "your-api-key-here"').length, 0);
  assert.equal(scanText('password = "aaaaaaaaaaaa"').length, 0);
});

test('.env files: secret values flagged, example files ignored', () => {
  const line = 'DB_PASSWORD=' + 'k9Xv' + '2pLmQ7';
  assert.equal(scanText(line, { file: '.env' })[0].rule, 'dotenv-secret');
  assert.equal(scanText(line, { file: 'config/.env.production' })[0].rule, 'dotenv-secret');
  assert.equal(scanText(line, { file: '.env.example' }).length, 0);
  assert.equal(scanText('API_KEY=your_key_here', { file: '.env' }).length, 0);
});

test('one finding per secret even when several rules match', () => {
  const secret = 'sk-' + 'proj-' + rand(40);
  const found = scanText(`api_key = "${secret}"`);
  assert.equal(found.length, 1);
  assert.equal(found[0].rule, 'openai-key');
});

test('inline ignore comments', () => {
  const secret = 'gh' + 'p_' + rand(36);
  assert.equal(scanText(`x = "${secret}" // secret-sweep:ignore`).length, 0);
  assert.equal(scanText(`# secret-sweep:ignore-next-line\nx = "${secret}"`).length, 0);
  assert.equal(scanText(`# secret-sweep:ignore-next-line\nok\nx = "${secret}"`).length, 1);
});

test('ordinary code is clean', () => {
  const code = [
    'import { readFileSync } from "node:fs";',
    'const token = process.env.GITHUB_TOKEN;',
    'const sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";',
    'const url = "https://example.com/api?page=2";',
    'password: "${{ secrets.DB_PASSWORD }}"',
    '"integrity": "sha512-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz==",',
  ].join('\n');
  assert.deepEqual(scanText(code), []);
});

test('glob patterns behave like .gitignore', () => {
  assert.ok(globToRegExp('*.min.js').test('a/b/app.min.js'));
  assert.ok(globToRegExp('fixtures/').test('test/fixtures/x.txt'));
  assert.ok(!globToRegExp('fixtures/').test('test/fixtures2/x.txt'));
  assert.ok(globToRegExp('fixtures/').test('fixtures/x.txt'));
  assert.ok(globToRegExp('**/fixtures/**').test('test/fixtures/x.txt'));
  assert.ok(globToRegExp('/docs').test('docs/a.md'));
  assert.ok(!globToRegExp('/docs').test('src/docs/a.md'));
  const pats = parseIgnore('# comment\n*.snap\n!keep.snap\n');
  assert.ok(isIgnored('a/b.snap', pats));
  assert.ok(!isIgnored('keep.snap', pats));
  assert.ok(!isIgnored('a.js', pats));
});

test('helpers', () => {
  assert.ok(isBinary(Buffer.from([0x89, 0x50, 0x00, 0x01])));
  assert.ok(!isBinary(Buffer.from('hello')));
  assert.ok(entropy('aaaa') === 0);
  assert.ok(entropy('a1B2c3D4') > 2.5);
  assert.ok(isPlaceholder('${TOKEN}'));
  assert.ok(isPlaceholder('<api-key>'));
  assert.ok(!isPlaceholder('k9Xv2pLmQ7'));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'secret-sweep.js');
const run = (args, cwd) => spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
const TOKEN = 'gh' + 'p_' + 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYzaB3d';

function tmp() {
  const dir = mkdtempSync(join(tmpdir(), 'secret-sweep-'));
  return { dir, done: () => rmSync(dir, { recursive: true, force: true }) };
}

const hasGit = spawnSync('git', ['--version']).status === 0;
function gitInit(dir) {
  const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q');
  g('config', 'user.email', 'test@example.com');
  g('config', 'user.name', 'test');
  g('config', 'commit.gpgsign', 'false');
  return g;
}

test('clean folder exits 0', () => {
  const t = tmp();
  writeFileSync(join(t.dir, 'a.js'), 'console.log("hi")\n');
  const r = run(['--no-git', '.'], t.dir);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /no secrets found \(1 file scanned\)/);
  t.done();
});

test('secret exits 1 and prints a redacted location', () => {
  const t = tmp();
  mkdirSync(join(t.dir, 'src'));
  writeFileSync(join(t.dir, 'src', 'config.js'), `\nexport const token = "${TOKEN}";\n`);
  const r = run(['--no-git'], t.dir);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /src\/config\.js:2:23 {2}error {4}GitHub token \(github-token\) {2}ghp_\*+/);
  assert.ok(!r.stdout.includes(TOKEN));
  t.done();
});

test('--json, --disable and .secretsweepignore', () => {
  const t = tmp();
  writeFileSync(join(t.dir, 'a.txt'), TOKEN);
  let r = run(['--no-git', '--json'], t.dir);
  const out = JSON.parse(r.stdout);
  assert.equal(out.errors, 1);
  assert.equal(out.findings[0].rule, 'github-token');

  r = run(['--no-git', '--disable', 'github-token'], t.dir);
  assert.equal(r.status, 0);

  writeFileSync(join(t.dir, '.secretsweepignore'), 'a.txt\n');
  r = run(['--no-git'], t.dir);
  assert.equal(r.status, 0);
  t.done();
});

test('skips node_modules and binary files', () => {
  const t = tmp();
  mkdirSync(join(t.dir, 'node_modules'));
  writeFileSync(join(t.dir, 'node_modules', 'x.js'), TOKEN);
  writeFileSync(join(t.dir, 'img.bin'), Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(TOKEN)]));
  const r = run(['--no-git'], t.dir);
  assert.equal(r.status, 0, r.stdout);
  t.done();
});

test('usage errors exit 2', () => {
  assert.equal(run(['--nope']).status, 2);
  assert.equal(run(['--disable', 'not-a-rule']).status, 2);
  assert.equal(run(['--no-git', 'does-not-exist']).status, 2);
});

test('--list-rules and --version', () => {
  assert.match(run(['--list-rules']).stdout, /github-token/);
  assert.match(run(['--version']).stdout, /^\d+\.\d+\.\d+/);
});

test('respects .gitignore inside a git repo', { skip: !hasGit }, () => {
  const t = tmp();
  gitInit(t.dir);
  writeFileSync(join(t.dir, '.gitignore'), '.env\n');
  writeFileSync(join(t.dir, '.env'), `TOKEN=${TOKEN}\n`);
  writeFileSync(join(t.dir, 'ok.js'), 'ok\n');
  assert.equal(run([], t.dir).status, 0);
  assert.equal(run(['--no-git'], t.dir).status, 1);
  t.done();
});

test('--staged scans the index and install-hook blocks bad commits', { skip: !hasGit }, () => {
  const t = tmp();
  const g = gitInit(t.dir);
  writeFileSync(join(t.dir, 'safe.js'), 'ok\n');
  g('add', 'safe.js');
  assert.equal(run(['--staged'], t.dir).status, 0);

  writeFileSync(join(t.dir, 'leak.js'), `const t = "${TOKEN}";\n`);
  assert.equal(run(['--staged'], t.dir).status, 0, 'unstaged files are not checked');
  g('add', 'leak.js');
  const r = run(['--staged'], t.dir);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /leak\.js:1/);

  const hook = run(['install-hook'], t.dir);
  assert.equal(hook.status, 0, hook.stderr);
  assert.ok(existsSync(join(t.dir, '.git', 'hooks', 'pre-commit')));
  assert.match(readFileSync(join(t.dir, '.git', 'hooks', 'pre-commit'), 'utf8'), /--staged/);
  assert.equal(run(['install-hook'], t.dir).status, 2, 'refuses to overwrite without --force');
  assert.equal(run(['install-hook', '--force'], t.dir).status, 0);
  t.done();
});

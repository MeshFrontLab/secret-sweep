#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RULES } from '../src/rules.js';
import { scanPaths, scanStaged, gitRoot } from '../src/scan.js';

const pkg = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8'));

const HELP = `secret-sweep ${pkg.version} - find leaked API keys, tokens and passwords before they ship

Usage:
  secret-sweep [paths...]        scan files and folders (default: current folder)
  secret-sweep --staged          scan only what is staged for the next commit
  secret-sweep install-hook      add a git pre-commit hook that runs --staged

Options:
  --staged              scan the git index (staged changes) instead of files on disk
  --no-git              walk folders directly instead of asking git (includes ignored files)
  --disable <ids>       comma-separated rule ids to turn off
  --strict              exit with code 1 on warnings too
  --json                print findings as JSON
  --max-size <kb>       skip files larger than this (default 2048)
  --list-rules          show all rules
  --force               (install-hook) replace an existing pre-commit hook
  -q, --quiet           only print problems
  -h, --help            show this help
  -v, --version         show version

Ignore a line by adding the comment  secret-sweep:ignore  to it, or put
gitignore-style patterns in a .secretsweepignore file.

Exit codes: 0 = clean, 1 = secrets found, 2 = usage or runtime error.`;

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = paint(31);
const yellow = paint(33);
const green = paint(32);
const dim = paint(2);

function fail(msg) {
  console.error(`secret-sweep: ${msg}`);
  process.exit(2);
}

let args;
try {
  args = parseArgs({
    allowPositionals: true,
    options: {
      staged: { type: 'boolean' },
      'no-git': { type: 'boolean' },
      disable: { type: 'string' },
      strict: { type: 'boolean' },
      json: { type: 'boolean' },
      'max-size': { type: 'string' },
      'list-rules': { type: 'boolean' },
      force: { type: 'boolean' },
      quiet: { type: 'boolean', short: 'q' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
} catch (e) {
  fail(`${e.message}\nRun "secret-sweep --help" for usage.`);
}
const { values: opt, positionals } = args;

if (opt.help) { console.log(HELP); process.exit(0); }
if (opt.version) { console.log(pkg.version); process.exit(0); }
if (opt['list-rules']) {
  for (const r of RULES) console.log(`${r.id.padEnd(26)} ${r.severity.padEnd(8)} ${r.description}`);
  process.exit(0);
}

if (positionals[0] === 'install-hook') installHook();

const disabled = new Set((opt.disable || '').split(',').map((s) => s.trim()).filter(Boolean));
for (const id of disabled) if (!RULES.some((r) => r.id === id)) fail(`unknown rule "${id}" (see --list-rules)`);
const rules = RULES.filter((r) => !disabled.has(r.id));

let maxBytes;
if (opt['max-size'] !== undefined) {
  const kb = Number(opt['max-size']);
  if (!Number.isFinite(kb) || kb <= 0) fail('--max-size must be a positive number of kilobytes');
  maxBytes = kb * 1024;
}

let result;
try {
  result = opt.staged
    ? scanStaged({ rules, maxBytes })
    : scanPaths(positionals.length ? positionals : ['.'], { rules, maxBytes, useGit: !opt['no-git'] });
} catch (e) {
  fail(e.code === 'ENOENT' ? `no such file or folder: ${e.path}` : e.message);
}

const { findings, scanned } = result;
const errors = findings.filter((f) => f.severity === 'error').length;
const warnings = findings.length - errors;

if (opt.json) {
  console.log(JSON.stringify({ scanned, errors, warnings, findings }, null, 2));
} else {
  for (const f of findings) {
    const sev = f.severity === 'error' ? red('error  ') : yellow('warning');
    console.log(`${f.file}:${f.line}:${f.column}  ${sev}  ${f.description} ${dim(`(${f.rule})`)}  ${dim(f.match)}`);
  }
  const files = `${scanned} file${scanned === 1 ? '' : 's'} scanned`;
  if (findings.length) {
    console.log(
      `\nsecret-sweep: ${findings.length} problem${findings.length === 1 ? '' : 's'} ` +
        `(${errors} error${errors === 1 ? '' : 's'}, ${warnings} warning${warnings === 1 ? '' : 's'}), ${files}`,
    );
    if (errors) console.log(dim('Remove the secret, rotate it (it may already be exposed), or mark a false alarm with "secret-sweep:ignore".'));
  } else if (!opt.quiet) {
    console.log(green(`secret-sweep: no secrets found (${files})`));
  }
}

process.exit(errors || (opt.strict && warnings) ? 1 : 0);

function installHook() {
  const root = gitRoot(process.cwd());
  if (!root) fail('not inside a git repository');
  let hooksDir = execFileSync('git', ['rev-parse', '--git-path', 'hooks'], { cwd: process.cwd(), encoding: 'utf8' }).trim();
  hooksDir = resolve(process.cwd(), hooksDir);
  mkdirSync(hooksDir, { recursive: true });
  const hook = join(hooksDir, 'pre-commit');
  if (existsSync(hook) && !opt.force) {
    fail(`${hook} already exists. Re-run with --force to replace it, or add "secret-sweep --staged" to it yourself.`);
  }
  writeFileSync(
    hook,
    `#!/bin/sh
# Installed by secret-sweep: blocks commits that contain secrets.
if command -v secret-sweep >/dev/null 2>&1; then
  exec secret-sweep --staged --quiet
elif [ -x ./node_modules/.bin/secret-sweep ]; then
  exec ./node_modules/.bin/secret-sweep --staged --quiet
else
  echo "secret-sweep is not installed; see https://github.com/MeshFrontLab/secret-sweep" >&2
  exit 1
fi
`,
  );
  try { chmodSync(hook, 0o755); } catch { /* Windows: git runs hooks through sh anyway */ }
  console.log(`secret-sweep: pre-commit hook installed at ${hook}`);
  process.exit(0);
}

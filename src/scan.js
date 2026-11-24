import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { RULES } from './rules.js';

export const DEFAULT_SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.nuxt', '.cache',
  'vendor', '__pycache__', '.venv', 'venv', 'target', '.terraform',
]);
export const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

const IGNORE_LINE = /secret-sweep[:-]ignore(?!-next-line)/;
const IGNORE_NEXT = /secret-sweep[:-]ignore-next-line/;

const compiled = new WeakMap();
function globalRe(rule) {
  let re = compiled.get(rule);
  if (!re) {
    re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
    compiled.set(rule, re);
  }
  return re;
}

export function redact(value) {
  // Long tokens: keep the well-known prefix (e.g. "ghp_") so you can tell what it is.
  // Short values (passwords): show nothing at all.
  if (value.length < 20) return '*'.repeat(Math.min(12, value.length));
  return value.slice(0, 4) + '*'.repeat(12);
}

const toPosix = (p) => p.split(sep).join('/');

/** Scan one string. Returns a list of findings (never the raw secret). */
export function scanText(text, { file = '<text>', rules = RULES } = {}) {
  const findings = [];
  const posixFile = toPosix(file);
  const active = rules.filter((r) => !r.files || r.files.test(posixFile));
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (IGNORE_LINE.test(line)) continue;
    if (i > 0 && IGNORE_NEXT.test(lines[i - 1])) continue;
    const taken = [];
    for (const rule of active) {
      for (const m of line.matchAll(globalRe(rule))) {
        const secret = m.groups?.secret ?? m[0];
        const [start, end] = m.indices?.groups?.secret ?? [m.index, m.index + m[0].length];
        if (rule.skip?.(secret, line)) continue;
        if (taken.some(([s, e]) => start < e && end > s)) continue;
        taken.push([start, end]);
        findings.push({
          file: posixFile,
          line: i + 1,
          column: start + 1,
          rule: rule.id,
          severity: rule.severity,
          description: rule.description,
          match: rule.noRedact ? secret : redact(secret),
        });
      }
    }
  }
  return findings;
}

/** True when the buffer looks like a binary file (has a NUL byte near the start). */
export function isBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

// --- ignore file (.secretsweepignore), gitignore-style globs -----------------

export function globToRegExp(pattern) {
  let p = pattern.trim().replace(/\\/g, '/');
  if (p.endsWith('/')) p = p.slice(0, -1);
  const anchored = p.includes('/');
  if (p.startsWith('/')) p = p.slice(1);
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*') {
      if (p[i + 1] === '*') {
        i++;
        if (p[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp((anchored ? '^' : '^(?:.*/)?') + re + '(?:/.*)?$');
}

export function loadIgnore(root) {
  const file = join(root, '.secretsweepignore');
  if (!existsSync(file)) return [];
  return parseIgnore(readFileSync(file, 'utf8'));
}

export function parseIgnore(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => (l.startsWith('!') ? { negate: true, re: globToRegExp(l.slice(1)) } : { negate: false, re: globToRegExp(l) }));
}

export function isIgnored(path, patterns) {
  let ignored = false;
  for (const { negate, re } of patterns) if (re.test(path)) ignored = !negate;
  return ignored;
}

// --- collecting files --------------------------------------------------------

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'buffer', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 256 * 1024 * 1024 });
}

export function gitRoot(dir) {
  try {
    return git(['rev-parse', '--show-toplevel'], dir).toString('utf8').trim();
  } catch {
    return null;
  }
}

function walk(dir, out, skipDirs) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!skipDirs.has(entry.name)) walk(p, out, skipDirs);
    } else if (entry.isFile()) out.push(p);
  }
}

/** List files under `target` (absolute paths). Uses git when possible so .gitignore is respected. */
export function listFiles(target, { useGit = true, skipDirs = DEFAULT_SKIP_DIRS } = {}) {
  const abs = resolve(target);
  const st = statSync(abs);
  if (st.isFile()) return [abs];
  if (useGit && gitRoot(abs)) {
    const out = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard'], abs).toString('utf8');
    return out
      .split('\0')
      .filter((f) => f && !f.split('/').slice(0, -1).some((part) => skipDirs.has(part)))
      .map((f) => join(abs, f))
      .filter((f) => existsSync(f));
  }
  const files = [];
  walk(abs, files, skipDirs);
  return files;
}

/**
 * Scan files on disk.
 * @returns {{ findings: object[], scanned: number, skipped: number }}
 */
export function scanPaths(targets, { cwd = process.cwd(), useGit = true, maxBytes = DEFAULT_MAX_BYTES, rules = RULES, ignore } = {}) {
  const patterns = ignore ?? loadIgnore(cwd);
  const findings = [];
  let scanned = 0;
  let skipped = 0;
  const seen = new Set();
  for (const t of targets) {
    for (const abs of listFiles(resolve(cwd, t), { useGit })) {
      if (seen.has(abs)) continue;
      seen.add(abs);
      const rel = toPosix(relative(cwd, abs)) || abs;
      if (isIgnored(rel, patterns)) { skipped++; continue; }
      let buf;
      try {
        if (statSync(abs).size > maxBytes) { skipped++; continue; }
        buf = readFileSync(abs);
      } catch {
        skipped++;
        continue;
      }
      if (isBinary(buf)) { skipped++; continue; }
      scanned++;
      findings.push(...scanText(buf.toString('utf8'), { file: rel, rules }));
    }
  }
  return { findings, scanned, skipped };
}

/** Scan what is staged for the next commit (the index), not the working copy. */
export function scanStaged({ cwd = process.cwd(), maxBytes = DEFAULT_MAX_BYTES, rules = RULES, ignore } = {}) {
  const root = gitRoot(cwd);
  if (!root) throw new Error('not inside a git repository (needed for --staged)');
  const patterns = ignore ?? loadIgnore(root);
  const names = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], root)
    .toString('utf8')
    .split('\0')
    .filter(Boolean);
  const findings = [];
  let scanned = 0;
  let skipped = 0;
  for (const name of names) {
    if (isIgnored(name, patterns)) { skipped++; continue; }
    let buf;
    try {
      buf = git(['show', `:${name}`], root);
    } catch {
      skipped++;
      continue;
    }
    if (buf.length > maxBytes || isBinary(buf)) { skipped++; continue; }
    scanned++;
    findings.push(...scanText(buf.toString('utf8'), { file: name, rules }));
  }
  return { findings, scanned, skipped };
}

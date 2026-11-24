// Detection rules. Each rule is a regular expression with a named group `secret`
// (the part that gets reported, redacted). Rules are checked in order; when two
// rules match the same text, only the first one is reported.

// Values that are obviously placeholders, not real secrets.
const PLACEHOLDER =
  /^(?:\$\{?[\w.:-]*\}?|<[^>]*>|\{\{[^}]*\}\}|%\w+%|\*+|x+|\.+|-+|(?:your|my|example|sample|dummy|fake|test|changeme|change[_-]?me|placeholder|redacted|replace[_-]?me|insert|enter|xxx+|todo|none|null|undefined|empty|secret|password|passwd|pass|token|api[_-]?key)(?:[\w-]*)?)$/i;

export function isPlaceholder(value) {
  return PLACEHOLDER.test(value) || /process\.env|os\.environ|getenv|import\.meta\.env/.test(value);
}

// Shannon entropy in bits per character. Real secrets are random; words are not.
export function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let e = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

const SECRET_WORDS =
  '(?:password|passwd|pwd|secret|client[_-]?secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|token)';

const DOTENV_FILE = /(^|\/)\.env(?:\.(?!example$|sample$|template$|dist$|defaults$|schema$)[\w.-]+)?$/i;

export const RULES = [
  {
    id: 'private-key',
    description: 'Private key block',
    severity: 'error',
    re: /(?<secret>-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)/d,
    noRedact: true,
  },
  {
    id: 'github-token',
    description: 'GitHub token',
    severity: 'error',
    re: /(?<![A-Za-z0-9_])(?<secret>gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_])/d,
  },
  {
    id: 'github-fine-grained-pat',
    description: 'GitHub fine-grained personal access token',
    severity: 'error',
    re: /(?<![A-Za-z0-9_])(?<secret>github_pat_[A-Za-z0-9_]{50,255})/d,
  },
  {
    id: 'anthropic-key',
    description: 'Anthropic API key',
    severity: 'error',
    re: /(?<![A-Za-z0-9])(?<secret>sk-ant-[A-Za-z0-9_-]{20,})/d,
  },
  {
    id: 'openai-key',
    description: 'OpenAI API key',
    severity: 'error',
    re: /(?<![A-Za-z0-9])(?<secret>sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})/d,
  },
  {
    id: 'aws-access-key-id',
    description: 'AWS access key ID',
    severity: 'error',
    re: /(?<![A-Z0-9])(?<secret>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![A-Z0-9])/d,
  },
  {
    id: 'aws-secret-access-key',
    description: 'AWS secret access key',
    severity: 'error',
    re: /aws_?secret_?access_?key["']?\s*[:=]\s*["']?(?<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/di,
  },
  {
    id: 'google-api-key',
    description: 'Google API key',
    severity: 'error',
    re: /(?<secret>AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/d,
  },
  {
    id: 'slack-token',
    description: 'Slack token',
    severity: 'error',
    re: /(?<![A-Za-z0-9])(?<secret>xox[abposr]-[0-9A-Za-z-]{10,})/d,
  },
  {
    id: 'slack-webhook',
    description: 'Slack incoming webhook URL',
    severity: 'error',
    re: /(?<secret>https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,})/d,
  },
  {
    id: 'discord-webhook',
    description: 'Discord webhook URL',
    severity: 'error',
    re: /(?<secret>https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,})/d,
  },
  {
    id: 'stripe-live-key',
    description: 'Stripe live secret key',
    severity: 'error',
    re: /(?<![A-Za-z0-9])(?<secret>(?:sk|rk)_live_[0-9A-Za-z]{20,})/d,
  },
  {
    id: 'npm-token',
    description: 'npm access token',
    severity: 'error',
    re: /(?<![A-Za-z0-9_])(?<secret>npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])/d,
  },
  {
    id: 'huggingface-token',
    description: 'Hugging Face token',
    severity: 'error',
    re: /(?<![A-Za-z0-9_])(?<secret>hf_[A-Za-z0-9]{34,})(?![A-Za-z0-9])/d,
  },
  {
    id: 'sendgrid-key',
    description: 'SendGrid API key',
    severity: 'error',
    re: /(?<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})/d,
  },
  {
    id: 'twilio-api-key',
    description: 'Twilio API key',
    severity: 'error',
    re: /(?<![A-Za-z0-9])(?<secret>SK[0-9a-f]{32})(?![A-Za-z0-9])/d,
  },
  {
    id: 'url-with-password',
    description: 'Password inside a connection URL',
    severity: 'error',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"]+:(?<secret>[^\s:@/'"]{3,})@[^\s'"]+/di,
    skip: (secret) => isPlaceholder(secret),
  },
  {
    id: 'jwt',
    description: 'JSON Web Token',
    severity: 'warning',
    re: /(?<![A-Za-z0-9_-])(?<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/d,
  },
  {
    id: 'dotenv-secret',
    description: 'Secret value in a committed .env file',
    severity: 'error',
    files: DOTENV_FILE,
    re: new RegExp(
      `^\\s*(?:export\\s+)?[A-Za-z0-9_]*${SECRET_WORDS}[A-Za-z0-9_]*\\s*=\\s*["']?(?<secret>[^"'\\s#]{8,})`,
      'di',
    ),
    skip: (secret) => isPlaceholder(secret),
  },
  {
    id: 'generic-secret',
    description: 'Hard-coded password or key',
    severity: 'warning',
    re: new RegExp(
      `(?<![A-Za-z0-9])${SECRET_WORDS}["']?\\s*(?::|=|:=|=>)\\s*["'\`](?<secret>[^"'\`\\s]{8,})["'\`]`,
      'di',
    ),
    skip: (secret) => isPlaceholder(secret) || entropy(secret) < 2.5,
  },
];

export function ruleById(id) {
  return RULES.find((r) => r.id === id);
}

# secret-sweep

**Find leaked API keys, tokens and passwords before they reach GitHub.** One small command, zero dependencies, works as a git pre-commit hook or a CI step.

[![CI](https://github.com/MeshFrontLab/secret-sweep/actions/workflows/ci.yml/badge.svg)](https://github.com/MeshFrontLab/secret-sweep/actions/workflows/ci.yml)
![node](https://img.shields.io/badge/node-%3E%3D22-informational)
![dependencies](https://img.shields.io/badge/dependencies-0-success)
![license](https://img.shields.io/badge/license-MIT-blue)

- Catches GitHub, OpenAI, Anthropic, AWS, Google, Slack, Stripe, npm, Hugging Face, SendGrid and Twilio keys, private keys, passwords in database URLs, secrets in committed `.env` files and more.
- **Never prints the secret itself**: output shows only a short, masked prefix (`ghp_************`), so CI logs stay safe.
- Respects `.gitignore`, skips binaries, `node_modules` and big files.
- No network calls, no telemetry, no config needed.

## Install

Requires [Node.js](https://nodejs.org) 22 or newer.

```sh
# run once, without installing
npx --allow-git=all github:MeshFrontLab/secret-sweep

# or install the `secret-sweep` command globally
npm install -g --allow-git=all github:MeshFrontLab/secret-sweep

# or add it to a project
npm install --save-dev --allow-git=all github:MeshFrontLab/secret-sweep
```

`--allow-git=all` is needed on npm 12 and newer, which blocks installing straight from GitHub unless you allow it. Older npm versions accept it too. Prefer not to use it? Clone and install from the folder instead:

```sh
git clone https://github.com/MeshFrontLab/secret-sweep
npm install -g ./secret-sweep
```

## Usage

Scan the current folder:

```console
$ secret-sweep
src/config.js:3:17  error    AWS access key ID (aws-access-key-id)  AKIA************
src/config.js:4:17  error    GitHub token (github-token)  ghp_************
src/db.js:1:29  error    Password inside a connection URL (url-with-password)  ******
src/db.js:2:19  warning  Hard-coded password or key (generic-secret)  ************

secret-sweep: 4 problems (3 errors, 1 warning), 3 files scanned
Remove the secret, rotate it (it may already be exposed), or mark a false alarm with "secret-sweep:ignore".
```

```console
$ secret-sweep
secret-sweep: no secrets found (128 files scanned)
```

Other ways to run it:

```sh
secret-sweep src/ config/app.json   # scan specific files or folders
secret-sweep --staged               # scan only what you are about to commit
secret-sweep --json                 # machine-readable output
secret-sweep --strict               # fail on warnings too
secret-sweep --list-rules           # see every rule
```

| Option | What it does |
| --- | --- |
| `--staged` | Scan the staged version of files (what `git commit` would save). |
| `--no-git` | Walk folders directly, including files that `.gitignore` hides. |
| `--disable <ids>` | Turn off rules, e.g. `--disable jwt,generic-secret`. |
| `--strict` | Exit with code 1 on warnings as well as errors. |
| `--json` | Print `{ scanned, errors, warnings, findings[] }` as JSON. |
| `--max-size <kb>` | Skip files bigger than this (default 2048 KB). |
| `-q, --quiet` | Print nothing when everything is clean. |

**Exit codes:** `0` clean, `1` secrets found, `2` bad usage or an error.

### Block secrets on every commit

```sh
secret-sweep install-hook
```

This writes a `pre-commit` hook into the current repository. From then on, `git commit` stops if the staged changes contain a secret. Use `--force` to replace an existing hook.

Using the [pre-commit](https://pre-commit.com) framework instead? Add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/MeshFrontLab/secret-sweep
    rev: v0.1.0
    hooks:
      - id: secret-sweep
```

### Run in CI (GitHub Actions)

```yaml
- uses: actions/checkout@v5
- uses: actions/setup-node@v5
  with:
    node-version: 22
- run: npx --yes --allow-git=all github:MeshFrontLab/secret-sweep
```

## Configuration

There is nothing to configure for normal use. Two optional ways to silence false alarms:

**On one line**: add a `secret-sweep:ignore` comment to it, or `secret-sweep:ignore-next-line` on the line above:

```js
const exampleKey = 'AKIA...EXAMPLE'; // secret-sweep:ignore
```

**For whole files**: list gitignore-style patterns in a `.secretsweepignore` file at the root of the scan:

```gitignore
# test fixtures with fake keys
test/fixtures/
*.snap
!important.snap
```

## Rules

| Rule | Severity | Finds |
| --- | --- | --- |
| `private-key` | error | `-----BEGIN ... PRIVATE KEY-----` blocks |
| `github-token` | error | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens |
| `github-fine-grained-pat` | error | `github_pat_` tokens |
| `anthropic-key` | error | `sk-ant-` keys |
| `openai-key` | error | `sk-`, `sk-proj-` keys |
| `aws-access-key-id` | error | `AKIA...` / `ASIA...` key IDs |
| `aws-secret-access-key` | error | `aws_secret_access_key = ...` |
| `google-api-key` | error | `AIza...` keys |
| `slack-token` / `slack-webhook` | error | `xoxb-` tokens, `hooks.slack.com` URLs |
| `discord-webhook` | error | Discord webhook URLs |
| `stripe-live-key` | error | `sk_live_` / `rk_live_` keys |
| `npm-token` | error | `npm_` tokens |
| `huggingface-token` | error | `hf_` tokens |
| `sendgrid-key` | error | `SG.` keys |
| `twilio-api-key` | error | `SK` + 32 hex |
| `url-with-password` | error | `postgres://user:pass@host` and similar |
| `dotenv-secret` | error | real-looking passwords and keys in `.env` files (not `.env.example`) |
| `jwt` | warning | JSON Web Tokens |
| `generic-secret` | warning | `password = "..."`, `api_key: "..."` with random-looking values |

Obvious placeholders such as `changeme`, `your-api-key`, `<token>` and `${DB_PASSWORD}` are ignored.

## Use it from code

```js
import { scanText, scanPaths } from '@meshfrontlab/secret-sweep';

const findings = scanText(someString, { file: 'input.txt' });
const { findings: all, scanned } = scanPaths(['.']);
```

## Found a real secret?

Deleting it from the file is not enough: it is still in your git history and may already be copied. **Revoke or rotate the key first** with the service that issued it, then remove it from the code.

## Contributing

Issues and pull requests are welcome, especially new rules.

```sh
git clone https://github.com/MeshFrontLab/secret-sweep
cd secret-sweep
npm test
```

Please keep it dependency-free, add a test for every new rule, and build fake tokens in tests from pieces (`'gh' + 'p_' + ...`) so the repository itself never contains a realistic token.

## Licence

[MIT](LICENSE) © MESHFRONT LTD

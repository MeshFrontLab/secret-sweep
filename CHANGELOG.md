# Changelog

All notable changes to this project are documented here. This project follows [Semantic Versioning](https://semver.org).

## [0.1.0] - 2026-11-24

First release.

### Added

- `secret-sweep [paths...]` scans files and folders, respecting `.gitignore` inside git repositories.
- `--staged` mode that scans exactly what is about to be committed.
- `install-hook` command that adds a git pre-commit hook, plus a `.pre-commit-hooks.yaml` for the pre-commit framework.
- 20 rules covering GitHub, OpenAI, Anthropic, AWS, Google, Slack, Discord, Stripe, npm, Hugging Face, SendGrid and Twilio credentials, private keys, passwords in URLs, secrets in `.env` files, JWTs and hard-coded passwords.
- Masked output that never prints the full secret.
- `--json`, `--strict`, `--disable`, `--max-size`, `--quiet` and `--list-rules` options.
- Inline `secret-sweep:ignore` comments and a `.secretsweepignore` file.
- Small programmatic API (`scanText`, `scanPaths`, `scanStaged`).

[0.1.0]: https://github.com/MeshFrontLab/secret-sweep/releases/tag/v0.1.0

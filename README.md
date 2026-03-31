# publish-guard

> Pre-publish safety linter for npm packages. Blocks source maps, secrets, and raw source files from shipping to the registry.

Anthropic leaked their Claude Code source code to npm **twice** via an accidentally included `.map` file. A 59.8MB source map containing ~512,000 lines of TypeScript. The second time was March 31, 2026 — one year after the first incident.

**This tool would have caught it both times.**

## Quick Start — GitHub Action (recommended)

Add this to `.github/workflows/publish-guard.yml` in your repo:

```yaml
name: Publish Guard
on: [push, pull_request]

jobs:
  publish-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oliver-virt/publish-guard@v1
```

That's it. 3 lines in your CI pipeline. Every push gets scanned before anything ships.

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `directory` | `.` | Directory to scan |
| `allow-src` | `false` | Allow src/ directory without warning |

```yaml
# Example with options
- uses: oliver-virt/publish-guard@v1
  with:
    allow-src: true
    directory: ./packages/my-lib
```

## CLI Usage

Run directly with npx (no install needed):

```bash
npx publish-guard
```

Or add as a prepublish hook so it runs automatically every time:

```json
{
  "scripts": {
    "prepublishOnly": "npx publish-guard"
  }
}
```

## What it checks

| Rule | Severity | Description |
|------|----------|-------------|
| `source-maps` | error | `.map` files expose your full unminified source |
| `env-files` | error | `.env` files may contain API keys and secrets |
| `secrets-filename` | error | Files named `secret`, `credentials`, `api-key`, `.npmrc`, etc. |
| `secret-in-content` | error | Scans file contents for API keys (AWS, OpenAI, Anthropic, Stripe, GitHub, Slack, etc.) |
| `private-keys` | error | `.pem`, `.key`, `.p12` and other certificate/key files |
| `git-directory` | error | `.git/`, `.svn/` directories |
| `large-file-extreme` | error | Files over 20MB — almost certainly an accident |
| `package-too-large` | error | Total package over 20MB |
| `source-directory` | warn | Raw `src/` directory included (use `--allow-src` to skip) |
| `large-file` | warn | Files between 5–20MB |
| `config-files` | warn | Internal tooling configs (`.eslintrc`, `jest.config.js`, etc.) |
| `test-files` | warn | Test files (`.test.ts`, `.spec.js`, `__tests__/`) |
| `ide-files` | warn | IDE directories (`.vscode/`, `.idea/`) |

## Example output

```
publish-guard — pre-publish safety check
──────────────────────────────────────────────────
Package:  my-package@2.1.88
Size:     59.8MB
Scanning 6 files...

⚠  1 warning
   ▸ src/index.test.ts (5B)
     Test files are being published
     → Use the 'files' field in package.json or .npmignore to exclude tests.

✖  2 errors — publish blocked
   ▸ dist/cli.js.map (59.8MB)
     Source map files (.map) expose your full source code
     → Add '*.map' to .npmignore, or set sourceMap: false in your bundler config.
   ▸ .env (21B)
     Environment files may contain secrets
     → Add '.env*' to .npmignore.

──────────────────────────────────────────────────
Publish aborted. Fix the errors above before publishing.
```

## Options

```
--json         Output as JSON (for CI parsing)
--allow-src    Don't warn about src/ directory
-h, --help     Show help
-v, --version  Show version
```

## CI integration

`publish-guard` exits with code `1` on errors, so it blocks pipelines automatically.

```yaml
# GitLab CI
publish:
  script:
    - npx publish-guard
    - npm publish
```

## JSON output

Use `--json` for machine-readable output:

```bash
npx publish-guard --json
```

```json
{
  "package": { "name": "my-pkg", "version": "1.0.0", "size": 1234, "fileCount": 3 },
  "errors": [{ "file": "dist/app.js.map", "rule": "source-maps", "description": "..." }],
  "warnings": [],
  "passed": false
}
```

## How it works

Internally runs `npm pack --dry-run --json` to get the exact list of files npm would publish, then checks each file against safety rules and scans text file contents for secret patterns. No files are actually written or uploaded.

## Why this exists

There is no existing tool that does this. The current advice is "remember to check manually" or "use `npm pack --dry-run`" — which is exactly the kind of thing that fails under release pressure.

- `npm audit` scans for vulnerable **dependencies**, not what **you're** shipping
- `npm pack --dry-run` shows the file list but doesn't check for problems
- Snyk, Socket.dev — focused on consuming packages safely, not publishing them
- `.npmignore` — manual config, easy to forget (as demonstrated by a $10B AI lab, twice)

## License

MIT

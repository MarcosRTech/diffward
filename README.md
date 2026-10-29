# diffward

```text
██████╗ ██╗███████╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██║██╔════╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
██║  ██║██║█████╗  █████╗  ██║ █╗ ██║███████║██████╔╝██║  ██║
██║  ██║██║██╔══╝  ██╔══╝  ██║███╗██║██╔══██║██╔══██╗██║  ██║
██████╔╝██║██║     ██║     ╚███╔███╔╝██║  ██║██║  ██║██████╔╝
╚═════╝ ╚═╝╚═╝     ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**Security scanner for pull requests** — vulnerable dependencies, insecure code and outage-prone bad practices, scoped to the diff.

```console
$ diffward --diff origin/main

Security

 CRITICAL  js/sql-injection src/routes/users.ts:42:9
  SQL query built from dynamic strings (query()).
  │ return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
  fix: Use parameterized queries (placeholders such as ? or $1 with a values array) or a tagged-template SQL helper instead of concatenation/interpolation.

Vulnerable dependencies

 HIGH  lodash@4.17.20 npm · direct · production · package-lock.json:1187
  1 advisory (1 high) — upgrade to 4.17.21 or later
  fix: npm install lodash@^4.17.21
  · GHSA-35jh-r3h4-6jhm  high     Command Injection in lodash

Quality

 MEDIUM  js/http-no-timeout src/integrations/payments.ts:18:22
  Outbound HTTP call without a timeout (axios.post()).
  │ const res = await axios.post(`${PSP_URL}/charges`, body);
  fix: A slow partner keeps the request (and its socket) open indefinitely and piles up concurrent requests. Pass `timeout` (axios) or `signal: AbortSignal.timeout(ms)` (fetch), or set it once on the axios instance.

diffward: 1 security, 1 vulnerable package(s), 1 quality — fails the build: 1 code finding(s) and 1 package(s) (changed code; 14 file(s), 3 package(s) in 1 lockfile(s)).
$ echo $?
1
```

**diffward** is a free, zero-config security check for pull requests. It looks only at what the PR changes and reports three kinds of problems:

- **Vulnerable dependencies** — packages the PR adds or upgrades in a lockfile that have a known advisory (CVE/GHSA), checked against the free [OSV.dev](https://osv.dev) database, grouped by package with the command that fixes them.
- **Insecure code and configuration** — SQL/command/code injection, path traversal, SSRF, XSS, open CORS, sensitive data in logs, unsafe deserialization, weak crypto and disabled TLS in JavaScript/TypeScript and Python; secrets in any committed file (code, `.env`, YAML/JSON, shell, Dockerfiles, docs); script injection and unpinned actions in GitHub Actions workflows; containers running as root.
- **Bad practices that cause outages** — HTTP calls without a timeout, queries without a filter or limit, N+1 calls in loops, unhandled promises, swallowed errors and blocking calls in request handlers. Reported, but they only fail the build if you ask.

Old problems already on `main` don't block the PR; new ones do. Results come as readable text, Markdown (job summary / PR comment), JSON, or SARIF for GitHub Code Scanning.

## Quick start

Install the single self-contained binary (no Node.js or Bun needed):

```sh
# macOS / Linux
curl -fsSL https://github.com/MarcosRTech/diffward/releases/latest/download/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://github.com/MarcosRTech/diffward/releases/latest/download/install.ps1 | iex
```

The installer detects your OS and CPU, downloads the matching binary with a progress bar, verifies it against the release's `SHA256SUMS`, installs it to `~/.local/bin` (Windows: `%LOCALAPPDATA%\diffward\bin`) and tells you if that directory is missing from your `PATH`. Running it again updates diffward. Options: `DIFFWARD_VERSION=v0.2.0` pins a version, `DIFFWARD_INSTALL_DIR=...` changes the destination, `DIFFWARD_FORCE=1` reinstalls. In CI it prints plain progress lines instead of a redrawn bar.

```text
[1/4] Detecting your system
      System     macOS 26.1 · arm64
      Version    v0.2.0 (latest)

[2/4] Downloading
      Package    diffward-darwin-arm64 (58.4 MB)
      ██████████████████░░░░░░░░░░░░  61%  35.6 MB / 58.4 MB  11.2 MB/s
```

Prefer to do it by hand? Every binary is on the [releases page](https://github.com/MarcosRTech/diffward/releases/latest) (`diffward-<linux|darwin>-<x64|arm64>`, `diffward-windows-x64.exe`) next to `SHA256SUMS`.

Then, inside a repository:

```sh
diffward                          # full scan of the current repository
diffward --diff origin/main       # only what this branch introduces (incl. uncommitted edits)
diffward --diff origin/main --fail-on critical --sarif diffward.sarif
git diff main... | diffward --diff-file -   # from a patch, no git history needed
diffward baseline                 # adopting on an old project: accept what exists today
```

With [Bun](https://bun.sh) you can also run it from source: `git clone https://github.com/MarcosRTech/diffward && cd diffward && bun install && bun src/cli.ts <path>`.

## GitHub Actions

```yaml
# .github/workflows/security.yml
name: security
on: pull_request

permissions:
  contents: read
  security-events: write # only for the SARIF upload

jobs:
  diffward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0 # needed to find the PR's merge-base

      - id: diffward
        uses: MarcosRTech/diffward@v0
        with:
          fail-on: high

      - uses: github/codeql-action/upload-sarif@v4
        if: always() && steps.diffward.outputs.sarif-file != ''
        with:
          sarif_file: ${{ steps.diffward.outputs.sarif-file }}
          category: diffward
```

On `pull_request` events the action diffs against the PR base automatically and writes a summary table to the job page. The SARIF upload shows findings inline in the PR's *Files changed* tab; Code Scanning is free for public repositories (private ones need GitHub Advanced Security — without it, drop that step and keep the summary and the failing check).

| Input | Default | |
|---|---|---|
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none` |
| `fail-on-quality` | `none` | Same scale, for quality (bad-practice) findings |
| `diff-base` | PR base SHA | Any ref/SHA; empty outside PRs means a full scan |
| `path` | `.` | Directory to scan |
| `sarif-file` | `diffward.sarif` | Empty to skip |
| `code` / `deps` | `true` | Turn either analysis off |
| `args` | | Extra CLI flags, e.g. `--deps-scope all` |

Outputs: `sarif-file`, `findings` (count), `failed` (`"true"`/`"false"`).

## Other CI systems

diffward only needs a checkout with the target branch fetched. See [`examples/`](examples) for GitLab CI and a generic shell script; the core is always:

```sh
git fetch origin main
curl -fsSL https://github.com/MarcosRTech/diffward/releases/latest/download/install.sh | DIFFWARD_INSTALL_DIR=. sh
./diffward --diff origin/main --fail-on high --sarif diffward.sarif
```

GitLab can ingest the SARIF file, and Azure DevOps, Jenkins (Warnings NG) and SonarQube read SARIF too.

## What it checks

### Dependencies (OSV)

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `bun.lock`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5–v9) |
| PyPI | `requirements*.txt` (pinned `==`), `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock` |
| Go | `go.mod` (or `go.sum` when there is no `go.mod`) |
| crates.io | `Cargo.lock` |
| Packagist | `composer.lock` |
| RubyGems | `Gemfile.lock` |

In diff mode only packages that are **new or changed** relative to the base branch are checked, so a PR is not blamed for advisories published against code it didn't touch (`--deps-scope all` changes that). Severity comes from the GitHub-reviewed label when present, otherwise from the CVSS v3 base score.

Findings are grouped per package, and diffward reads the dependency graph in the lockfile (npm, bun, yarn incl. workspaces, pnpm; Pipfile, poetry, `requirements-dev.txt`) to say for each one:

- **production or dev only** — vulnerabilities in packages only reachable from `devDependencies` are shown but **don't fail the build** unless you pass `--fail-on-dev`;
- **direct or transitive**, and for transitive ones **which direct dependency pulls it in**;
- **how to fix it**: the smallest version that closes every advisory, as a command for your package manager (`bun add next@^16.4.1`, `poetry add "django>=5.2.15"`…) or, for transitive packages, the dependency to update or the `overrides`/`resolutions` entry to add.

Only package names, versions and ecosystems are sent to `api.osv.dev`. Your code never leaves the machine. Use `--osv-url` (or `DIFFWARD_OSV_URL`) to point at a mirror. If OSV can't be reached the run fails with exit code 2 instead of passing silently.

### Code

JavaScript/TypeScript (`.js .jsx .ts .tsx .mjs .cjs .mts .cts`) is parsed into an AST with the TypeScript compiler; Python is analyzed statement by statement.

| Area | Rules |
|---|---|
| Injection | `js/sql-injection`, `js/command-injection`, `js/code-injection`, `py/sql-injection`, `py/command-injection`, `py/code-injection` |
| Request data reaching a sink | `js/path-traversal`, `js/ssrf`, `js/open-redirect`, `js/xss`, `py/path-traversal`, `py/ssrf` |
| Deserialization | `js/insecure-deserialization`, `py/insecure-deserialization` (pickle, yaml.load, marshal, torch.load…) |
| Crypto / transport | `*/weak-hash`, `*/weak-cipher`, `*/insecure-random`, `*/tls-verification-disabled`, `js/jwt-none-algorithm`, `js/gcm-no-tag-length` |
| Web configuration | `js/cors-any-origin` (`enableCors()`, `cors()`, `Access-Control-Allow-Origin: *`, origin reflected with credentials) |
| Data exposure | `js/sensitive-log`, `py/sensitive-log` (passwords, tokens, CPF/card numbers, whole request bodies/headers/cookies in logs) |
| Misc | `py/debug-enabled`, `py/insecure-tempfile` |

SQL is also checked when it is passed inside an options object (`bigquery.query({ query })`, `pg.query({ text, values })`), including through a local `const options = { ... }`.

### Secrets

Checked in every committed text file, with heuristics matched to the kind of file:

| Rule | What it catches | Where |
|---|---|---|
| `secret/known-token` | AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm, SendGrid, Twilio, Telegram, Discord… and passwords inside connection strings | everywhere |
| `secret/private-key` | `-----BEGIN … PRIVATE KEY-----` | everywhere |
| `secret/jwt` | Signed JSON Web Tokens (expired ones are reported as low; the jwt.io sample is ignored) | everywhere |
| `secret/auth-header` | `Authorization: Bearer/Basic/Token …` with a real-looking value (`<token>`, `$TOKEN` are ignored) | everywhere |
| `secret/env-file` | A committed `.env`, `.env.local`, `.env.production`… with values (`.env.example` is fine) | `.env*` |
| `secret/hardcoded-password` | `password = "…"`, `API_KEY=…`, `client_secret: …`, `?applicationKey=…` in URLs, literal HMAC keys and JWT signing secrets | code, config (YAML, JSON, `.env`, shell, Dockerfile, Terraform…), URLs in docs |

Values are redacted in every report. Placeholders, variable references (`${VAR}`, `$VAR`, `%VAR%`), labels like `forgot-password` and low-entropy strings are skipped; Markdown and text files only get the unambiguous checks, since examples in docs are usually fake.

### CI/CD and containers

| Rule | What it catches |
|---|---|
| `gha/script-injection` | `${{ github.event.pull_request.title }}`, `${{ github.head_ref }}`, comment bodies… pasted into `run:` or `github-script` (critical on `pull_request_target`/`issue_comment` workflows); `${{ inputs.* }}` as medium |
| `gha/untrusted-checkout` | `pull_request_target` workflows that check out the PR's head ("pwn request") |
| `gha/unpinned-action` | Third-party actions referenced by a tag instead of a commit SHA (`actions/*` and `github/*` are exempt) |
| `gha/excessive-permissions` | `permissions: write-all` |
| `docker/root-user` | The final stage runs as root (no `USER`, or `USER root`); distroless `:nonroot` and Chainguard bases are recognized |
| `docker/curl-pipe-shell`, `docker/add-remote` | `curl … \| sh` and `ADD https://…` without `--checksum` |
| `docker/latest-tag` (quality) | Base images without a version or digest |

Secrets in `ENV`/`ARG` lines are covered by the secret rules. Dockerfiles and workflows under `node_modules/` or vendored code are never scanned.

### Bad practices (quality)

| Rule | What it catches |
|---|---|
| `js/http-no-timeout`, `py/http-no-timeout` | axios / fetch / requests calls (and `axios.create`) without a timeout, in server code |
| `js/unbounded-query` | Prisma `findMany`, TypeORM `find`, Sequelize `findAll` with no `where` and no `take`/`limit` |
| `js/await-in-loop` | A database or HTTP call awaited on every iteration of a loop (N+1) |
| `js/floating-promise` | An async function called without `await`/`.catch`, and `forEach(async ...)`, in server code |
| `js/empty-catch`, `py/empty-except` | `catch {}` / `except: pass` with no comment explaining why |
| `js/sync-io-in-handler` | `readFileSync`, `pbkdf2Sync`, `execSync`… inside a request handler |

They are tuned to stay quiet where the pattern is normal: browser code for timeouts and promises, seeds/migrations/scripts for loops, chunked `createMany` batches, and a project's own `service.findMany(filters)` wrappers. Quality findings don't fail the build by default; use `--fail-on-quality medium` (or `"failOnQuality"` in the config) once a project is clean.

Full list with CWE and fix guidance: [docs/rules.md](docs/rules.md) or `diffward --list-rules`.

**How severity is decided for injections.** diffward tracks values within a function: if request data (`req.query`, `req.body`, `event.queryStringParameters`, `searchParams.get()`, Flask/Django `request.*`…) reaches the sink, the finding is **critical**; if a function parameter reaches it, **high**; if the string is merely dynamic (e.g. a table name from a constant), it stays at the rule's default, usually **medium**. Passing bound parameters separately (`db.raw(sql, bindings)`, `cursor.execute(sql, params)`) keeps it at medium unless request data is in the SQL text itself.

**Test files** (`test/`, `__tests__/`, `*.test.ts`, `test_*.py`, `fixtures/`…) are skipped by code rules, since tests legitimately turn off TLS or build SQL by hand. Provider tokens and private keys are still reported there. Set `"includeTests": true` to scan them fully.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing reached a fail threshold |
| `1` | A security finding or production dependency at/above `--fail-on` (default `high`), a quality finding at/above `--fail-on-quality` (default `none`), or a dev dependency when `--fail-on-dev` is set |
| `2` | Usage error, unreadable config, git error, or OSV unreachable |

## Speed

A full scan of a 14,000-file TypeScript monorepo with 4,000 locked packages takes about 3–4 s on a laptop once the advisory cache is warm (about 7 s cold). How:

- **Code and dependencies run at the same time**: analysis is CPU-bound, the OSV lookup is network-bound.
- **Code analysis uses every core** through worker threads (up to 8); small scans and the Node.js bundle run on one thread.
- **OSV lookups are batched and parallel** (all `querybatch` pages at once, 32 advisory fetches in flight).
- **Advisories are cached on disk** in `~/.cache/diffward` (`DIFFWARD_CACHE_DIR` to move it, `--no-cache` to skip it). An entry is reused only while OSV reports the same `modified` date for it, so the cache is never staler than the API. The GitHub Action keeps this cache between runs.
- **Secrets are pre-filtered per line**: only lines that could contain a credential go through the full set of patterns.
- In `--diff` mode only the changed files and the new or updated packages are looked at, which usually takes well under a second.

On an interactive terminal diffward shows a live display while it works: the file being analyzed, OSV progress (with how many advisories came from the cache) and finding counters by severity. It is drawn on stderr and erased before the report, so `--format json > out.json` stays clean; it never appears in CI or when output is piped. `--no-progress` turns it off.

## Adopting on an existing project

A first full scan of an old codebase can list hundreds of findings. Record them once and commit the file:

```sh
diffward baseline            # writes .diffward-baseline.json
git add .diffward-baseline.json
```

From then on every scan (full or `--diff`) hides the findings in the baseline and reports only new ones, so you can gate on `--fail-on high` from day one and burn the old list down over time. Entries are matched by rule, file and line text (or package@version), so they survive code moving around but not the code itself changing. `--no-baseline` shows everything again.

## Configuration

Optional `.diffward.json` at the repository root (lines starting with `//` are allowed as comments):

```jsonc
{
  "failOn": "high",
  "failOnQuality": "none",          // e.g. "medium" once the project is clean
  "failOnDev": false,               // let dev-only dependencies fail the build
  "quality": true,                  // false turns the quality rules off
  "baseline": ".diffward-baseline.json",
  "ignorePaths": ["migrations/", "scripts/one-off/**"],
  "includeTests": false,
  "rules": {
    "js/weak-hash": "off",          // or change a rule's severity:
    "py/debug-enabled": "high"
  },
  "ignoreVulnerabilities": [
    "GHSA-xxxx-xxxx-xxxx",
    { "id": "CVE-2024-12345", "reason": "only used at build time", "until": "2026-12-31" }
  ]
}
```

`ignoreVulnerabilities` matches any id or alias (GHSA, CVE, PYSEC, GO…). An entry with `until` stops applying after that date, so accepted risks come back for review.

Silence a single line with a comment, optionally naming the rule:

```ts
const etag = createHash("md5").update(body).digest("hex"); // diffward-ignore js/weak-hash

// diffward-ignore-next-line
eval(trustedBuildTimeSnippet);
```

`node_modules/`, `vendor/`, virtualenvs and git-ignored files are never scanned; minified or bundled JavaScript is only checked for secrets.

## CLI reference

```
diffward [scan] [path] [options]
diffward baseline [path]  Record current findings so only new ones are reported

  --diff <ref>            Only report issues introduced since the merge-base with <ref>
  --diff-file <file|->    Same, from a unified diff file (or stdin) instead of git
  --no-code / --no-deps / --no-quality   Skip one of the analyses
  --deps-scope <s>        changed | all (default: changed with --diff, all otherwise)
  --no-baseline           Ignore the baseline file
  --format <f>            text | json | sarif | markdown for stdout (default: text)
  -o, --output <file>     Write the --format output to a file
  --sarif / --markdown / --json <file>   Also write that format to a file
  --fail-on <severity>    Security threshold: critical | high | medium | low | info | none (default: high)
  --fail-on-quality <s>   Quality threshold (default: none)
  --fail-on-dev           Count dev-only dependencies against --fail-on
  --config <file>         Config file (default: <repo>/.diffward.json)
  --osv-url <url>         OSV API base URL (env DIFFWARD_OSV_URL)
  --no-cache              Don't read or write the advisory cache (env DIFFWARD_CACHE_DIR moves it)
  --no-progress           Hide the live progress display
  --list-rules            Print the code rules
  --no-color, -v/--version, -h/--help
```

## Limitations

diffward is a fast first line of defense, not a full program analyzer:

- Data flow is tracked **within a function**. Request data passed through several layers before reaching a query is reported at the parameter's level (high) or as merely dynamic (medium), not as critical.
- Python analysis is pattern-based on statements, not a full AST.
- Dependency checks need exact versions: `requirements.txt` ranges (`>=`) can't be checked — commit a lockfile.
- Advisories are matched by version only; diffward doesn't know whether your code calls the vulnerable function.

Pair it with a deep analyzer (CodeQL, Semgrep) for scheduled full-repository scans if you need more; diffward is meant to keep every PR clean at near-zero cost.

## Development

```sh
bun install
bun test               # unit, fixture and end-to-end tests (no network)
bun run typecheck
bun run build          # dist/diffward.js, runs on Node.js >= 18
bun run build:bin      # single-file binary for this platform
```

Rule tests live in [`tests/fixtures/code`](tests/fixtures/code): every `// ruleid: <rule> [severity]` comment says the next line must be reported, every `// ok: <rule>` that it must not, and any other finding fails the test. Adding a rule means adding both kinds of cases there.

## License

[MIT](LICENSE)

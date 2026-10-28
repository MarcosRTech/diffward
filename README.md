# diffward

```console
$ npx diffward --diff origin/main

 CRITICAL  js/sql-injection src/routes/users.ts:42:9
  SQL query built from dynamic strings (query()).
  │ return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
  fix: Use parameterized queries (placeholders such as ? or $1 with a values array) or a tagged-template SQL helper instead of concatenation/interpolation.

 HIGH  GHSA-35jh-r3h4-6jhm package-lock.json:1187
  lodash@4.17.20 (npm) is affected by GHSA-35jh-r3h4-6jhm / CVE-2021-23337: Command Injection in lodash. Upgrade to 4.17.21 or later.
  fix: Upgrade lodash to 4.17.21 or later. Details: https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm

diffward: 2 finding(s): 1 critical, 1 high (changed code; 14 file(s), 3 package(s) in 1 lockfile(s)).
$ echo $?
1
```

**diffward** is a free, zero-config security check for pull requests. It looks only at what the PR changes and reports two kinds of problems:

- **Vulnerable dependencies** — packages the PR adds or upgrades in a lockfile that have a known advisory (CVE/GHSA), checked against the free [OSV.dev](https://osv.dev) database.
- **Insecure code** — SQL/command/code injection, path traversal, SSRF, XSS, hardcoded secrets, unsafe deserialization, weak crypto and disabled TLS verification in the lines the PR adds, for JavaScript/TypeScript and Python.

Old problems already on `main` don't block the PR; new ones do. Results come as readable text, Markdown (job summary / PR comment), JSON, or SARIF for GitHub Code Scanning.

## Quick start

```sh
npx diffward                          # full scan of the current repository
npx diffward --diff origin/main       # only what this branch introduces (incl. uncommitted edits)
npx diffward --diff origin/main --fail-on critical --sarif diffward.sarif
git diff main... | npx diffward --diff-file -   # from a patch, no git history needed
```

Also available as `bunx diffward`, or as a single self-contained binary (Linux, macOS, Windows) from the [releases page](https://github.com/MarcosRTech/diffward/releases) — no Node.js or Bun required.

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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # needed to find the PR's merge-base

      - id: diffward
        uses: MarcosRTech/diffward@v0
        with:
          fail-on: high

      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.diffward.outputs.sarif-file != ''
        with:
          sarif_file: ${{ steps.diffward.outputs.sarif-file }}
          category: diffward
```

On `pull_request` events the action diffs against the PR base automatically and writes a summary table to the job page. The SARIF upload shows findings inline in the PR's *Files changed* tab; Code Scanning is free for public repositories (private ones need GitHub Advanced Security — without it, drop that step and keep the summary and the failing check).

| Input | Default | |
|---|---|---|
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none` |
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
npx diffward --diff origin/main --fail-on high --sarif diffward.sarif
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

In diff mode only packages that are **new or changed** relative to the base branch are checked, so a PR is not blamed for advisories published against code it didn't touch (`--deps-scope all` changes that). Severity comes from the GitHub-reviewed label when present, otherwise from the CVSS v3 base score. Each finding names the smallest fixed version above the one you have.

Only package names, versions and ecosystems are sent to `api.osv.dev`. Your code never leaves the machine. Use `--osv-url` (or `DIFFWARD_OSV_URL`) to point at a mirror. If OSV can't be reached the run fails with exit code 2 instead of passing silently.

### Code

JavaScript/TypeScript (`.js .jsx .ts .tsx .mjs .cjs .mts .cts`) is parsed into an AST with the TypeScript compiler; Python is analyzed statement by statement. Secrets are checked in every text file.

| Area | Rules |
|---|---|
| Injection | `js/sql-injection`, `js/command-injection`, `js/code-injection`, `py/sql-injection`, `py/command-injection`, `py/code-injection` |
| Request data reaching a sink | `js/path-traversal`, `js/ssrf`, `js/open-redirect`, `js/xss`, `py/path-traversal`, `py/ssrf` |
| Secrets | `secret/known-token` (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm, SendGrid, connection strings…), `secret/private-key`, `secret/hardcoded-password` |
| Deserialization | `js/insecure-deserialization`, `py/insecure-deserialization` (pickle, yaml.load, marshal, torch.load…) |
| Crypto / transport | `*/weak-hash`, `*/weak-cipher`, `*/insecure-random`, `*/tls-verification-disabled`, `js/jwt-none-algorithm` |
| Misc | `py/debug-enabled`, `py/insecure-tempfile` |

Full list with CWE and fix guidance: [docs/rules.md](docs/rules.md) or `diffward --list-rules`.

**How severity is decided for injections.** diffward tracks values within a function: if request data (`req.query`, `req.body`, `event.queryStringParameters`, `searchParams.get()`, Flask/Django `request.*`…) reaches the sink, the finding is **critical**; if a function parameter reaches it, **high**; if the string is merely dynamic (e.g. a table name from a constant), it stays at the rule's default, usually **medium**. Passing bound parameters separately (`db.raw(sql, bindings)`, `cursor.execute(sql, params)`) keeps it at medium unless request data is in the SQL text itself.

**Test files** (`test/`, `__tests__/`, `*.test.ts`, `test_*.py`, `fixtures/`…) are skipped by code rules, since tests legitimately turn off TLS or build SQL by hand. Provider tokens and private keys are still reported there. Set `"includeTests": true` to scan them fully.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` (default `high`) |
| `2` | Usage error, unreadable config, git error, or OSV unreachable |

## Configuration

Optional `.diffward.json` at the repository root (lines starting with `//` are allowed as comments):

```jsonc
{
  "failOn": "high",
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

  --diff <ref>            Only report issues introduced since the merge-base with <ref>
  --diff-file <file|->    Same, from a unified diff file (or stdin) instead of git
  --no-code / --no-deps   Skip one of the analyses
  --deps-scope <s>        changed | all (default: changed with --diff, all otherwise)
  --format <f>            text | json | sarif | markdown for stdout (default: text)
  -o, --output <file>     Write the --format output to a file
  --sarif / --markdown / --json <file>   Also write that format to a file
  --fail-on <severity>    critical | high | medium | low | info | none (default: high)
  --config <file>         Config file (default: <repo>/.diffward.json)
  --osv-url <url>         OSV API base URL (env DIFFWARD_OSV_URL)
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

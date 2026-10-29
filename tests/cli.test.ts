import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startOsvServer } from "./helpers/osv-mock.ts";

const CLI = join(import.meta.dir, "..", "src", "cli.ts");
let server: ReturnType<typeof startOsvServer>;
let repo: string;

// Async on purpose: the mock OSV server runs in this process, so a blocking
// spawnSync would deadlock it.
async function run(args: string[], opts: { cwd?: string; input?: string; osvUrl?: string } = {}) {
  const proc = Bun.spawn(["bun", CLI, ...args], {
    cwd: opts.cwd ?? repo,
    stdin: opts.input !== undefined ? new TextEncoder().encode(opts.input) : "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, DIFFWARD_OSV_URL: opts.osvUrl ?? server.url.href, DIFFWARD_CACHE_DIR: join(tmpdir(), `diffward-cache-${process.pid}`), NO_COLOR: "1" },
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stdout, stderr };
}

function git(...args: string[]) {
  execFileSync("git", args, { cwd: repo, stdio: "ignore" });
}

function write(path: string, content: string) {
  mkdirSync(join(repo, path, ".."), { recursive: true });
  writeFileSync(join(repo, path), content);
}

beforeAll(() => {
  server = startOsvServer();
  repo = mkdtempSync(join(tmpdir(), "diffward-e2e-"));
  git("init", "-q", "-b", "main");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "test");
  git("config", "commit.gpgsign", "false");

  // main: an old vulnerability that a PR should not be blamed for
  write("src/legacy.js", 'const cp = require("child_process");\nmodule.exports = (x) => cp.exec("rm -rf " + x);\n');
  write("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/lodash": { version: "4.17.15" } } }, null, 2));
  write("requirements.txt", "requests==2.31.0\n");
  git("add", ".");
  git("commit", "-q", "-m", "base");

  // feature branch: one new SQL injection, one new vulnerable dependency
  git("checkout", "-q", "-b", "feature");
  write(
    "src/users.ts",
    'export async function find(db: any, req: any) {\n  const ok = await db.query("SELECT 1");\n  return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n}\n',
  );
  write("requirements.txt", "requests==2.31.0\nPyYAML==5.3\n");
  git("add", ".");
  git("commit", "-q", "-m", "feature");
});

afterAll(() => {
  server.stop(true);
  rmSync(repo, { recursive: true, force: true });
});

describe("cli", () => {
  test("full scan finds old and new issues and exits 1", async () => {
    const r = await run(["."]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("js/command-injection");
    expect(r.stdout).toContain("js/sql-injection");
    expect(r.stdout).toContain("GHSA-35jh-r3h4-6jhm");
    expect(r.stdout).toContain("GHSA-6757-jp84-gxfx");
  });

  test("--diff reports only what the branch introduced", async () => {
    const r = await run(["--diff", "main", "--format", "json"]);
    expect(r.code).toBe(1);
    const out = JSON.parse(r.stdout);
    expect(out.mode).toBe("diff");
    expect(out.findings.map((f: { ruleId: string; file: string; line: number }) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual([
      "GHSA-6757-jp84-gxfx requirements.txt:2",
      "js/sql-injection src/users.ts:3",
    ]);
  });

  test("--diff-file reads a patch from stdin", async () => {
    const patch = execFileSync("git", ["diff", "main...feature"], { cwd: repo, encoding: "utf8" });
    const r = await run(["--diff-file", "-", "--no-deps", "--format", "json"], { input: patch });
    expect(JSON.parse(r.stdout).findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(["js/sql-injection"]);
  });

  test("--fail-on controls the exit code", async () => {
    expect((await run(["--diff", "main", "--fail-on", "critical", "--no-deps"])).code).toBe(1); // tainted SQLi is critical
    expect((await run(["--diff", "main", "--fail-on", "none"])).code).toBe(0);
    expect((await run(["--diff", "main", "--no-code", "--fail-on", "critical"])).code).toBe(1); // PyYAML CVSS 9.8
  });

  test("writes SARIF that GitHub accepts", async () => {
    const sarifPath = join(repo, "out.sarif");
    await run(["--diff", "main", "--sarif", sarifPath, "--fail-on", "none"]);
    const sarif = JSON.parse(readFileSync(sarifPath, "utf8"));
    expect(sarif.version).toBe("2.1.0");
    const run0 = sarif.runs[0];
    expect(run0.tool.driver.name).toBe("diffward");
    expect(run0.results).toHaveLength(2);
    for (const r of run0.results) {
      expect(run0.tool.driver.rules[r.ruleIndex].id).toBe(r.ruleId);
      expect(r.locations[0].physicalLocation.artifactLocation.uri).not.toStartWith("/");
      expect(r.partialFingerprints["diffward/v1"]).toMatch(/^[0-9a-f]{32}$/);
      expect(Number(r.properties["security-severity"])).toBeGreaterThan(0);
    }
    rmSync(sarifPath);
  });

  test("config file disables rules and accepts vulnerabilities", async () => {
    write(
      ".diffward.json",
      JSON.stringify({ rules: { "js/sql-injection": "off" }, ignoreVulnerabilities: [{ id: "CVE-2020-1747", reason: "not reachable" }] }),
    );
    const r = await run(["--diff", "main", "--format", "json"]);
    rmSync(join(repo, ".diffward.json"));
    const out = JSON.parse(r.stdout);
    expect(r.code).toBe(0);
    expect(out.findings).toEqual([]);
    expect(out.stats.suppressed).toBe(2);
  });

  test("uncommitted edits are included in --diff", async () => {
    write("src/tmp.py", "import os\nos.system('ls ' + input())\n");
    const r = await run(["--diff", "main", "--no-deps", "--format", "json"]);
    rmSync(join(repo, "src/tmp.py"));
    expect(JSON.parse(r.stdout).findings.map((f: { file: string }) => f.file)).toContain("src/tmp.py");
  });

  test("quality findings are reported but only fail with --fail-on-quality", async () => {
    write("server/client.ts", 'import axios from "axios";\nexport const get = (url: string) => axios.get(url);\n');
    const r = await run(["server", "--no-deps", "--format", "json"]);
    const strict = await run(["server", "--no-deps", "--fail-on-quality", "medium"]);
    rmSync(join(repo, "server"), { recursive: true, force: true });
    const out = JSON.parse(r.stdout);
    expect(out.findings.map((f: { ruleId: string; category: string }) => `${f.category} ${f.ruleId}`)).toEqual([
      "quality js/http-no-timeout",
    ]);
    expect(r.code).toBe(0);
    expect(strict.code).toBe(1);
    expect(strict.stdout).toContain("Quality");
  });

  test("baseline: adopt on an old project, then only new findings count", async () => {
    const base = await run(["baseline"]);
    expect(base.code).toBe(0);
    expect(base.stdout).toMatch(/wrote \d+ finding/);

    const clean = await run([".", "--format", "json"]);
    expect(clean.code).toBe(0);
    expect(JSON.parse(clean.stdout).findings).toEqual([]);
    expect(JSON.parse(clean.stdout).stats.baselined).toBeGreaterThan(0);

    write("src/new.js", 'const cp = require("child_process");\nmodule.exports = (req) => cp.exec("ls " + req.query.dir);\n');
    const fresh = await run([".", "--no-deps", "--format", "json"]);
    expect(JSON.parse(fresh.stdout).findings.map((f: { file: string }) => f.file)).toEqual(["src/new.js"]);

    const all = await run([".", "--no-deps", "--no-baseline", "--format", "json"]);
    expect(JSON.parse(all.stdout).findings.length).toBeGreaterThan(1);
    rmSync(join(repo, "src/new.js"));
    rmSync(join(repo, ".diffward-baseline.json"));
  });

  test("markdown summary", async () => {
    const r = await run(["--diff", "main", "--format", "markdown", "--fail-on", "none"]);
    expect(r.stdout).toContain("### diffward — changed code");
    expect(r.stdout).toContain("| Severity | Rule | Location | Details |");
  });

  test("works outside git", async () => {
    const dir = mkdtempSync(join(tmpdir(), "diffward-nogit-"));
    writeFileSync(join(dir, "a.py"), "import pickle\npickle.loads(data)\n");
    const r = await run([dir, "--no-deps", "--format", "json"], { cwd: tmpdir() });
    rmSync(dir, { recursive: true, force: true });
    expect(JSON.parse(r.stdout).findings[0].file).toBe("a.py");
  });

  test("usage errors exit 2", async () => {
    const r = await run(["--fail-on", "urgent"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("invalid --fail-on");
    expect((await run(["--diff", "does-not-exist"])).code).toBe(2);
    expect((await run(["--bogus"])).code).toBe(2);
  });

  test("OSV unreachable exits 2 instead of passing silently", async () => {
    const r = await run([".", "--no-code"], { osvUrl: "http://127.0.0.1:9" });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("OSV request failed");
  });

  test("--version and --list-rules", async () => {
    const pkg = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8"));
    expect((await run(["--version"])).stdout.trim()).toBe(pkg.version);
    expect((await run(["--list-rules"])).stdout).toContain("py/insecure-deserialization");
  });
});

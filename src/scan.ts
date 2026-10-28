import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { scanCode, shouldScanText } from "./code/index.ts";
import { activeVulnIgnores, type Config } from "./config.ts";
import { scanDependencies } from "./deps/index.ts";
import { isLockfile } from "./deps/lockfiles/index.ts";
import type { OsvClient } from "./deps/osv.ts";
import { diffAgainst, git, gitRoot, parseUnifiedDiff, readFileAtRevision, type ChangedLines } from "./diff.ts";
import { makeMatcher } from "./glob.ts";
import { SEVERITIES, severityRank, type Finding } from "./types.ts";

export interface ScanOptions {
  /** Directory to scan. */
  path: string;
  /** Compare against this git ref (merge-base) and report only what changed. */
  diffBase?: string;
  /** Alternatively, a unified diff (e.g. from `git diff` or a CI provider). */
  diffPatch?: string;
  code: boolean;
  deps: boolean;
  /** "changed": only packages added/updated by the diff. Defaults to "changed" in diff mode. */
  depsScope?: "changed" | "all";
  osv: OsvClient;
  config: Config;
}

export interface ScanResult {
  root: string;
  mode: "full" | "diff";
  findings: Finding[];
  filesScanned: number;
  lockfiles: string[];
  packagesChecked: number;
  suppressed: number;
}

const ALWAYS_IGNORED = [
  "node_modules/",
  ".git/",
  "vendor/",
  "bower_components/",
  ".venv/",
  "venv/",
  "__pycache__/",
  "site-packages/",
  "*.min.js",
  "*.bundle.js",
];
const WALK_IGNORED = ["dist/", "build/", "out/", "coverage/", ".next/", ".nuxt/", ".turbo/", ".cache/", "target/"];
const MAX_FILE_BYTES = 2 * 1024 * 1024;

/**
 * Test code legitimately disables TLS, uses MD5, builds SQL by hand... Code
 * rules skip it by default (config `includeTests`); provider tokens and
 * private keys are still checked.
 */
export const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|testdata|e2e|cypress|playwright)\/|\.(?:test|spec|e2e)\.[cm]?[jt]sx?$|(?:^|\/)(?:test_[^/]*|[^/]*_test|conftest)\.py$/;

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const target = resolve(opts.path);
  const repoRoot = gitRoot(target);
  // Report paths relative to the repository root so SARIF lines up with GitHub.
  const root = repoRoot ?? target;
  const prefix = toPosix(relative(root, target));
  const inTarget = (f: string) => !prefix || f === prefix || f.startsWith(`${prefix}/`);
  const ignored = makeMatcher([...ALWAYS_IGNORED, ...(opts.config.ignorePaths ?? [])]);

  let changed: ChangedLines | null = null;
  let mergeBase: string | null = null;
  if (opts.diffBase) {
    if (!repoRoot) throw new Error(`--diff needs a git repository, but ${target} is not inside one`);
    const d = diffAgainst(root, opts.diffBase);
    changed = d.changed;
    mergeBase = d.mergeBase;
  } else if (opts.diffPatch !== undefined) {
    changed = parseUnifiedDiff(opts.diffPatch);
  }

  const allFiles = repoRoot ? listGitFiles(root) : walk(root, makeMatcher(WALK_IGNORED));
  const existing = allFiles.filter((f) => inTarget(f) && !ignored(f));
  const files = changed ? existing.filter((f) => changed!.has(f)) : existing;
  const read = (f: string) => readFileSync(join(root, f), "utf8");

  const findings: Finding[] = [];
  let filesScanned = 0;

  if (opts.code) {
    for (const file of files) {
      if (!shouldScanText(file)) continue;
      let size: number;
      try {
        size = statSync(join(root, file)).size;
      } catch {
        continue; // deleted in the working tree
      }
      if (size > MAX_FILE_BYTES) continue;
      filesScanned++;
      const lines = changed?.get(file);
      const isTest = !opts.config.includeTests && TEST_PATH.test(file);
      for (const f of scanCode(file, read(file))) {
        // Real credentials leak from tests too; generic "password = ..." in tests is almost always fake.
        if (isTest && f.ruleId !== "secret/known-token" && f.ruleId !== "secret/private-key") continue;
        if (!lines || lines.has(f.line)) findings.push(f);
      }
    }
  }

  let lockfiles: string[] = [];
  let packagesChecked = 0;
  if (opts.deps) {
    const scope = opts.depsScope ?? (changed ? "changed" : "all");
    const candidates = (scope === "changed" && changed ? files : existing).filter(isLockfile);
    const res = await scanDependencies({
      files: candidates,
      read,
      readBase: scope === "changed" && mergeBase ? (f) => readFileAtRevision(root, mergeBase!, f) : undefined,
      osv: opts.osv,
    });
    lockfiles = res.lockfiles;
    packagesChecked = res.packagesChecked;
    for (const f of res.findings) {
      // With a raw patch there is no base lockfile to compare; keep packages whose entry was touched.
      if (scope === "changed" && changed && !mergeBase) {
        const lines = changed.get(f.file);
        if (lines && ![0, 1, 2, 3].some((d) => lines.has(f.line + d))) continue;
      }
      findings.push(f);
    }
  }

  const { kept, suppressed } = applyConfig(findings, opts.config);
  kept.sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line,
  );
  return {
    root,
    mode: changed ? "diff" : "full",
    findings: kept,
    filesScanned,
    lockfiles,
    packagesChecked,
    suppressed,
  };
}

function applyConfig(findings: Finding[], config: Config): { kept: Finding[]; suppressed: number } {
  const vulnIgnores = activeVulnIgnores(config);
  const kept: Finding[] = [];
  let suppressed = 0;
  for (const f of findings) {
    const override = config.rules?.[f.ruleId];
    if (override === "off") {
      suppressed++;
      continue;
    }
    if (f.dependency && [f.dependency.vulnId, ...f.dependency.aliases].some((id) => vulnIgnores.has(id))) {
      suppressed++;
      continue;
    }
    kept.push(override && SEVERITIES.includes(override) ? { ...f, severity: override } : f);
  }
  return { kept, suppressed };
}

function listGitFiles(root: string): string[] {
  return git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    .split("\0")
    .filter((f) => f && isRegularFile(join(root, f))); // skips deleted files, submodules, dir symlinks
}

function isRegularFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function walk(root: string, skip: (path: string) => boolean): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
      const rel = dir ? `${dir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!skip(`${rel}/`) && !skip(rel)) visit(rel);
      } else if (entry.isFile()) {
        out.push(rel);
      }
    }
  };
  visit("");
  return out;
}

function toPosix(p: string): string {
  return p.split(sep).join("/");
}

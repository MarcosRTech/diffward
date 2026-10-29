import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { shouldScanText } from "./code/index.ts";
import { activeVulnIgnores, type Config } from "./config.ts";
import { scanDependencies } from "./deps/index.ts";
import { isLockfile } from "./deps/lockfiles/index.ts";
import type { OsvClient, OsvProgress } from "./deps/osv.ts";
import { analyzeFiles } from "./code/pool.ts";
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
  /** Run quality (bad-practice) rules in addition to security rules. */
  quality: boolean;
  /** Live progress for interactive output. */
  onProgress?: (e: ProgressEvent) => void;
  /** "changed": only packages added/updated by the diff. Defaults to "changed" in diff mode. */
  depsScope?: "changed" | "all";
  osv: OsvClient;
  config: Config;
}

export type ProgressEvent =
  | { type: "code"; done: number; total: number; file?: string }
  | { type: "code-done"; files: number }
  | { type: "finding"; finding: Finding }
  | ({ type: "deps" } & OsvProgress)
  | { type: "deps-done"; packages: number; vulnerable: number; lockfiles: number };

export interface ScanResult {
  root: string;
  mode: "full" | "diff";
  findings: Finding[];
  filesScanned: number;
  lockfiles: string[];
  packagesChecked: number;
  suppressed: number;
  /** Findings hidden because they are in the baseline (set by the caller). */
  baselined: number;
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
  const emit = opts.onProgress ?? (() => {});

  // Dependencies are network-bound and code analysis is CPU-bound: run both at once.
  const depsTask = (async () => {
    if (!opts.deps) return { lockfiles: [] as string[], packagesChecked: 0, findings: [] as Finding[] };
    const scope = opts.depsScope ?? (changed ? "changed" : "all");
    const candidates = (scope === "changed" && changed ? files : existing).filter(isLockfile);
    const res = await scanDependencies({
      files: candidates,
      read,
      allFiles: existing,
      readBase: scope === "changed" && mergeBase ? (f) => readFileAtRevision(root, mergeBase!, f) : undefined,
      osv: opts.osv,
      onProgress: (p) => emit({ type: "deps", ...p }),
    });
    const kept = res.findings.filter((f) => {
      // With a raw patch there is no base lockfile to compare; keep packages whose entry was touched.
      if (scope === "changed" && changed && !mergeBase) {
        const lines = changed.get(f.file);
        if (lines && ![0, 1, 2, 3].some((d) => lines.has(f.line + d))) return false;
      }
      return true;
    });
    for (const f of kept) emit({ type: "finding", finding: f });
    emit({ type: "deps-done", packages: res.packagesChecked, vulnerable: kept.length, lockfiles: res.lockfiles.length });
    return { lockfiles: res.lockfiles, packagesChecked: res.packagesChecked, findings: kept };
  })();

  const codeTask = (async () => {
    if (!opts.code) return;
    const targets = files.filter(shouldScanText);
    let done = 0;
    emit({ type: "code", done, total: targets.length });
    await analyzeFiles(root, targets, (r) => {
      done++;
      if (r.scanned) filesScanned++;
      const lines = changed?.get(r.file);
      const isTest = !opts.config.includeTests && TEST_PATH.test(r.file);
      for (const f of r.findings) {
        // Real credentials leak from tests too; generic "password = ..." in tests is almost always fake.
        if (isTest && f.ruleId !== "secret/known-token" && f.ruleId !== "secret/private-key") continue;
        if (!opts.quality && f.category === "quality") continue;
        if (!lines || lines.has(f.line)) {
          findings.push(f);
          emit({ type: "finding", finding: f });
        }
      }
      emit({ type: "code", done, total: targets.length, file: r.file });
    });
    emit({ type: "code-done", files: filesScanned });
  })();

  const [deps] = await Promise.all([depsTask, codeTask]);
  findings.push(...deps.findings);
  const lockfiles = deps.lockfiles;
  const packagesChecked = deps.packagesChecked;

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
    baselined: 0,
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

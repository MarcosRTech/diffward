#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { relative } from "node:path";
import { parseArgs } from "node:util";
import { applyBaseline, baselinePath, readBaseline, writeBaseline } from "./baseline.ts";
import { RULES } from "./code/rules.ts";
import { loadConfig } from "./config.ts";
import { createOsvClient, DEFAULT_OSV_URL } from "./deps/osv.ts";
import { createDiskCache } from "./deps/osv-cache.ts";
import { gitRoot } from "./diff.ts";
import { banner, TAGLINE } from "./logo.ts";
import { createProgressUI, type ProgressUI } from "./ui/progress.ts";
import { basename, resolve } from "node:path";
import { failed, type Policy, type Threshold } from "./policy.ts";
import { toMarkdown } from "./report/markdown.ts";
import { toSarif } from "./report/sarif.ts";
import { toText } from "./report/text.ts";
import { scan, type ScanResult } from "./scan.ts";
import { isSeverity } from "./types.ts";
import { VERSION } from "./version.ts";

const HELP = `diffward ${VERSION} — ${TAGLINE.toLowerCase()}

Usage:
  diffward [scan] [path] [options]
  diffward baseline [path] [options]   Record current findings so only new ones are reported

Scope:
  --diff <ref>            Only report issues introduced since the merge-base with <ref>
                          (e.g. origin/main). Changed lines for code, new/updated
                          packages for dependencies.
  --diff-file <file|->    Same, from a unified diff file (or stdin) instead of git.
  --no-code               Skip code analysis.
  --no-deps               Skip the dependency (OSV) check.
  --no-quality            Skip the quality (bad-practice) rules.
  --deps-scope <s>        changed | all. Default: changed with --diff, all otherwise.
  --no-baseline           Ignore the baseline file and report everything.

Output:
  --format <f>            text | json | sarif | markdown for stdout (default: text)
  -o, --output <file>     Write the --format output to a file instead of stdout.
  --sarif <file>          Also write SARIF 2.1.0 (GitHub Code Scanning).
  --markdown <file>       Also write a Markdown summary (PR comment / step summary).
  --json <file>           Also write JSON.
  --no-color              Disable colors (also honors NO_COLOR).
  --no-progress           Don't show the live progress display (it only appears on
                          interactive terminals, never in CI or when piped).

Policy:
  --fail-on <severity>    Exit 1 on a security finding at or above: critical | high |
                          medium | low | info | none (default: high).
  --fail-on-quality <s>   Same for quality findings (default: none).
  --fail-on-dev           Let vulnerabilities in dev-only dependencies fail too.
  --config <file>         Config file (default: <repo>/.diffward.json).

Other:
  --osv-url <url>         OSV API base URL (default: ${DEFAULT_OSV_URL}, env DIFFWARD_OSV_URL).
  --no-cache              Don't read or write the advisory cache (~/.cache/diffward, env DIFFWARD_CACHE_DIR).
  --list-rules            Print the code rules and exit.
  -v, --version           Print the version.
  -h, --help              Show this help.

Exit codes: 0 = nothing reached the fail thresholds, 1 = something did,
2 = usage or runtime error (e.g. OSV unreachable).

Examples:
  diffward .                                    # full scan of the current repo
  diffward --diff origin/main                   # only what this branch introduces
  diffward --diff origin/main --sarif out.sarif --fail-on critical
  git diff main... | diffward --diff-file -     # any CI that can produce a patch
  diffward baseline                             # adopt on an old project: start from zero
`;

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      diff: { type: "string" },
      "diff-file": { type: "string" },
      "no-code": { type: "boolean" },
      "no-deps": { type: "boolean" },
      "no-quality": { type: "boolean" },
      "deps-scope": { type: "string" },
      "no-baseline": { type: "boolean" },
      format: { type: "string", default: "text" },
      output: { type: "string", short: "o" },
      sarif: { type: "string" },
      markdown: { type: "string" },
      json: { type: "string" },
      "no-color": { type: "boolean" },
      "no-progress": { type: "boolean" },
      "fail-on": { type: "string" },
      "fail-on-quality": { type: "string" },
      "fail-on-dev": { type: "boolean" },
      config: { type: "string" },
      "osv-url": { type: "string" },
      "no-cache": { type: "boolean" },
      "list-rules": { type: "boolean" },
      version: { type: "boolean", short: "v" },
      help: { type: "boolean", short: "h" },
    },
  });

  if (values.help) {
    const tty = Boolean(process.stdout.isTTY);
    const utf8 = process.platform === "win32" || /utf-?8/i.test(process.env.LC_ALL ?? process.env.LC_CTYPE ?? process.env.LANG ?? "");
    const color = tty && !values["no-color"] && !process.env.NO_COLOR;
    process.stdout.write(banner({ tty, utf8, color }) + HELP);
    return 0;
  }
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (values["list-rules"]) {
    for (const r of RULES.values()) {
      const cat = r.category ?? "security";
      process.stdout.write(`${r.id.padEnd(30)} ${cat.padEnd(9)} ${r.severity.padEnd(8)} ${r.cwe.join(",").padEnd(16)} ${r.title}\n`);
    }
    return 0;
  }

  const command = positionals[0] === "scan" || positionals[0] === "baseline" ? positionals[0] : "scan";
  const args = positionals[0] === command ? positionals.slice(1) : positionals;
  if (args.length > 1) throw new UsageError(`expected at most one path, got: ${args.join(" ")}`);
  const path = args[0] ?? ".";

  if (values.diff && values["diff-file"]) throw new UsageError("use either --diff or --diff-file, not both");
  if (command === "baseline" && (values.diff || values["diff-file"])) {
    throw new UsageError("a baseline records the whole project; --diff/--diff-file don't apply");
  }
  const format = values.format!;
  if (!["text", "json", "sarif", "markdown"].includes(format)) throw new UsageError(`unknown --format: ${format}`);
  const depsScope = values["deps-scope"];
  if (depsScope !== undefined && depsScope !== "changed" && depsScope !== "all") {
    throw new UsageError(`--deps-scope must be "changed" or "all"`);
  }

  const root = gitRoot(path) ?? path;
  const config = loadConfig(root, values.config);
  const policy: Policy = {
    failOn: threshold("--fail-on", values["fail-on"] ?? config.failOn ?? "high"),
    failOnQuality: threshold("--fail-on-quality", values["fail-on-quality"] ?? config.failOnQuality ?? "none"),
    failOnDev: values["fail-on-dev"] ?? config.failOnDev ?? false,
  };

  const diffPatch = values["diff-file"] !== undefined ? readInput(values["diff-file"]) : undefined;

  // Live HUD on stderr: interactive terminals only, so CI logs and pipes stay clean.
  const interactive = Boolean(process.stderr.isTTY) && !process.env.CI && !values["no-progress"];
  const runCode = !values["no-code"];
  const runDeps = !values["no-deps"];
  let ui: ProgressUI | undefined;
  if (interactive) {
    const scope = values.diff ? `changes since ${values.diff}` : values["diff-file"] !== undefined ? "changes from patch" : "full scan";
    ui = createProgressUI({
      stream: process.stderr,
      title: `${VERSION} · ${scope}`,
      subtitle: `scanning ${basename(resolve(path))}${runDeps ? " · dependencies checked against OSV" : ""}`,
      code: runCode,
      deps: runDeps,
      level: values["no-color"] ? 0 : undefined,
    });
  }
  const started = Date.now();
  let filesDone = 0;
  let packagesDone = 0;
  const onProgress = ui
    ? (e: Parameters<ProgressUI["onProgress"]>[0]) => {
        if (e.type === "code-done") filesDone = e.files;
        if (e.type === "deps-done") packagesDone = e.packages;
        ui!.onProgress(e);
      }
    : undefined;

  const result = await scan({
    path,
    onProgress,
    diffBase: values.diff,
    diffPatch,
    code: runCode,
    deps: runDeps,
    quality: !values["no-quality"] && config.quality !== false,
    depsScope,
    osv: createOsvClient(values["osv-url"] ?? process.env.DIFFWARD_OSV_URL ?? DEFAULT_OSV_URL, fetch, {
      cache: values["no-cache"] ? undefined : createDiskCache(),
    }),
    config,
  }).then(
    (r) => {
      const parts = [runCode ? `${filesDone.toLocaleString("en-US")} files` : "", runDeps ? `${packagesDone.toLocaleString("en-US")} packages` : ""];
      ui?.stop(`scanned ${parts.filter(Boolean).join(" and ")} in ${((Date.now() - started) / 1000).toFixed(1)}s`);
      return r;
    },
    (err: unknown) => {
      ui?.stop();
      throw err;
    },
  );

  const blPath = baselinePath(result.root, config.baseline);
  if (command === "baseline") {
    const n = writeBaseline(blPath, result.findings);
    process.stdout.write(
      `diffward: wrote ${n} finding(s) to ${relative(process.cwd(), blPath) || blPath}. ` +
        `Commit it; later scans report only findings that are not in it.\n`,
    );
    return 0;
  }
  if (!values["no-baseline"]) {
    const { kept, baselined } = applyBaseline(result.findings, readBaseline(blPath));
    result.findings = kept;
    result.baselined = baselined;
  }

  const color = !values["no-color"] && !process.env.NO_COLOR && !values.output && Boolean(process.stdout.isTTY);
  const render = (fmt: string): string => {
    switch (fmt) {
      case "json":
        return JSON.stringify(toJson(result, policy), null, 2) + "\n";
      case "sarif":
        return JSON.stringify(toSarif(result), null, 2) + "\n";
      case "markdown":
        return toMarkdown(result, policy);
      default:
        return toText(result, { color, policy }) + "\n";
    }
  };

  if (values.output) writeFileSync(values.output, render(format));
  else process.stdout.write(render(format));
  if (values.sarif) writeFileSync(values.sarif, render("sarif"));
  if (values.markdown) writeFileSync(values.markdown, render("markdown"));
  if (values.json) writeFileSync(values.json, render("json"));

  return failed(result.findings, policy) ? 1 : 0;
}

function threshold(flag: string, raw: string): Threshold {
  if (raw !== "none" && !isSeverity(raw)) throw new UsageError(`invalid ${flag}: ${raw}`);
  return raw as Threshold;
}

function toJson(result: ScanResult, policy: Policy) {
  return {
    version: VERSION,
    mode: result.mode,
    policy,
    failed: failed(result.findings, policy),
    stats: {
      filesScanned: result.filesScanned,
      lockfiles: result.lockfiles,
      packagesChecked: result.packagesChecked,
      suppressed: result.suppressed,
      baselined: result.baselined,
    },
    findings: result.findings,
  };
}

function readInput(file: string): string {
  return file === "-" ? readFileSync(0, "utf8") : readFileSync(file, "utf8");
}

class UsageError extends Error {}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: Error) => {
    const usage = err instanceof UsageError || (err as { code?: string }).code?.startsWith("ERR_PARSE_ARGS");
    process.stderr.write(`diffward: error: ${err.message}\n${usage ? "Run `diffward --help` for usage.\n" : ""}`);
    process.exitCode = 2;
  },
);

#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { RULES } from "./code/rules.ts";
import { loadConfig } from "./config.ts";
import { createOsvClient, DEFAULT_OSV_URL } from "./deps/osv.ts";
import { gitRoot } from "./diff.ts";
import { toMarkdown } from "./report/markdown.ts";
import { toSarif } from "./report/sarif.ts";
import { toText } from "./report/text.ts";
import { scan, type ScanResult } from "./scan.ts";
import { atLeast, isSeverity, type Severity } from "./types.ts";
import { VERSION } from "./version.ts";

const HELP = `diffward ${VERSION} — security scanner for pull requests

Usage:
  diffward [scan] [path] [options]

Scope:
  --diff <ref>            Only report issues introduced since the merge-base with <ref>
                          (e.g. origin/main). Changed lines for code, new/updated
                          packages for dependencies.
  --diff-file <file|->    Same, from a unified diff file (or stdin) instead of git.
  --no-code               Skip code analysis.
  --no-deps               Skip the dependency (OSV) check.
  --deps-scope <s>        changed | all. Default: changed with --diff, all otherwise.

Output:
  --format <f>            text | json | sarif | markdown for stdout (default: text)
  -o, --output <file>     Write the --format output to a file instead of stdout.
  --sarif <file>          Also write SARIF 2.1.0 (GitHub Code Scanning).
  --markdown <file>       Also write a Markdown summary (PR comment / step summary).
  --json <file>           Also write JSON.
  --no-color              Disable colors (also honors NO_COLOR).

Policy:
  --fail-on <severity>    Exit 1 if any finding is at or above: critical | high |
                          medium | low | info | none (default: high).
  --config <file>         Config file (default: <repo>/.diffward.json).

Other:
  --osv-url <url>         OSV API base URL (default: ${DEFAULT_OSV_URL}, env DIFFWARD_OSV_URL).
  --list-rules            Print the code rules and exit.
  -v, --version           Print the version.
  -h, --help              Show this help.

Exit codes: 0 = no findings at/above --fail-on, 1 = findings at/above --fail-on,
2 = usage or runtime error (e.g. OSV unreachable).

Examples:
  diffward .                                    # full scan of the current repo
  diffward --diff origin/main                   # only what this branch introduces
  diffward --diff origin/main --sarif out.sarif --fail-on critical
  git diff main... | diffward --diff-file -     # any CI that can produce a patch
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
      "deps-scope": { type: "string" },
      format: { type: "string", default: "text" },
      output: { type: "string", short: "o" },
      sarif: { type: "string" },
      markdown: { type: "string" },
      json: { type: "string" },
      "no-color": { type: "boolean" },
      "fail-on": { type: "string" },
      config: { type: "string" },
      "osv-url": { type: "string" },
      "list-rules": { type: "boolean" },
      version: { type: "boolean", short: "v" },
      help: { type: "boolean", short: "h" },
    },
  });

  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (values["list-rules"]) {
    for (const r of RULES.values()) {
      process.stdout.write(`${r.id.padEnd(30)} ${r.severity.padEnd(8)} ${r.cwe.join(",").padEnd(16)} ${r.title}\n`);
    }
    return 0;
  }

  const args = positionals[0] === "scan" ? positionals.slice(1) : positionals;
  if (args.length > 1) throw new UsageError(`expected at most one path, got: ${args.join(" ")}`);
  const path = args[0] ?? ".";

  if (values.diff && values["diff-file"]) throw new UsageError("use either --diff or --diff-file, not both");
  const format = values.format!;
  if (!["text", "json", "sarif", "markdown"].includes(format)) throw new UsageError(`unknown --format: ${format}`);
  const depsScope = values["deps-scope"];
  if (depsScope !== undefined && depsScope !== "changed" && depsScope !== "all") {
    throw new UsageError(`--deps-scope must be "changed" or "all"`);
  }

  const config = loadConfig(gitRoot(path) ?? path, values.config);

  const failOnRaw = values["fail-on"] ?? config.failOn ?? "high";
  if (failOnRaw !== "none" && !isSeverity(failOnRaw)) throw new UsageError(`invalid --fail-on: ${failOnRaw}`);
  const failOn = failOnRaw as Severity | "none";

  const diffPatch = values["diff-file"] !== undefined ? readInput(values["diff-file"]) : undefined;

  const result = await scan({
    path,
    diffBase: values.diff,
    diffPatch,
    code: !values["no-code"],
    deps: !values["no-deps"],
    depsScope,
    osv: createOsvClient(values["osv-url"] ?? process.env.DIFFWARD_OSV_URL ?? DEFAULT_OSV_URL),
    config,
  });

  const color = !values["no-color"] && !process.env.NO_COLOR && !values.output && Boolean(process.stdout.isTTY);
  const render = (fmt: string): string => {
    switch (fmt) {
      case "json":
        return JSON.stringify(toJson(result, failOn), null, 2) + "\n";
      case "sarif":
        return JSON.stringify(toSarif(result), null, 2) + "\n";
      case "markdown":
        return toMarkdown(result);
      default:
        return toText(result, { color }) + "\n";
    }
  };

  if (values.output) writeFileSync(values.output, render(format));
  else process.stdout.write(render(format));
  if (values.sarif) writeFileSync(values.sarif, render("sarif"));
  if (values.markdown) writeFileSync(values.markdown, render("markdown"));
  if (values.json) writeFileSync(values.json, render("json"));

  return failed(result, failOn) ? 1 : 0;
}

function failed(result: ScanResult, failOn: Severity | "none"): boolean {
  return failOn !== "none" && result.findings.some((f) => atLeast(f.severity, failOn));
}

function toJson(result: ScanResult, failOn: Severity | "none") {
  return {
    version: VERSION,
    mode: result.mode,
    failOn,
    failed: failed(result, failOn),
    stats: {
      filesScanned: result.filesScanned,
      lockfiles: result.lockfiles,
      packagesChecked: result.packagesChecked,
      suppressed: result.suppressed,
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

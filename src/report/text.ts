import type { ScanResult } from "../scan.ts";
import { SEVERITIES, type Finding, type Severity } from "../types.ts";

const COLORS: Record<Severity, string> = {
  critical: "\x1b[1;37;41m",
  high: "\x1b[1;31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[2m",
};

export function toText(result: ScanResult, opts: { color: boolean }): string {
  const c = (code: string, s: string) => (opts.color ? `${code}${s}\x1b[0m` : s);
  const dim = (s: string) => c("\x1b[2m", s);
  const bold = (s: string) => c("\x1b[1m", s);
  const out: string[] = [];

  for (const f of result.findings) {
    const label = c(COLORS[f.severity], ` ${f.severity.toUpperCase()} `);
    const where = `${f.file}:${f.line}${f.column ? `:${f.column}` : ""}`;
    out.push(`${label} ${bold(f.ruleId)} ${dim(where)}`);
    out.push(`  ${f.message}`);
    if (f.snippet) out.push(`  ${dim("│")} ${f.snippet}`);
    if (f.help) out.push(`  ${dim("fix:")} ${f.help}`);
    out.push("");
  }

  out.push(summaryLine(result, bold));
  return out.join("\n");
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function summaryLine(result: ScanResult, bold: (s: string) => string): string {
  const counts = countBySeverity(result.findings);
  const parts = SEVERITIES.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  const scope = result.mode === "diff" ? "changed code" : "full scan";
  const stats =
    `${result.filesScanned} file(s), ${result.packagesChecked} package(s) in ${result.lockfiles.length} lockfile(s)` +
    (result.suppressed ? `, ${result.suppressed} suppressed by config` : "");
  if (result.findings.length === 0) return `${bold("diffward:")} no findings (${scope}; ${stats}).`;
  return `${bold("diffward:")} ${result.findings.length} finding(s): ${parts.join(", ")} (${scope}; ${stats}).`;
}

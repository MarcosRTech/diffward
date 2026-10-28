import { gates, type Policy } from "../policy.ts";
import type { ScanResult } from "../scan.ts";
import { SEVERITIES, type Finding, type Severity } from "../types.ts";
import { describe, groupDependencies } from "./group.ts";

const COLORS: Record<Severity, string> = {
  critical: "\x1b[1;37;41m",
  high: "\x1b[1;31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[2m",
};
const MAX_VULNS_PER_PACKAGE = 5;

export function toText(result: ScanResult, opts: { color: boolean; policy: Policy }): string {
  const c = (code: string, s: string) => (opts.color ? `${code}${s}\x1b[0m` : s);
  const dim = (s: string) => c("\x1b[2m", s);
  const bold = (s: string) => c("\x1b[1m", s);
  const label = (s: Severity) => c(COLORS[s], ` ${s.toUpperCase()} `);
  const out: string[] = [];

  const code = result.findings.filter((f) => f.kind === "code");
  const security = code.filter((f) => f.category === "security");
  const quality = code.filter((f) => f.category === "quality");

  const section = (title: string, findings: Finding[]) => {
    if (!findings.length) return;
    out.push(bold(title), "");
    for (const f of findings) {
      const where = `${f.file}:${f.line}${f.column ? `:${f.column}` : ""}`;
      out.push(`${label(f.severity)} ${bold(f.ruleId)} ${dim(where)}`);
      out.push(`  ${f.message}`);
      if (f.snippet) out.push(`  ${dim("│")} ${f.snippet}`);
      if (f.help) out.push(`  ${dim("fix:")} ${f.help}`);
      out.push("");
    }
  };

  section("Security", security);

  const groups = groupDependencies(result.findings);
  if (groups.length) {
    out.push(bold("Vulnerable dependencies"), "");
    for (const g of groups) {
      out.push(`${label(g.worst)} ${bold(`${g.name}@${g.version}`)} ${dim(`${describe(g)} · ${g.file}:${g.line}`)}`);
      const counts = SEVERITIES.map((s) => [s, g.vulns.filter((v) => v.severity === s).length] as const)
        .filter(([, n]) => n > 0)
        .map(([s, n]) => `${n} ${s}`)
        .join(", ");
      const fix = g.fixVersion
        ? `upgrade to ${g.fixVersion} or later${g.unfixed ? ` (${g.unfixed} still without a fix)` : ""}`
        : "no fixed version published yet";
      out.push(`  ${g.vulns.length} advisor${g.vulns.length === 1 ? "y" : "ies"} (${counts}) — ${fix}`);
      if (g.hint) out.push(`  ${dim("fix:")} ${g.hint}`);
      for (const v of g.vulns.slice(0, MAX_VULNS_PER_PACKAGE)) {
        out.push(`  ${dim("·")} ${v.ruleId.padEnd(20)} ${v.severity.padEnd(8)} ${truncate(v.title, 90)}`);
      }
      if (g.vulns.length > MAX_VULNS_PER_PACKAGE) out.push(`  ${dim(`· …and ${g.vulns.length - MAX_VULNS_PER_PACKAGE} more`)}`);
      if (g.dev && !opts.policy.failOnDev) out.push(`  ${dim("dev-only: does not fail the build (use --fail-on-dev to change)")}`);
      out.push("");
    }
  }

  section("Quality", quality);

  out.push(summaryLine(result, opts.policy, bold));
  return out.join("\n");
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function summaryLine(result: ScanResult, policy: Policy, bold: (s: string) => string): string {
  const scope = result.mode === "diff" ? "changed code" : "full scan";
  const extras = [
    result.suppressed ? `${result.suppressed} suppressed by config` : "",
    result.baselined ? `${result.baselined} in baseline` : "",
  ].filter(Boolean);
  const stats =
    `${result.filesScanned} file(s), ${result.packagesChecked} package(s) in ${result.lockfiles.length} lockfile(s)` +
    (extras.length ? `, ${extras.join(", ")}` : "");
  if (result.findings.length === 0) return `${bold("diffward:")} no findings (${scope}; ${stats}).`;

  const security = result.findings.filter((f) => f.kind === "code" && f.category === "security").length;
  const quality = result.findings.filter((f) => f.category === "quality").length;
  const packages = groupDependencies(result.findings).length;
  const parts = [
    security ? `${security} security` : "",
    packages ? `${packages} vulnerable package(s)` : "",
    quality ? `${quality} quality` : "",
  ].filter(Boolean);
  const blocking = result.findings.filter((f) => gates(f, policy));
  const blockingCode = blocking.filter((f) => f.kind === "code").length;
  const blockingPackages = groupDependencies(blocking).length;
  const reasons = [
    blockingCode ? `${blockingCode} code finding(s)` : "",
    blockingPackages ? `${blockingPackages} package(s)` : "",
  ].filter(Boolean);
  const verdict = reasons.length ? `fails the build: ${reasons.join(" and ")}` : "nothing fails the build";
  return `${bold("diffward:")} ${parts.join(", ")} — ${verdict} (${scope}; ${stats}).`;
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

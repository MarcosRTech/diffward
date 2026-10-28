import { gates, type Policy } from "../policy.ts";
import type { ScanResult } from "../scan.ts";
import type { Finding } from "../types.ts";
import { describe, groupDependencies } from "./group.ts";

const ICON = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" } as const;
const MAX_ROWS = 50;

/** Compact report for a PR comment or $GITHUB_STEP_SUMMARY. */
export function toMarkdown(result: ScanResult, policy: Policy): string {
  const scope = result.mode === "diff" ? "changed code" : "full scan";
  const lines = [`### diffward — ${scope}`, ""];

  if (result.findings.length === 0) {
    lines.push(`✅ No findings in ${result.filesScanned} file(s) and ${result.packagesChecked} package(s).`);
    return lines.join("\n") + "\n";
  }

  const blocking = result.findings.filter((f) => gates(f, policy)).length;
  lines.push(blocking ? `❌ **${blocking}** finding(s) fail the build.` : "✅ Nothing fails the build.", "");

  const code = result.findings.filter((f) => f.kind === "code");
  codeTable(lines, "Security", code.filter((f) => f.category === "security"));

  const groups = groupDependencies(result.findings);
  if (groups.length) {
    lines.push("#### Vulnerable dependencies", "", "| Severity | Package | Advisories | Fix |", "|---|---|---|---|");
    for (const g of groups.slice(0, MAX_ROWS)) {
      const ids = g.vulns
        .slice(0, 3)
        .map((v) => `[${v.ruleId}](${v.dependency!.url})`)
        .join(", ");
      const more = g.vulns.length > 3 ? ` +${g.vulns.length - 3}` : "";
      const fix = g.hint ? `\`${cell(g.hint)}\`` : "no fix yet";
      lines.push(
        `| ${ICON[g.worst]} ${g.worst} | \`${g.name}@${g.version}\`<br><sub>${describe(g)}</sub> | ${ids}${more} | ${fix} |`,
      );
    }
    if (groups.length > MAX_ROWS) lines.push("", `…and ${groups.length - MAX_ROWS} more packages.`);
    lines.push("");
  }

  codeTable(lines, "Quality", code.filter((f) => f.category === "quality"));
  return lines.join("\n") + "\n";
}

function codeTable(lines: string[], title: string, findings: Finding[]) {
  if (!findings.length) return;
  lines.push(`#### ${title}`, "", "| Severity | Rule | Location | Details |", "|---|---|---|---|");
  for (const f of findings.slice(0, MAX_ROWS)) {
    lines.push(`| ${ICON[f.severity]} ${f.severity} | \`${f.ruleId}\` | \`${f.file}:${f.line}\` | ${cell(f.message)} |`);
  }
  if (findings.length > MAX_ROWS) lines.push("", `…and ${findings.length - MAX_ROWS} more. See the job log or SARIF.`);
  lines.push("");
}

function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

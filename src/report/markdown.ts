import type { ScanResult } from "../scan.ts";
import { SEVERITIES } from "../types.ts";
import { countBySeverity } from "./text.ts";

const ICON = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" } as const;
const MAX_ROWS = 100;

/** Compact report for a PR comment or $GITHUB_STEP_SUMMARY. */
export function toMarkdown(result: ScanResult): string {
  const counts = countBySeverity(result.findings);
  const scope = result.mode === "diff" ? "changed code" : "full scan";
  const lines = [`### diffward — ${scope}`, ""];

  if (result.findings.length === 0) {
    lines.push(
      `✅ No findings in ${result.filesScanned} file(s) and ${result.packagesChecked} package(s).`,
    );
    return lines.join("\n") + "\n";
  }

  lines.push(
    SEVERITIES.filter((s) => counts[s] > 0)
      .map((s) => `${ICON[s]} **${counts[s]}** ${s}`)
      .join(" · "),
    "",
    "| Severity | Rule | Location | Details |",
    "|---|---|---|---|",
  );
  for (const f of result.findings.slice(0, MAX_ROWS)) {
    const rule = f.dependency ? `[${f.ruleId}](${f.dependency.url})` : `\`${f.ruleId}\``;
    lines.push(`| ${ICON[f.severity]} ${f.severity} | ${rule} | \`${f.file}:${f.line}\` | ${cell(f.message)} |`);
  }
  if (result.findings.length > MAX_ROWS) {
    lines.push("", `…and ${result.findings.length - MAX_ROWS} more. See the full report in the job log or SARIF.`);
  }
  return lines.join("\n") + "\n";
}

function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

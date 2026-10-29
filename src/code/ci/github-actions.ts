import type { RawFinding } from "../rules.ts";

export function isWorkflowFile(file: string): boolean {
  return /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(file) || /(?:^|\/)action\.ya?ml$/.test(file);
}

/**
 * GitHub Actions rules, line-based (no YAML dependency): indentation is enough
 * to know whether a line sits inside a `run:` / `script:` block.
 */
export function analyzeWorkflow(text: string): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = text.split("\n");
  // Triggers anyone on the internet can fire, with data they control.
  const untrustedTrigger = /\b(?:pull_request_target|issue_comment|issues|discussion(?:_comment)?|pull_request_review(?:_comment)?|workflow_run)\b/.test(text);
  const prTarget = /\bpull_request_target\b/.test(text);

  let blockIndent = -1; // indent of the `run:`/`script:` key whose block we're in

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const indent = line.search(/\S/);
    const report = (ruleId: string, col: number, extra: Partial<RawFinding> = {}) =>
      out.push({ ruleId, line: i + 1, column: col + 1, ...extra });

    if (blockIndent >= 0 && indent !== -1 && indent <= blockIndent) blockIndent = -1;

    const script = /^(\s*)(?:-\s+)?(run|script):\s*(\|[-+]?|>[-+]?)?\s*(.*)$/.exec(line);
    let code: string | null = null;
    if (script) {
      if (script[3] || !script[4]) blockIndent = script[1]!.length + (line.trimStart().startsWith("-") ? 2 : 0);
      code = script[4] ?? "";
    } else if (blockIndent >= 0 && indent > blockIndent) {
      code = line;
    }

    if (code) {
      for (const m of code.matchAll(/\$\{\{\s*([^}]+?)\s*\}\}/g)) {
        const expr = m[1]!;
        const level = injectionLevel(expr);
        if (!level) continue;
        const col = line.indexOf(m[0]);
        report("gha/script-injection", col, {
          severity: level === "untrusted" ? (untrustedTrigger ? "critical" : "high") : undefined,
          detail: expr,
        });
      }
      continue;
    }

    const uses = /^\s*(?:-\s+)?uses:\s*['"]?([^'"\s#]+)/.exec(line);
    if (uses) {
      const ref = uses[1]!;
      if (ref.startsWith("./") || ref.startsWith("docker://")) continue;
      const [action, version = ""] = ref.split("@");
      const owner = action!.split("/")[0]!.toLowerCase();
      if (owner === "actions" || owner === "github") continue; // maintained by GitHub itself
      if (/^[0-9a-f]{40}$/.test(version)) continue;
      report("gha/unpinned-action", line.indexOf(ref), { detail: `${action}@${version || "(no ref)"}` });
      continue;
    }

    const ref = /^\s*ref:\s*['"]?\$\{\{\s*(github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)\s*\}\}/.exec(line);
    if (ref && prTarget) {
      report("gha/untrusted-checkout", line.indexOf("ref:"), { detail: ref[1] });
      continue;
    }

    if (/^\s*permissions:\s*['"]?write-all['"]?\s*(?:#.*)?$/.test(line)) report("gha/excessive-permissions", indent);
  }
  return out;
}

/**
 * "untrusted": text anyone can put in an issue, PR, comment or branch name.
 * "caller": values chosen by whoever triggers or calls the workflow (inputs).
 */
function injectionLevel(expr: string): "untrusted" | "caller" | null {
  if (/^github\.head_ref$/.test(expr)) return "untrusted";
  if (
    /^github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|pages|commits|head_commit|workflow_run|release|label)\b/.test(expr) &&
    /\b(?:title|body|message|name|email|ref|label|head_branch|page_name|default_branch|tag_name|description)\b/.test(expr)
  ) {
    return "untrusted";
  }
  // github.ref / ref_name are left out: branch and tag names need push access and
  // `if [ "${{ github.ref }}" = ... ]` is everywhere.
  if (/^(?:inputs|github\.event\.inputs)\./.test(expr)) return "caller";
  return null;
}

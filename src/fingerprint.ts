import { createHash } from "node:crypto";
import type { Finding } from "./types.ts";

/**
 * Stable across unrelated edits: the rule, the file and the trimmed line text
 * (not the line number), so a finding keeps its identity when code moves.
 * Used for SARIF partialFingerprints and for the baseline.
 */
export function fingerprint(f: Finding): string {
  const anchor = f.dependency ? `${f.dependency.name}@${f.dependency.version}` : (f.snippet ?? String(f.line));
  return createHash("sha256").update(`${f.ruleId}\0${f.file}\0${anchor}`).digest("hex").slice(0, 32);
}

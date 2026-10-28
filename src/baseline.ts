import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fingerprint } from "./fingerprint.ts";
import type { Finding } from "./types.ts";

export const DEFAULT_BASELINE = ".diffward-baseline.json";

/**
 * A baseline records the findings that already exist so a first full scan of
 * an old project starts from zero: only what appears afterwards is reported.
 * Entries are fingerprints (rule + file + line text / package@version), so they
 * survive code moving around but not the code itself changing.
 */
interface BaselineFile {
  version: 1;
  createdAt: string;
  findings: { fingerprint: string; ruleId: string; file: string }[];
}

export function baselinePath(root: string, configured?: string): string {
  const p = configured ?? DEFAULT_BASELINE;
  return isAbsolute(p) ? p : join(root, p);
}

export function writeBaseline(path: string, findings: Finding[]): number {
  const seen = new Map<string, BaselineFile["findings"][number]>();
  for (const f of findings) seen.set(fingerprint(f), { fingerprint: fingerprint(f), ruleId: f.ruleId, file: f.file });
  const entries = [...seen.values()].sort((a, b) => a.file.localeCompare(b.file) || a.ruleId.localeCompare(b.ruleId));
  const data: BaselineFile = { version: 1, createdAt: new Date().toISOString(), findings: entries };
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n");
  return entries.length;
}

/** Fingerprints in the baseline, or null when there is no baseline file. */
export function readBaseline(path: string): Set<string> | null {
  if (!existsSync(path)) return null;
  let data: BaselineFile;
  try {
    data = JSON.parse(readFileSync(path, "utf8")) as BaselineFile;
  } catch (err) {
    throw new Error(`invalid baseline file ${path}: ${(err as Error).message}`);
  }
  if (data.version !== 1 || !Array.isArray(data.findings)) throw new Error(`unsupported baseline file ${path}`);
  return new Set(data.findings.map((f) => f.fingerprint));
}

export function applyBaseline(findings: Finding[], baseline: Set<string> | null): { kept: Finding[]; baselined: number } {
  if (!baseline) return { kept: findings, baselined: 0 };
  const kept = findings.filter((f) => !baseline.has(fingerprint(f)));
  return { kept, baselined: findings.length - kept.length };
}

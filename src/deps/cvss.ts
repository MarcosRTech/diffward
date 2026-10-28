import type { Severity } from "../types.ts";

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

function roundUp(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** CVSS v3.0 / v3.1 base score from a vector string, or null if malformed. */
export function cvss3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  const av = W.AV[m.AV as keyof typeof W.AV];
  const ac = W.AC[m.AC as keyof typeof W.AC];
  const ui = W.UI[m.UI as keyof typeof W.UI];
  const c = W.CIA[m.C as keyof typeof W.CIA];
  const i = W.CIA[m.I as keyof typeof W.CIA];
  const a = W.CIA[m.A as keyof typeof W.CIA];
  const scope = m.S;
  if ([av, ac, ui, c, i, a].some((x) => x === undefined) || (scope !== "U" && scope !== "C")) return null;

  const changed = scope === "C";
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR as "N" | "L" | "H"];
  if (pr === undefined) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr * ui!;
  const raw = changed ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundUp(Math.min(raw, 10));
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

/** Maps the labels used by GHSA ("MODERATE") and other databases. */
export function severityFromLabel(label: string): Severity | null {
  switch (label.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return null;
  }
}

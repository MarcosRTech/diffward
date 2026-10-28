import { atLeast, type Finding, type Severity } from "./types.ts";

export type Threshold = Severity | "none";

/** Which findings make the run exit with code 1. */
export interface Policy {
  /** Security findings (code and production dependencies). */
  failOn: Threshold;
  /** Quality findings (bad practices). Off by default. */
  failOnQuality: Threshold;
  /** Count vulnerabilities in dev-only dependencies against failOn. Off by default. */
  failOnDev: boolean;
}

export function gates(f: Finding, p: Policy): boolean {
  if (f.category === "quality") return reaches(f.severity, p.failOnQuality);
  if (f.dependency?.dev && !p.failOnDev) return false;
  return reaches(f.severity, p.failOn);
}

export function failed(findings: Finding[], p: Policy): boolean {
  return findings.some((f) => gates(f, p));
}

function reaches(s: Severity, t: Threshold): boolean {
  return t !== "none" && atLeast(s, t);
}

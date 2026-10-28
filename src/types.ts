export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type FindingKind = "code" | "dependency";

export interface Finding {
  kind: FindingKind;
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  /** Path relative to the scan root, always with forward slashes. */
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  snippet?: string;
  cwe?: string[];
  help?: string;
  dependency?: {
    ecosystem: Ecosystem;
    name: string;
    version: string;
    vulnId: string;
    aliases: string[];
    fixedVersions: string[];
    url: string;
  };
}

export type Ecosystem = "npm" | "PyPI" | "Go" | "crates.io" | "Packagist" | "RubyGems";

export interface Package {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

export function severityRank(s: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(s);
}

export function atLeast(s: Severity, threshold: Severity): boolean {
  return severityRank(s) >= severityRank(threshold);
}

export function isSeverity(v: string): v is Severity {
  return (SEVERITIES as readonly string[]).includes(v);
}

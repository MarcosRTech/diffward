import { compareVersions } from "../deps/osv.ts";
import { fixHint } from "../deps/fix.ts";
import { severityRank, type Finding, type Severity } from "../types.ts";

/** All vulnerabilities of one package version in one lockfile. */
export interface DependencyGroup {
  name: string;
  version: string;
  ecosystem: string;
  file: string;
  line: number;
  dev?: boolean;
  direct?: boolean;
  via?: string;
  worst: Severity;
  vulns: Finding[];
  /** Smallest version that fixes every vulnerability that has a fix. */
  fixVersion?: string;
  /** Vulnerabilities with no fixed version published. */
  unfixed: number;
  hint?: string;
}

export function groupDependencies(findings: Finding[]): DependencyGroup[] {
  const groups = new Map<string, DependencyGroup>();
  for (const f of findings) {
    const d = f.dependency;
    if (!d) continue;
    const key = `${f.file}|${d.name}|${d.version}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        name: d.name,
        version: d.version,
        ecosystem: d.ecosystem,
        file: f.file,
        line: f.line,
        dev: d.dev,
        direct: d.direct,
        via: d.via,
        worst: f.severity,
        vulns: [],
        unfixed: 0,
      };
      groups.set(key, g);
    }
    g.vulns.push(f);
    if (severityRank(f.severity) > severityRank(g.worst)) g.worst = f.severity;
    const fix = d.fixedVersions[0];
    if (!fix) g.unfixed++;
    else if (!g.fixVersion || compareVersions(fix, g.fixVersion) > 0) g.fixVersion = fix;
  }
  for (const g of groups.values()) {
    g.vulns.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    if (g.fixVersion) g.hint = fixHint(g.file, g, g.fixVersion);
  }
  return [...groups.values()].sort(
    (a, b) =>
      severityRank(b.worst) - severityRank(a.worst) ||
      Number(Boolean(a.dev)) - Number(Boolean(b.dev)) ||
      b.vulns.length - a.vulns.length ||
      a.name.localeCompare(b.name),
  );
}

export function describe(g: DependencyGroup): string {
  const parts = [g.ecosystem];
  if (g.direct === true) parts.push("direct");
  if (g.direct === false) parts.push(g.via ? `via ${g.via}` : "transitive");
  if (g.dev === true) parts.push("dev only");
  if (g.dev === false) parts.push("production");
  return parts.join(" · ");
}

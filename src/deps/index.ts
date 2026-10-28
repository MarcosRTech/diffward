import type { Finding, Package } from "../types.ts";
import { parseLockfile, selectLockfiles, type LockedPackage } from "./lockfiles/index.ts";
import type { OsvClient } from "./osv.ts";

export interface DependencyScanInput {
  /** Lockfiles to check, relative paths. */
  files: string[];
  read: (file: string) => string;
  /**
   * When set, only packages that are new or changed compared to this version
   * of each lockfile are checked (returns null if the file did not exist).
   */
  readBase?: (file: string) => string | null;
  osv: OsvClient;
}

export interface DependencyScanResult {
  findings: Finding[];
  lockfiles: string[];
  packagesChecked: number;
}

export async function scanDependencies(input: DependencyScanInput): Promise<DependencyScanResult> {
  const lockfiles = selectLockfiles(input.files);
  const targets: { file: string; pkg: LockedPackage }[] = [];

  for (const file of lockfiles) {
    let packages = dedupe(parseLockfile(file, input.read(file)));
    if (input.readBase) {
      const before = input.readBase(file);
      if (before !== null) {
        let old: Set<string>;
        try {
          old = new Set(parseLockfile(file, before).map(key));
        } catch {
          old = new Set(); // unparseable base: treat everything as new
        }
        packages = packages.filter((p) => !old.has(key(p)));
      }
    }
    for (const pkg of packages) targets.push({ file, pkg });
  }

  if (targets.length === 0) return { findings: [], lockfiles, packagesChecked: 0 };

  // Query each distinct package once even if several lockfiles pin it.
  const unique = new Map<string, Package>();
  for (const t of targets) unique.set(key(t.pkg), t.pkg);
  const uniqueList = [...unique.values()];
  const results = await input.osv.scan(uniqueList);
  const vulnsByKey = new Map(uniqueList.map((p, i) => [key(p), results[i] ?? []]));

  const findings: Finding[] = [];
  for (const { file, pkg } of targets) {
    for (const v of vulnsByKey.get(key(pkg)) ?? []) {
      const cve = v.aliases.find((a) => a.startsWith("CVE-"));
      const fix = v.fixedVersions[0];
      findings.push({
        kind: "dependency",
        ruleId: v.id,
        severity: v.severity,
        title: v.summary,
        message:
          `${pkg.name}@${pkg.version} (${pkg.ecosystem}) is affected by ${v.id}${cve ? ` / ${cve}` : ""}: ${v.summary}.` +
          (fix ? ` Upgrade to ${fix} or later.` : " No fixed version is published yet."),
        file,
        line: pkg.line ?? 1,
        cwe: v.cwe,
        help:
          (fix ? `Upgrade ${pkg.name} to ${fix} or later.` : `No fix is available yet; consider replacing ${pkg.name}.`) +
          (v.severityUnknown ? " Severity was not provided by the advisory database; reported as medium." : "") +
          ` Details: ${v.url}`,
        dependency: {
          ecosystem: pkg.ecosystem,
          name: pkg.name,
          version: pkg.version,
          vulnId: v.id,
          aliases: v.aliases,
          fixedVersions: v.fixedVersions,
          url: v.url,
        },
      });
    }
  }
  return { findings, lockfiles, packagesChecked: uniqueList.length };
}

function key(p: Package): string {
  return `${p.ecosystem}|${p.name}|${p.version}`;
}

function dedupe(pkgs: LockedPackage[]): LockedPackage[] {
  const seen = new Map<string, LockedPackage>();
  for (const p of pkgs) if (!seen.has(key(p))) seen.set(key(p), p);
  return [...seen.values()];
}

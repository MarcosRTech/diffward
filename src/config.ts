import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { isSeverity, type Severity } from "./types.ts";

export const CONFIG_FILE = ".diffward.json";

export interface IgnoredVuln {
  id: string;
  reason?: string;
  /** ISO date; the ignore stops applying after it. */
  until?: string;
}

export interface Config {
  failOn?: Severity | "none";
  /** Threshold for quality (bad-practice) findings. Default "none": they never fail the build. */
  failOnQuality?: Severity | "none";
  /** Let vulnerabilities in dev-only dependencies fail the build. Default false. */
  failOnDev?: boolean;
  /** Run the quality rules. Default true. */
  quality?: boolean;
  /** Baseline file (relative to the repo root). Default ".diffward-baseline.json". */
  baseline?: string;
  /** Glob patterns (gitignore style) of paths to skip. */
  ignorePaths?: string[];
  /** Run code rules on test files too (secrets are always checked). Default false. */
  includeTests?: boolean;
  /** Rule id → "off" or a severity override. */
  rules?: Record<string, "off" | Severity>;
  /** Vulnerability ids (GHSA/CVE/OSV ids or aliases) to accept. */
  ignoreVulnerabilities?: (string | IgnoredVuln)[];
}

export function loadConfig(root: string, explicitPath?: string): Config {
  const path = explicitPath ?? join(root, CONFIG_FILE);
  if (!existsSync(path)) {
    if (explicitPath) throw new Error(`config file not found: ${explicitPath}`);
    return {};
  }
  let parsed: unknown;
  try {
    // Allow // comments so the file can explain why a rule is off.
    parsed = JSON.parse(readFileSync(path, "utf8").replace(/^\s*\/\/.*$/gm, ""));
  } catch (err) {
    throw new Error(`invalid JSON in ${path}: ${(err as Error).message}`);
  }
  return validate(parsed, path);
}

function validate(raw: unknown, path: string): Config {
  const fail = (msg: string): never => {
    throw new Error(`${path}: ${msg}`);
  };
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) fail("must be a JSON object");
  const c = raw as Record<string, unknown>;
  const known = new Set([
    "$schema",
    "failOn",
    "failOnQuality",
    "failOnDev",
    "quality",
    "baseline",
    "ignorePaths",
    "includeTests",
    "rules",
    "ignoreVulnerabilities",
  ]);
  for (const k of Object.keys(c)) if (!known.has(k)) fail(`unknown key "${k}"`);

  for (const key of ["failOn", "failOnQuality"] as const) {
    const v = c[key];
    if (v !== undefined && !(v === "none" || (typeof v === "string" && isSeverity(v)))) {
      fail(`${key} must be one of critical, high, medium, low, info, none`);
    }
  }
  for (const key of ["failOnDev", "quality", "includeTests"] as const) {
    if (c[key] !== undefined && typeof c[key] !== "boolean") fail(`${key} must be true or false`);
  }
  if (c.baseline !== undefined && typeof c.baseline !== "string") fail("baseline must be a path");
  if (c.ignorePaths !== undefined && !(Array.isArray(c.ignorePaths) && c.ignorePaths.every((p) => typeof p === "string"))) {
    fail("ignorePaths must be an array of strings");
  }
  if (c.rules !== undefined) {
    if (typeof c.rules !== "object" || c.rules === null) fail("rules must be an object");
    for (const [id, v] of Object.entries(c.rules as object)) {
      if (!(v === "off" || (typeof v === "string" && isSeverity(v)))) fail(`rules.${id} must be "off" or a severity`);
    }
  }
  if (c.ignoreVulnerabilities !== undefined) {
    if (!Array.isArray(c.ignoreVulnerabilities)) fail("ignoreVulnerabilities must be an array");
    for (const v of c.ignoreVulnerabilities as unknown[]) {
      if (typeof v === "string") continue;
      if (typeof v !== "object" || v === null || typeof (v as IgnoredVuln).id !== "string") {
        fail("ignoreVulnerabilities entries must be a string or { id, reason?, until? }");
      }
      const until = (v as IgnoredVuln).until;
      if (until !== undefined && Number.isNaN(Date.parse(until))) fail(`invalid date in ignoreVulnerabilities: ${until}`);
    }
  }
  return c as Config;
}

/** Ids from ignoreVulnerabilities that are still in effect at `now`. */
export function activeVulnIgnores(config: Config, now = new Date()): Set<string> {
  const ids = new Set<string>();
  for (const v of config.ignoreVulnerabilities ?? []) {
    if (typeof v === "string") ids.add(v);
    else if (!v.until || new Date(v.until) >= now) ids.add(v.id);
  }
  return ids;
}

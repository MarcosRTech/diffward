import type { LockedPackage } from "./index.ts";

const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;

function npm(name: string, version: string, line?: number): LockedPackage | null {
  if (!name || !SEMVER.test(version)) return null; // skips git/file/link/workspace refs
  return { ecosystem: "npm", name, version, line };
}

/** Splits "name@version" honoring scoped names ("@scope/name@1.0.0"). */
export function splitAt(spec: string): [string, string] {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return [spec, ""];
  return [spec.slice(0, at), spec.slice(at + 1)];
}

function lineIndex(text: string): (needle: string) => number | undefined {
  const lines = text.split("\n");
  return (needle) => {
    const i = lines.findIndex((l) => l.includes(needle));
    return i === -1 ? undefined : i + 1;
  };
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parsePackageLock(text: string): LockedPackage[] {
  const json = JSON.parse(text) as {
    packages?: Record<string, { version?: string; name?: string; link?: boolean }>;
    dependencies?: Record<string, V1Dep>;
  };
  const find = lineIndex(text);
  const out: LockedPackage[] = [];

  if (json.packages) {
    for (const [path, info] of Object.entries(json.packages)) {
      if (!path || info.link || !info.version) continue;
      const idx = path.lastIndexOf("node_modules/");
      if (idx === -1) continue; // workspace package, not a dependency
      const name = info.name ?? path.slice(idx + "node_modules/".length);
      const pkg = npm(name, info.version, find(`"${path}"`));
      if (pkg) out.push(pkg);
    }
    return out;
  }

  const walk = (deps: Record<string, V1Dep> | undefined) => {
    for (const [name, info] of Object.entries(deps ?? {})) {
      const pkg = info.version ? npm(name, info.version, find(`"${name}"`)) : null;
      if (pkg) out.push(pkg);
      walk(info.dependencies);
    }
  };
  walk(json.dependencies);
  return out;
}

interface V1Dep {
  version?: string;
  dependencies?: Record<string, V1Dep>;
}

/** bun.lock (text format, Bun >= 1.2). JSON with trailing commas. */
export function parseBunLock(text: string): LockedPackage[] {
  const json = JSON.parse(stripTrailingCommas(text)) as {
    packages?: Record<string, unknown[]>;
  };
  const find = lineIndex(text);
  const out: LockedPackage[] = [];
  for (const [key, entry] of Object.entries(json.packages ?? {})) {
    const spec = entry[0];
    if (typeof spec !== "string") continue;
    const [name, version] = splitAt(spec);
    const pkg = npm(name, version, find(`"${key}": [`));
    if (pkg) out.push(pkg);
  }
  return out;
}

function stripTrailingCommas(text: string): string {
  // Walk the text so commas inside strings are left alone.
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inString) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    if (c === ",") {
      const rest = /^\s*([\]}])/.exec(text.slice(i + 1, i + 200));
      if (rest) continue;
    }
    out += c;
  }
  return out;
}

/** yarn.lock, both classic (v1) and Berry (v2+). */
export function parseYarnLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  let header: { name: string; line: number } | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!line.trim() || line.startsWith("#")) continue;

    if (!/^\s/.test(line)) {
      header = null;
      if (!line.endsWith(":") || line.startsWith("__metadata")) continue;
      const first = line.slice(0, -1).split(",")[0]!.trim().replace(/^"|"$/g, "");
      if (/@(?:workspace|link|portal|file|patch|git|github):/.test(first)) continue;
      const [name] = splitAt(first.replace(/@npm:/, "@"));
      header = { name, line: i + 1 };
      continue;
    }

    const version = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
    if (header && version) {
      const pkg = npm(header.name, version[1]!, header.line);
      if (pkg) out.push(pkg);
      header = null;
    }
  }
  return out;
}

/** pnpm-lock.yaml, lockfile versions 5.x, 6.x and 9.x. */
export function parsePnpmLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  const legacySlashFormat = /^lockfileVersion:\s*'?5/m.test(text);
  let inPackages = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\S/.test(line)) {
      inPackages = line.startsWith("packages:");
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}(\S.*):\s*$/.exec(line);
    if (!key) continue;

    let spec = key[1]!.replace(/^['"]|['"]$/g, "");
    spec = spec.replace(/\(.*$/, ""); // peer-dependency suffix (v6+)
    if (spec.startsWith("/")) spec = spec.slice(1);

    let name: string;
    let version: string;
    if (legacySlashFormat) {
      const slash = spec.lastIndexOf("/");
      name = spec.slice(0, slash);
      version = spec.slice(slash + 1).replace(/_.*$/, "");
    } else {
      [name, version] = splitAt(spec);
    }
    const pkg = npm(name, version, i + 1);
    if (pkg) out.push(pkg);
  }
  return out;
}

import type { LockedPackage, ParseContext } from "./index.ts";
import { globToRegExp } from "../../glob.ts";
import { annotate, readPackageJson, type Manifest } from "./graph.ts";

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

// ----------------------------------------------------------------- package-lock

interface LockEntry {
  version?: string;
  name?: string;
  link?: boolean;
  dev?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parsePackageLock(text: string, ctx?: ParseContext): LockedPackage[] {
  const json = JSON.parse(text) as {
    packages?: Record<string, LockEntry>;
    dependencies?: Record<string, V1Dep>;
  };
  const find = lineIndex(text);
  const out: LockedPackage[] = [];

  if (json.packages) {
    const entries = json.packages;
    const nodeOf = new Map<LockedPackage, string>();
    for (const [path, info] of Object.entries(entries)) {
      if (!path || info.link || !info.version) continue;
      const idx = path.lastIndexOf("node_modules/");
      if (idx === -1) continue; // workspace package, not a dependency
      const name = info.name ?? path.slice(idx + "node_modules/".length);
      const pkg = npm(name, info.version, find(`"${path}"`));
      if (!pkg) continue;
      out.push(pkg);
      nodeOf.set(pkg, path);
    }

    // Node's resolution: look in node_modules next to the dependent, then upwards.
    const resolve = (from: string, dep: string): string | undefined => {
      let base = from;
      for (;;) {
        const candidate = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
        if (entries[candidate]) return candidate;
        if (!base) return undefined;
        const up = base.lastIndexOf("/node_modules/");
        base = up === -1 ? "" : base.slice(0, up);
      }
    };
    const edges = new Map<string, string[]>();
    const prodRoots: string[] = [];
    const devRoots: string[] = [];
    for (const [path, info] of Object.entries(entries)) {
      const deps = [info.dependencies, info.optionalDependencies, info.peerDependencies].flatMap((d) => Object.keys(d ?? {}));
      const isWorkspace = !path.includes("node_modules/");
      const targets = deps.map((d) => resolve(path, d)).filter((t): t is string => Boolean(t));
      if (isWorkspace) {
        prodRoots.push(...targets);
        devRoots.push(...Object.keys(info.devDependencies ?? {}).map((d) => resolve(path, d)).filter((t): t is string => Boolean(t)));
      } else {
        edges.set(path, targets);
      }
    }
    annotate(out, { edges, prodRoots, devRoots, nameOf: (n) => n.slice(n.lastIndexOf("node_modules/") + 13) }, (p) => nodeOf.get(p));
    // The lockfile's own dev flag is authoritative when present (v2/v3).
    for (const p of out) {
      const flag = entries[nodeOf.get(p)!]?.dev;
      if (flag !== undefined) p.dev = flag;
    }
    return out;
  }

  // v1 marks dev-only packages with "dev": true and omits the flag otherwise.
  const manifest = readPackageJson(ctx?.sibling("package.json") ?? null);
  const directNames = manifest ? new Set([...manifest.dependencies, ...manifest.devDependencies]) : null;
  const walk = (deps: Record<string, V1Dep> | undefined, top: boolean) => {
    for (const [name, info] of Object.entries(deps ?? {})) {
      const pkg = info.version ? npm(name, info.version, find(`"${name}"`)) : null;
      if (pkg) {
        pkg.dev = info.dev === true;
        if (!top) pkg.direct = false;
        else if (directNames) pkg.direct = directNames.has(name);
        out.push(pkg);
      }
      walk(info.dependencies, false);
    }
  };
  walk(json.dependencies, true);
  return out;
}

interface V1Dep {
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, V1Dep>;
}

// ----------------------------------------------------------------- bun.lock

/** bun.lock (text format, Bun >= 1.2). JSON with trailing commas. */
export function parseBunLock(text: string): LockedPackage[] {
  const json = JSON.parse(stripTrailingCommas(text)) as {
    workspaces?: Record<string, Record<string, Record<string, string> | string | undefined>>;
    packages?: Record<string, unknown[]>;
  };
  const find = lineIndex(text);
  const out: LockedPackage[] = [];
  const nodeOf = new Map<LockedPackage, string>();
  const packages = json.packages ?? {};

  for (const [key, entry] of Object.entries(packages)) {
    const spec = entry[0];
    if (typeof spec !== "string") continue;
    const [name, version] = splitAt(spec);
    const pkg = npm(name, version, find(`"${key}": [`));
    if (pkg) {
      out.push(pkg);
      nodeOf.set(pkg, key);
    }
  }

  // Nested versions are keyed "parent/child" (scoped names keep their slash).
  const segments = (key: string): string[] => {
    const out: string[] = [];
    let scope: string | null = null;
    for (const t of key.split("/")) {
      if (t.startsWith("@") && scope === null) scope = t;
      else if (scope !== null) {
        out.push(`${scope}/${t}`);
        scope = null;
      } else out.push(t);
    }
    return out;
  };
  const resolve = (from: string[], dep: string): string | undefined => {
    for (let i = from.length; i >= 0; i--) {
      const candidate = [...from.slice(0, i), dep].join("/");
      if (packages[candidate]) return candidate;
    }
    return undefined;
  };
  const depsOf = (meta: unknown): string[] => {
    if (!meta || typeof meta !== "object") return [];
    const m = meta as Record<string, Record<string, string> | undefined>;
    return [m.dependencies, m.optionalDependencies, m.peerDependencies].flatMap((d) => Object.keys(d ?? {}));
  };

  const edges = new Map<string, string[]>();
  for (const [key, entry] of Object.entries(packages)) {
    const meta = entry.find((x, i) => i > 0 && x && typeof x === "object" && !Array.isArray(x));
    const from = segments(key);
    edges.set(key, depsOf(meta).map((d) => resolve(from, d)).filter((t): t is string => Boolean(t)));
  }
  const prodRoots: string[] = [];
  const devRoots: string[] = [];
  for (const ws of Object.values(json.workspaces ?? {})) {
    const names = (s: string) => Object.keys((ws[s] as Record<string, string> | undefined) ?? {});
    const wsName = typeof ws.name === "string" ? [ws.name] : [];
    const r = (d: string) => resolve(wsName, d);
    prodRoots.push(...["dependencies", "optionalDependencies", "peerDependencies"].flatMap(names).map(r).filter((t): t is string => Boolean(t)));
    devRoots.push(...names("devDependencies").map(r).filter((t): t is string => Boolean(t)));
  }
  annotate(out, { edges, prodRoots, devRoots, nameOf: (k) => segments(k).pop() ?? k }, (p) => nodeOf.get(p));
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

// ----------------------------------------------------------------- yarn.lock

/** yarn.lock, both classic (v1) and Berry (v2+). */
export function parseYarnLock(text: string, ctx?: ParseContext): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  // Every "name@range" spec in a block header resolves to that block.
  const blockOfSpec = new Map<string, number>();
  const blocks: { pkg: LockedPackage | null; deps: string[] }[] = [];
  let current: (typeof blocks)[number] | null = null;
  let headerName = "";
  let headerLine = 0;
  let inDeps = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!line.trim() || line.startsWith("#")) continue;

    if (!/^\s/.test(line)) {
      current = null;
      inDeps = false;
      if (!line.endsWith(":") || line.startsWith("__metadata")) continue;
      const specs = line.slice(0, -1).split(",").map((s) => s.trim().replace(/^"|"$/g, ""));
      const first = specs[0]!;
      current = { pkg: null, deps: [] };
      blocks.push(current);
      for (const s of specs) blockOfSpec.set(s, blocks.length - 1);
      if (/@(?:workspace|link|portal|file|patch|git|github):/.test(first)) {
        headerName = "";
        continue;
      }
      [headerName] = splitAt(first.replace(/@npm:/, "@"));
      headerLine = i + 1;
      continue;
    }
    if (!current) continue;

    const version = /^\s{2}version:?\s+"?([^"\s]+)"?/.exec(line);
    if (version && headerName && !current.pkg) {
      current.pkg = npm(headerName, version[1]!, headerLine);
      if (current.pkg) out.push(current.pkg);
      continue;
    }
    if (/^\s{2}(?:dependencies|optionalDependencies|peerDependencies):?\s*$/.test(line)) {
      inDeps = true;
      continue;
    }
    if (/^\s{2}\S/.test(line)) {
      inDeps = false;
      continue;
    }
    const dep = inDeps && /^\s{4}"?([^"\s:]+)"?:?\s+"?([^"]+?)"?\s*$/.exec(line);
    if (dep) current.deps.push(berrySpec(dep[1]!, dep[2]!));
  }

  const manifest = workspaceManifest(ctx);
  if (manifest) {
    const node = (spec: string) => {
      const b = blockOfSpec.get(spec) ?? blockOfSpec.get(spec.replace("@npm:", "@"));
      return b === undefined ? undefined : String(b);
    };
    const edges = new Map(blocks.map((b, i) => [String(i), b.deps.map(node).filter((n): n is string => Boolean(n))]));
    const roots = (names: string[]) =>
      names.map((n) => node(berrySpec(n, manifest.ranges.get(n) ?? ""))).filter((n): n is string => Boolean(n));
    const blockIndex = new Map(blocks.map((b, i) => [b.pkg, String(i)]));
    annotate(
      out,
      {
        edges,
        prodRoots: roots(manifest.dependencies),
        devRoots: roots(manifest.devDependencies),
        nameOf: (n) => blocks[Number(n)]?.pkg?.name ?? n,
      },
      (p) => blockIndex.get(p),
    );
  }
  return out;
}

/**
 * Root package.json merged with every workspace's: in a yarn monorepo the
 * direct dependencies are spread across workspaces/*\/package.json.
 */
function workspaceManifest(ctx?: ParseContext): Manifest | null {
  const rootText = ctx?.sibling("package.json") ?? null;
  const root = readPackageJson(rootText);
  if (!root || !ctx || !rootText) return root;
  let patterns: string[] = [];
  try {
    const ws = (JSON.parse(rootText) as { workspaces?: string[] | { packages?: string[] } }).workspaces;
    patterns = Array.isArray(ws) ? ws : (ws?.packages ?? []);
  } catch {
    return root;
  }
  const matchers = patterns.map((p) => globToRegExp(`/${p.replace(/\/+$/, "")}/package.json`));
  for (const file of ctx.files) {
    if (file === "package.json" || !matchers.some((m) => m.test(file))) continue;
    const m = readPackageJson(ctx.sibling(file));
    if (!m) continue;
    root.dependencies.push(...m.dependencies);
    root.devDependencies.push(...m.devDependencies);
    for (const [k, v] of m.ranges) if (!root.ranges.has(k)) root.ranges.set(k, v);
  }
  return root;
}

/** Berry writes `name: "npm:^1.0.0"`, classic `name "^1.0.0"`; headers use `name@<that>`. */
function berrySpec(name: string, range: string): string {
  return `${name}@${range}`;
}

// ----------------------------------------------------------------- pnpm-lock

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
    const parsed = pnpmKey(key[1]!, legacySlashFormat);
    if (!parsed) continue;
    const pkg = npm(parsed[0], parsed[1], i + 1);
    if (pkg) out.push(pkg);
  }
  if (!legacySlashFormat) annotatePnpm(out, lines);
  return out;
}

function pnpmKey(raw: string, legacy: boolean): [string, string] | null {
  let spec = raw.replace(/^['"]|['"]$/g, "").replace(/\(.*$/, "");
  if (spec.startsWith("/")) spec = spec.slice(1);
  if (legacy) {
    const slash = spec.lastIndexOf("/");
    return [spec.slice(0, slash), spec.slice(slash + 1).replace(/_.*$/, "")];
  }
  return splitAt(spec);
}

/**
 * v6/v9: importers list direct deps (dependencies / devDependencies) and the
 * snapshots (v9) or packages (v6) sections list each package's dependencies.
 */
function annotatePnpm(pkgs: LockedPackage[], lines: string[]) {
  const edges = new Map<string, string[]>();
  const prodRoots: string[] = [];
  const devRoots: string[] = [];
  let section = "";
  let importer = false;
  let rootKind: "prod" | "dev" | null = null;
  let current: string | null = null;
  let inDeps = false;
  let pendingRootName: string | null = null;

  const ref = (name: string, version: string) => `${name}@${version.replace(/^['"]|['"]$/g, "").replace(/\(.*$/, "")}`;

  for (const line of lines) {
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, "");
      current = null;
      continue;
    }
    if (section === "importers") {
      if (/^ {2}\S/.test(line)) {
        importer = true;
        rootKind = null;
        continue;
      }
      const kind = /^ {4}(dependencies|optionalDependencies|devDependencies):\s*$/.exec(line);
      if (kind) {
        rootKind = kind[1] === "devDependencies" ? "dev" : "prod";
        continue;
      }
      if (/^ {4}\S/.test(line)) {
        rootKind = null;
        continue;
      }
      const dep = /^ {6}['"]?([^\s'":][^'":]*)['"]?:\s*(.*)$/.exec(line);
      if (importer && rootKind && dep) {
        if (dep[2]) (rootKind === "dev" ? devRoots : prodRoots).push(ref(dep[1]!, dep[2]));
        else pendingRootName = dep[1]!; // v9: version on the next lines
        continue;
      }
      const version = /^ {8}version:\s*(.+)$/.exec(line);
      if (importer && rootKind && pendingRootName && version) {
        if (!version[1]!.startsWith("link:")) (rootKind === "dev" ? devRoots : prodRoots).push(ref(pendingRootName, version[1]!));
        pendingRootName = null;
      }
      continue;
    }
    if (section === "snapshots" || section === "packages") {
      const key = /^ {2}(\S.*):\s*$/.exec(line);
      if (key) {
        const parsed = pnpmKey(key[1]!, false);
        current = parsed ? `${parsed[0]}@${parsed[1]}` : null;
        if (current && !edges.has(current)) edges.set(current, []);
        inDeps = false;
        continue;
      }
      if (/^ {4}(?:dependencies|optionalDependencies):\s*$/.test(line)) {
        inDeps = true;
        continue;
      }
      if (/^ {4}\S/.test(line)) {
        inDeps = false;
        continue;
      }
      const dep = inDeps && current && /^ {6}['"]?([^\s'":][^'":]*)['"]?:\s*(.+)$/.exec(line);
      if (dep && current) edges.get(current)!.push(ref(dep[1]!, dep[2]!));
    }
  }
  if (!prodRoots.length && !devRoots.length) return;
  annotate(pkgs, { edges, prodRoots, devRoots, nameOf: (n) => splitAt(n)[0] }, (p) => `${p.name}@${p.version}`);
}

import type { Ecosystem } from "../../types.ts";
import type { LockedPackage } from "./index.ts";

/** PEP 503 normalization, which is what OSV indexes PyPI names by. */
export function normalizePyPI(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/** requirements*.txt — only exact pins (`==` / `===`) can be checked. */
export function parseRequirements(text: string, path = "requirements.txt"): LockedPackage[] {
  const out: LockedPackage[] = [];
  // requirements-dev.txt, requirements/test.txt, dev-requirements.txt...
  const dev = /(?:^|[/_.-])(?:dev|devel|develop|test|tests|testing|lint|docs|ci)(?:[/_.-]|$)/i.test(path.replace(/requirements/gi, ""))
    ? true
    : undefined;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,\\]+)/.exec(line);
    if (m) out.push({ ecosystem: "PyPI", name: normalizePyPI(m[1]!), version: m[2]!, line: i + 1, dev });
  }
  return out;
}

/** Pipfile.lock */
export function parsePipfileLock(text: string): LockedPackage[] {
  const json = JSON.parse(text) as Record<string, Record<string, { version?: string }>>;
  const lines = text.split("\n");
  const out: LockedPackage[] = [];
  for (const section of ["default", "develop"]) {
    for (const [name, info] of Object.entries(json[section] ?? {})) {
      const version = info.version?.replace(/^===?/, "");
      if (!version) continue;
      const idx = lines.findIndex((l) => l.includes(`"${name}": {`));
      out.push({ ecosystem: "PyPI", name: normalizePyPI(name), version, line: idx + 1 || undefined, dev: section === "develop" });
    }
  }
  return out;
}

/**
 * TOML lockfiles made of `[[package]]` tables with `name` / `version` keys:
 * poetry.lock, uv.lock, pdm.lock and Cargo.lock.
 */
export function parseTomlPackageTables(
  text: string,
  ecosystem: Ecosystem,
  opts: { skipLocal?: boolean } = {},
): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  let cur: { name?: string; version?: string; line: number; local: boolean; dev?: boolean } | null = null;

  const flush = () => {
    if (cur?.name && cur.version && !(opts.skipLocal && cur.local)) {
      const name = ecosystem === "PyPI" ? normalizePyPI(cur.name) : cur.name;
      out.push({ ecosystem, name, version: cur.version, line: cur.line, dev: cur.dev });
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line.startsWith("[")) {
      if (line === "[[package]]") {
        flush();
        cur = { line: i + 1, local: true };
      } else if (!line.startsWith("[package.") && !line.startsWith("[[package.")) {
        flush();
        cur = null;
      }
      continue;
    }
    if (!cur) continue;
    // poetry < 1.2: category = "dev"; poetry >= 1.2: groups = ["dev"] (no "main")
    const category = /^category\s*=\s*"(\w+)"/.exec(line);
    if (category) cur.dev = category[1] === "dev";
    const groups = /^groups\s*=\s*\[(.*)\]/.exec(line);
    if (groups) cur.dev = !/"main"/.test(groups[1]!);
    const kv = /^(name|version|source)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const value = kv[2]!.trim();
    if (kv[1] === "source") {
      // Cargo: `source = "registry+..."`; uv: `source = { registry = "..." }`.
      if (/registry/.test(value)) cur.local = false;
    } else if (cur[kv[1] as "name" | "version"] === undefined) {
      cur[kv[1] as "name" | "version"] = value.replace(/^"|"$/g, "");
    }
  }
  flush();
  return out;
}

/** go.mod `require` directives. */
export function parseGoMod(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  let inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ")") {
      inBlock = false;
      continue;
    }
    const body = inBlock ? line : /^require\s+(.+)$/.exec(line)?.[1];
    const m = body && /^(\S+)\s+(v\S+)$/.exec(body);
    if (m) out.push({ ecosystem: "Go", name: m[1]!, version: m[2]!, line: i + 1 });
  }
  return out;
}

/** go.sum — used only when there is no go.mod next to it. */
export function parseGoSum(text: string): LockedPackage[] {
  const seen = new Map<string, LockedPackage>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\S+)\s+(v[^/\s]+)(\/go\.mod)?\s/.exec(lines[i]!);
    if (!m) continue;
    const key = `${m[1]}@${m[2]}`;
    if (!seen.has(key)) seen.set(key, { ecosystem: "Go", name: m[1]!, version: m[2]!, line: i + 1 });
  }
  return [...seen.values()];
}

/** composer.lock */
export function parseComposerLock(text: string): LockedPackage[] {
  const json = JSON.parse(text) as Record<string, { name: string; version: string }[]>;
  const lines = text.split("\n");
  const out: LockedPackage[] = [];
  for (const section of ["packages", "packages-dev"]) {
    for (const p of json[section] ?? []) {
      if (!p.name || !p.version || p.version.startsWith("dev-")) continue;
      const idx = lines.findIndex((l) => l.includes(`"name": "${p.name}"`));
      out.push({
        ecosystem: "Packagist",
        name: p.name,
        version: p.version.replace(/^v/, ""),
        line: idx + 1 || undefined,
      });
    }
  }
  return out;
}

/** Gemfile.lock — the `specs:` list of the GEM section. */
export function parseGemfileLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  let section = "";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\S/.test(line)) {
      section = line.trim();
      continue;
    }
    if (section !== "GEM") continue;
    const m = /^ {4}([^\s(]+) \(([^)]+)\)$/.exec(line);
    if (!m) continue;
    const version = m[2]!.split("-")[0]!; // drop platform suffix (e.g. -x86_64-linux)
    out.push({ ecosystem: "RubyGems", name: m[1]!, version, line: i + 1 });
  }
  return out;
}

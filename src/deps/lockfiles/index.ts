import type { Package } from "../../types.ts";
import { parseBunLock, parsePackageLock, parsePnpmLock, parseYarnLock } from "./npm.ts";
import {
  parseComposerLock,
  parseGemfileLock,
  parseGoMod,
  parseGoSum,
  parsePipfileLock,
  parseRequirements,
  parseTomlPackageTables,
} from "./others.ts";

export interface LockedPackage extends Package {
  /** 1-based line in the lockfile where the package is declared, if known. */
  line?: number;
  /** Only needed for development (undefined when the lockfile doesn't say). */
  dev?: boolean;
  /** Listed in the manifest, as opposed to pulled in by another package. */
  direct?: boolean;
  /** For transitive packages: the direct dependency that pulls it in. */
  via?: string;
}

export interface ParseContext {
  /** Lockfile path relative to the scan root. */
  path: string;
  /** Text of a file relative to the lockfile's directory (e.g. "package.json"), or null. */
  sibling: (name: string) => string | null;
  /** Files under the lockfile's directory, relative to it (for workspace manifests). */
  files: string[];
}

type Parser = (text: string, ctx: ParseContext) => LockedPackage[];

const PARSERS: { match: (base: string) => boolean; parse: Parser }[] = [
  { match: (b) => b === "package-lock.json" || b === "npm-shrinkwrap.json", parse: parsePackageLock },
  { match: (b) => b === "bun.lock", parse: parseBunLock },
  { match: (b) => b === "yarn.lock", parse: parseYarnLock },
  { match: (b) => b === "pnpm-lock.yaml", parse: parsePnpmLock },
  { match: (b) => /^requirements.*\.txt$/.test(b) || b === "constraints.txt", parse: (t, ctx) => parseRequirements(t, ctx.path) },
  { match: (b) => b === "Pipfile.lock", parse: parsePipfileLock },
  { match: (b) => b === "poetry.lock" || b === "pdm.lock", parse: (t) => parseTomlPackageTables(t, "PyPI") },
  { match: (b) => b === "uv.lock", parse: (t) => parseTomlPackageTables(t, "PyPI", { skipLocal: true }) },
  { match: (b) => b === "Cargo.lock", parse: (t) => parseTomlPackageTables(t, "crates.io", { skipLocal: true }) },
  { match: (b) => b === "go.mod", parse: parseGoMod },
  { match: (b) => b === "go.sum", parse: parseGoSum },
  { match: (b) => b === "composer.lock", parse: parseComposerLock },
  { match: (b) => b === "Gemfile.lock", parse: parseGemfileLock },
];

function basename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

export function isLockfile(path: string): boolean {
  const base = basename(path);
  return PARSERS.some((p) => p.match(base));
}

/** Throws a descriptive error if the file is malformed. */
export function parseLockfile(
  path: string,
  text: string,
  sibling: ParseContext["sibling"] = () => null,
  files: string[] = [],
): LockedPackage[] {
  const parser = PARSERS.find((p) => p.match(basename(path)));
  if (!parser) return [];
  try {
    return parser.parse(text, { path, sibling, files });
  } catch (err) {
    throw new Error(`failed to parse ${path}: ${(err as Error).message}`);
  }
}

/**
 * go.sum lists every module ever considered, so it is only used when the same
 * directory has no go.mod.
 */
export function selectLockfiles(paths: string[]): string[] {
  const set = new Set(paths);
  return paths.filter((p) => {
    if (!isLockfile(p)) return false;
    if (basename(p) === "go.sum") return !set.has(p.slice(0, -"go.sum".length) + "go.mod");
    return true;
  });
}

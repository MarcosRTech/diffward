import { execFileSync } from "node:child_process";

/** Lines added or modified per file (1-based line numbers in the new version). */
export type ChangedLines = Map<string, Set<number>>;

/**
 * Parses a unified diff and returns, for each file in the new version, the line
 * numbers that were added. Deleted files are omitted.
 */
export function parseUnifiedDiff(diff: string): ChangedLines {
  const changed: ChangedLines = new Map();
  let current: Set<number> | undefined;
  let newLine = 0;

  for (const raw of diff.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;

    if (line.startsWith("diff --git ")) {
      current = undefined;
      continue;
    }
    if (line.startsWith("+++ ")) {
      const target = stripDiffPath(line.slice(4));
      if (target === null) {
        current = undefined;
      } else {
        current = changed.get(target) ?? new Set();
        changed.set(target, current);
      }
      continue;
    }
    if (line.startsWith("--- ")) continue;

    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk) {
      newLine = Number(hunk[1]);
      continue;
    }
    if (!current) continue;

    if (line.startsWith("+")) {
      current.add(newLine);
      newLine++;
    } else if (line.startsWith(" ")) {
      newLine++;
    }
    // "-" lines and "\ No newline at end of file" don't advance the new side.
  }
  return changed;
}

function stripDiffPath(p: string): string | null {
  let path = p.split("\t")[0]!.trim();
  if (path === "/dev/null") return null;
  if (path.startsWith('"') && path.endsWith('"')) {
    path = JSON.parse(path) as string;
  }
  if (path.startsWith("b/")) path = path.slice(2);
  return path;
}

export function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

export function gitRoot(cwd: string): string | null {
  try {
    return git(cwd, ["rev-parse", "--show-toplevel"]).trim();
  } catch {
    return null;
  }
}

export interface GitDiff {
  mergeBase: string;
  changed: ChangedLines;
}

/**
 * Diff between the merge-base of `baseRef` and HEAD, and the working tree.
 * In CI the working tree equals HEAD; locally this also covers uncommitted
 * edits and untracked files, which is what you want before pushing.
 */
export function diffAgainst(root: string, baseRef: string): GitDiff {
  let mergeBase: string;
  try {
    mergeBase = git(root, ["merge-base", baseRef, "HEAD"]).trim();
  } catch (err) {
    throw new Error(
      `could not find a merge-base between "${baseRef}" and HEAD. ` +
        `In CI, check out with full history (e.g. actions/checkout with fetch-depth: 0).`,
    );
  }
  const patch = git(root, [
    "diff",
    "--no-color",
    "--no-ext-diff",
    "--unified=0",
    "--find-renames",
    mergeBase,
  ]);
  const changed = parseUnifiedDiff(patch);

  const untracked = git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    .split("\0")
    .filter(Boolean);
  for (const file of untracked) changed.set(file, ALL_LINES);

  return { mergeBase, changed };
}

/** Sentinel meaning "every line of this file is new". */
export const ALL_LINES: Set<number> = new Proxy(new Set<number>(), {
  get(target, prop) {
    if (prop === "has") return () => true;
    const value = Reflect.get(target, prop);
    return typeof value === "function" ? value.bind(target) : value;
  },
});

export function readFileAtRevision(root: string, rev: string, file: string): string | null {
  try {
    return git(root, ["show", `${rev}:${file}`]);
  } catch {
    return null;
  }
}

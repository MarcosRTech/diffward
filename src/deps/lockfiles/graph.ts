import type { LockedPackage } from "./index.ts";

/**
 * Dependency graph of one lockfile, used to tell production from dev-only
 * packages and direct from transitive ones. Nodes are lockfile-specific keys
 * (a package-lock path, a bun.lock key, "name@version"...).
 */
export interface DepGraph {
  edges: Map<string, string[]>;
  prodRoots: string[];
  devRoots: string[];
  /** Package name shown for a node in "via ..." hints. */
  nameOf: (node: string) => string;
}

/**
 * Annotates packages in place. `nodeOf` maps a package back to its graph node.
 * Packages the graph doesn't reach keep `dev`/`direct` undefined (unknown).
 */
export function annotate(pkgs: LockedPackage[], graph: DepGraph, nodeOf: (p: LockedPackage) => string | undefined) {
  const prod = reach(graph, graph.prodRoots);
  const dev = reach(graph, graph.devRoots);
  const roots = new Set([...graph.prodRoots, ...graph.devRoots]);
  for (const p of pkgs) {
    const node = nodeOf(p);
    if (!node) continue;
    if (prod.has(node)) p.dev = false;
    else if (dev.has(node)) p.dev = true;
    if (!prod.has(node) && !dev.has(node)) continue;
    p.direct = roots.has(node);
    if (!p.direct) {
      const root = prod.get(node) ?? dev.get(node);
      if (root) p.via = graph.nameOf(root);
    }
  }
}

/** Breadth-first: every reachable node → the root it was first reached from. */
function reach(graph: DepGraph, roots: string[]): Map<string, string> {
  const via = new Map<string, string>();
  const queue: string[] = [];
  for (const r of roots) {
    if (!via.has(r)) {
      via.set(r, r);
      queue.push(r);
    }
  }
  while (queue.length) {
    const node = queue.shift()!;
    for (const next of graph.edges.get(node) ?? []) {
      if (via.has(next)) continue;
      via.set(next, via.get(node)!);
      queue.push(next);
    }
  }
  return via;
}

export interface Manifest {
  dependencies: string[];
  devDependencies: string[];
  /** name → range, for lockfiles that key packages by "name@range" (yarn). */
  ranges: Map<string, string>;
}

/** package.json → its direct dependency names (optional/peer count as production). */
export function readPackageJson(text: string | null): Manifest | null {
  if (!text) return null;
  let json: Record<string, Record<string, string> | undefined>;
  try {
    json = JSON.parse(text);
  } catch {
    return null;
  }
  const ranges = new Map<string, string>();
  const names = (...sections: string[]) =>
    sections.flatMap((s) =>
      Object.entries(json[s] ?? {}).map(([name, range]) => {
        ranges.set(name, String(range));
        return name;
      }),
    );
  return {
    dependencies: names("dependencies", "optionalDependencies", "peerDependencies"),
    devDependencies: names("devDependencies"),
    ranges,
  };
}

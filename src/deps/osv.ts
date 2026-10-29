import type { Package, Severity } from "../types.ts";
import { cvss3BaseScore, severityFromLabel, severityFromScore } from "./cvss.ts";
import type { OsvCache } from "./osv-cache.ts";

export const DEFAULT_OSV_URL = "https://api.osv.dev";

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  /** True when no database gave a severity and we fell back to a default. */
  severityUnknown: boolean;
  cwe: string[];
  fixedVersions: string[];
  url: string;
}

interface OsvRecord {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: Record<string, string>[] }[];
    ecosystem_specific?: { severity?: string };
  }[];
}

export interface OsvProgress {
  phase: "query" | "advisories";
  done: number;
  total: number;
  /** Advisories served from the on-disk cache so far. */
  cached?: number;
}

export interface OsvClient {
  /** For each package, the vulnerabilities affecting that exact version. */
  scan(packages: Package[], onProgress?: (p: OsvProgress) => void): Promise<Vulnerability[][]>;
}

const BATCH_SIZE = 1000;
const CONCURRENCY = 32;
const REQUEST_TIMEOUT_MS = 30_000;

export function createOsvClient(
  baseUrl = DEFAULT_OSV_URL,
  fetchImpl: typeof fetch = fetch,
  opts: { cache?: OsvCache } = {},
): OsvClient {
  const base = baseUrl.replace(/\/+$/, "");
  const records = new Map<string, Promise<OsvRecord | null>>();
  /** `modified` per advisory id, as reported by querybatch: the cache key. */
  const modifiedOf = new Map<string, string>();
  let cachedHits = 0;

  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const res = await fetchImpl(`${base}${path}`, {
          ...init,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          headers: { "content-type": "application/json", "user-agent": "diffward" },
        });
        if (res.ok) return (await res.json()) as T;
        if (res.status === 404) return null as T;
        lastError = new Error(`OSV ${path} returned HTTP ${res.status}`);
        if (res.status < 500 && res.status !== 429) break;
      } catch (err) {
        lastError = err;
      }
      await new Promise((r) => setTimeout(r, 300 * 2 ** attempt));
    }
    throw new Error(`OSV request failed (${base}): ${(lastError as Error)?.message ?? lastError}`);
  }

  function record(id: string): Promise<OsvRecord | null> {
    let p = records.get(id);
    if (!p) {
      const modified = modifiedOf.get(id);
      const hit = opts.cache?.get(id, modified) as OsvRecord | undefined;
      if (hit) {
        cachedHits++;
        p = Promise.resolve(hit);
      } else {
        p = request<OsvRecord | null>(`/v1/vulns/${encodeURIComponent(id)}`).then((rec) => {
          if (rec) opts.cache?.set(id, modified, rec);
          return rec;
        });
      }
      records.set(id, p);
    }
    return p;
  }

  return {
    async scan(packages, onProgress) {
      // All batches in parallel: each is one request of up to 1000 packages.
      const chunks: Package[][] = [];
      for (let i = 0; i < packages.length; i += BATCH_SIZE) chunks.push(packages.slice(i, i + BATCH_SIZE));
      let batchesDone = 0;
      onProgress?.({ phase: "query", done: 0, total: packages.length });
      const responses = await Promise.all(
        chunks.map(async (chunk) => {
          const body = {
            queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
          };
          const res = await request<{ results: { vulns?: { id: string; modified?: string }[] }[] }>("/v1/querybatch", {
            method: "POST",
            body: JSON.stringify(body),
          });
          batchesDone++;
          onProgress?.({ phase: "query", done: Math.min(batchesDone * BATCH_SIZE, packages.length), total: packages.length });
          return res;
        }),
      );
      const idsPerPackage: string[][] = [];
      for (const res of responses) {
        for (const r of res.results) {
          for (const v of r.vulns ?? []) if (v.modified) modifiedOf.set(v.id, v.modified);
          idsPerPackage.push((r.vulns ?? []).map((v) => v.id));
        }
      }

      const allIds = [...new Set(idsPerPackage.flat())];
      let fetched = 0;
      onProgress?.({ phase: "advisories", done: 0, total: allIds.length, cached: 0 });
      await mapLimit(allIds, CONCURRENCY, async (id) => {
        const rec = await record(id);
        fetched++;
        onProgress?.({ phase: "advisories", done: fetched, total: allIds.length, cached: cachedHits });
        return rec;
      });

      const out: Vulnerability[][] = [];
      for (let i = 0; i < packages.length; i++) {
        const pkg = packages[i]!;
        const recs = (await Promise.all((idsPerPackage[i] ?? []).map(record))).filter(
          (r): r is OsvRecord => r !== null,
        );
        out.push(await mergeAliases(recs, pkg, record));
      }
      return out;
    },
  };
}

/**
 * OSV returns the same issue under several ids (GHSA, PYSEC, GO, CVE...).
 * Group records that alias each other and keep one entry per issue, preferring
 * the GHSA id because it carries a reviewed severity.
 */
async function mergeAliases(
  recs: OsvRecord[],
  pkg: Package,
  lookup: (id: string) => Promise<OsvRecord | null>,
): Promise<Vulnerability[]> {
  const groups: OsvRecord[][] = [];
  for (const rec of recs) {
    const names = new Set([rec.id, ...(rec.aliases ?? [])]);
    const group = groups.find((g) => g.some((r) => names.has(r.id) || r.aliases?.some((a) => names.has(a))));
    if (group) group.push(rec);
    else groups.push([rec]);
  }

  const out: Vulnerability[] = [];
  for (const group of groups) {
    group.sort((a, b) => rank(a.id) - rank(b.id));
    const primary = group[0]!;
    const aliases = [...new Set(group.flatMap((r) => [r.id, ...(r.aliases ?? [])]))].filter((a) => a !== primary.id);

    let sev = group.map(severityOf).find((s) => s !== null) ?? null;
    if (!sev) {
      // PYSEC/GO records often lack severity; their GHSA alias usually has it.
      const ghsa = aliases.find((a) => a.startsWith("GHSA-"));
      const rec = ghsa ? await lookup(ghsa).catch(() => null) : null;
      sev = rec ? severityOf(rec) : null;
    }

    out.push({
      id: primary.id,
      aliases: aliases.sort((a, b) => rank(a) - rank(b)),
      summary: group.map((r) => r.summary).find(Boolean) ?? firstLine(primary.details) ?? primary.id,
      severity: sev ?? "medium",
      severityUnknown: sev === null,
      cwe: [...new Set(group.flatMap((r) => r.database_specific?.cwe_ids ?? []))],
      fixedVersions: fixedVersions(group, pkg),
      url: `https://osv.dev/vulnerability/${primary.id}`,
    });
  }
  return out;
}

function rank(id: string): number {
  if (id.startsWith("GHSA-")) return 0;
  if (id.startsWith("CVE-")) return 2;
  return 1;
}

function firstLine(s: string | undefined): string | undefined {
  return s?.split("\n").find((l) => l.trim())?.trim();
}

export function severityOf(rec: OsvRecord): Severity | null {
  const label = rec.database_specific?.severity;
  if (label) {
    const s = severityFromLabel(label);
    if (s) return s;
  }
  let best: number | null = null;
  for (const s of rec.severity ?? []) {
    const score = cvss3BaseScore(s.score);
    if (score !== null && (best === null || score > best)) best = score;
  }
  if (best !== null) return severityFromScore(best);
  for (const a of rec.affected ?? []) {
    const s = a.ecosystem_specific?.severity && severityFromLabel(a.ecosystem_specific.severity);
    if (s) return s;
  }
  return null;
}

function fixedVersions(group: OsvRecord[], pkg: Package): string[] {
  const fixed = new Set<string>();
  for (const rec of group) {
    for (const a of rec.affected ?? []) {
      if (a.package?.ecosystem !== pkg.ecosystem) continue;
      if (a.package.name?.toLowerCase() !== pkg.name.toLowerCase()) continue;
      for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
    }
  }
  // Only versions above the installed one are useful upgrade targets.
  return [...fixed].filter((f) => compareVersions(f, pkg.version) > 0).sort(compareVersions);
}

/** Loose dotted-numeric comparison; good enough to order fix versions. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) =>
    v
      .replace(/^v/, "")
      .split(/[.+-]/)
      .map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return typeof y === "number" ? -1 : 1; // 1.0 < 1.0.1, 1.0 > 1.0-rc
    if (y === undefined) return typeof x === "number" ? 1 : -1;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x - y;
    if (typeof x === "number") return 1;
    if (typeof y === "number") return -1;
    return x < y ? -1 : 1;
  }
  return 0;
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

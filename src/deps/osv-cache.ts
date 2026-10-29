import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * On-disk cache of OSV advisory records. An entry is reused only while OSV
 * reports the same `modified` timestamp for it, so a cached advisory is never
 * staler than what the API would return. Entries looked up without a known
 * timestamp (GHSA aliases fetched for severity) expire after a day.
 */
export interface OsvCache {
  get(id: string, modified?: string): unknown | undefined;
  set(id: string, modified: string | undefined, record: unknown): void;
}

const ALIAS_TTL_MS = 24 * 60 * 60 * 1000;

export function defaultCacheDir(): string {
  if (process.env.DIFFWARD_CACHE_DIR) return process.env.DIFFWARD_CACHE_DIR;
  if (process.platform === "win32" && process.env.LOCALAPPDATA) return join(process.env.LOCALAPPDATA, "diffward", "cache");
  return join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "diffward");
}

export function createDiskCache(dir = join(defaultCacheDir(), "osv")): OsvCache {
  let ready = false;
  const file = (id: string) => join(dir, `${id.replace(/[^A-Za-z0-9._-]/g, "_")}.json`);
  return {
    get(id, modified) {
      try {
        const entry = JSON.parse(readFileSync(file(id), "utf8")) as { modified?: string; fetchedAt: number; record: unknown };
        if (modified ? entry.modified === modified : Date.now() - entry.fetchedAt < ALIAS_TTL_MS) return entry.record;
      } catch {
        // missing or corrupt: fetch again
      }
      return undefined;
    },
    set(id, modified, record) {
      try {
        if (!ready) {
          mkdirSync(dir, { recursive: true });
          ready = true;
        }
        writeFileSync(file(id), JSON.stringify({ modified, fetchedAt: Date.now(), record }));
      } catch {
        // read-only home, full disk...: the cache is an optimization only
      }
    },
  };
}

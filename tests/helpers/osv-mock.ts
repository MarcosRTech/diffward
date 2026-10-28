import type { OsvClient } from "../../src/deps/osv.ts";
import { createOsvClient } from "../../src/deps/osv.ts";

/** A tiny in-memory OSV database keyed by "ecosystem|name|version". */
export const ADVISORIES: Record<string, object> = {
  "GHSA-35jh-r3h4-6jhm": {
    id: "GHSA-35jh-r3h4-6jhm",
    aliases: ["CVE-2021-23337"],
    summary: "Command Injection in lodash",
    database_specific: { severity: "HIGH", cwe_ids: ["CWE-77"] },
    affected: [
      {
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      },
    ],
  },
  "PYSEC-2020-96": {
    id: "PYSEC-2020-96",
    aliases: ["CVE-2020-1747", "GHSA-6757-jp84-gxfx"],
    summary: "",
    details: "A vulnerability was discovered in the PyYAML library.\nMore text.",
    affected: [
      {
        package: { name: "pyyaml", ecosystem: "PyPI" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.3.1" }] }],
      },
    ],
  },
  "GHSA-6757-jp84-gxfx": {
    id: "GHSA-6757-jp84-gxfx",
    aliases: ["CVE-2020-1747", "PYSEC-2020-96"],
    summary: "Improper Input Validation in PyYAML",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    affected: [
      {
        package: { name: "pyyaml", ecosystem: "PyPI" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.3.1" }] }],
      },
    ],
  },
};

export const AFFECTED: Record<string, string[]> = {
  "npm|lodash|4.17.20": ["GHSA-35jh-r3h4-6jhm"],
  "npm|lodash|4.17.15": ["GHSA-35jh-r3h4-6jhm"],
  "PyPI|pyyaml|5.3": ["PYSEC-2020-96", "GHSA-6757-jp84-gxfx"],
};

export const mockFetch: typeof fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(String(input));
  if (url.pathname === "/v1/querybatch") {
    const body = JSON.parse(String(init?.body)) as {
      queries: { package: { name: string; ecosystem: string }; version: string }[];
    };
    const results = body.queries.map((q) => {
      const ids = AFFECTED[`${q.package.ecosystem}|${q.package.name}|${q.version}`] ?? [];
      return ids.length ? { vulns: ids.map((id) => ({ id, modified: "2024-01-01T00:00:00Z" })) } : {};
    });
    return Response.json({ results });
  }
  const m = /^\/v1\/vulns\/(.+)$/.exec(url.pathname);
  if (m) {
    const rec = ADVISORIES[decodeURIComponent(m[1]!)];
    return rec ? Response.json(rec) : new Response("not found", { status: 404 });
  }
  return new Response("bad", { status: 400 });
}) as typeof fetch;

export function mockOsv(): OsvClient {
  return createOsvClient("http://osv.test", mockFetch);
}

/** Real HTTP server for end-to-end CLI tests. */
export function startOsvServer() {
  return Bun.serve({
    port: 0,
    async fetch(req) {
      return mockFetch(req.url, { method: req.method, body: req.method === "POST" ? await req.text() : undefined });
    },
  });
}

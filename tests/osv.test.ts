import { describe, expect, test } from "bun:test";
import { cvss3BaseScore, severityFromScore } from "../src/deps/cvss.ts";
import { scanDependencies } from "../src/deps/index.ts";
import { compareVersions, createOsvClient } from "../src/deps/osv.ts";
import { mockOsv } from "./helpers/osv-mock.ts";

describe("CVSS v3", () => {
  test.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
    ["CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 2.5],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
  ])("%s → %d", (vector, score) => {
    expect(cvss3BaseScore(vector)).toBe(score);
  });

  test("rejects other versions and garbage", () => {
    expect(cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:X")).toBeNull();
  });

  test("score buckets", () => {
    expect([9.8, 7.0, 6.9, 0.1, 0].map(severityFromScore)).toEqual(["critical", "high", "medium", "low", "info"]);
  });
});

describe("compareVersions", () => {
  test("orders dotted versions numerically", () => {
    expect(["4.17.21", "4.17.3", "10.0.0", "v4.18.0"].sort(compareVersions)).toEqual(["4.17.3", "4.17.21", "v4.18.0", "10.0.0"]);
    expect(compareVersions("1.0.0-rc.1", "1.0.0")).toBeLessThan(0);
  });
});

describe("OSV client", () => {
  test("merges aliases, prefers GHSA and its severity, computes fix versions", async () => {
    const [lodash, yaml, clean] = await mockOsv().scan([
      { ecosystem: "npm", name: "lodash", version: "4.17.20" },
      { ecosystem: "PyPI", name: "pyyaml", version: "5.3" },
      { ecosystem: "npm", name: "left-pad", version: "1.3.0" },
    ]);
    expect(lodash).toHaveLength(1);
    expect(lodash![0]).toMatchObject({ id: "GHSA-35jh-r3h4-6jhm", severity: "high", fixedVersions: ["4.17.21"] });

    // PYSEC + GHSA for the same issue collapse into one, with the GHSA CVSS (9.8 → critical).
    expect(yaml).toHaveLength(1);
    expect(yaml![0]).toMatchObject({ id: "GHSA-6757-jp84-gxfx", severity: "critical", severityUnknown: false });
    expect(yaml![0]!.aliases).toContain("CVE-2020-1747");
    expect(clean).toEqual([]);
  });

  test("network failure is an error, not an empty result", async () => {
    const failing = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const client = createOsvClient("http://osv.test", failing);
    await expect(client.scan([{ ecosystem: "npm", name: "x", version: "1.0.0" }])).rejects.toThrow(/OSV request failed/);
  });
});

describe("dependency scan", () => {
  const files: Record<string, string> = {
    "package-lock.json": JSON.stringify(
      { lockfileVersion: 3, packages: { "node_modules/lodash": { version: "4.17.20" } } },
      null,
      2,
    ),
    "app/requirements.txt": "PyYAML==5.3\nrequests==2.31.0\n",
  };

  test("reports every vulnerable pinned package with location and fix", async () => {
    const res = await scanDependencies({ files: Object.keys(files), read: (f) => files[f]!, osv: mockOsv() });
    expect(res.packagesChecked).toBe(3);
    expect(res.findings.map((f) => `${f.file}:${f.line} ${f.ruleId} ${f.severity}`)).toEqual([
      "package-lock.json:4 GHSA-35jh-r3h4-6jhm high",
      "app/requirements.txt:1 GHSA-6757-jp84-gxfx critical",
    ]);
    expect(res.findings[0]!.message).toContain("Upgrade to 4.17.21");
  });

  test("in diff mode only packages that changed are checked", async () => {
    const base = { "package-lock.json": files["package-lock.json"]!, "app/requirements.txt": "PyYAML==5.1\n" };
    const res = await scanDependencies({
      files: Object.keys(files),
      read: (f) => files[f]!,
      readBase: (f) => base[f as keyof typeof base] ?? null,
      osv: mockOsv(),
    });
    expect(res.findings.map((f) => f.dependency!.name)).toEqual(["pyyaml"]);
  });
});

import { describe, expect, test } from "bun:test";
import { fixHint } from "../src/deps/fix.ts";
import { parseLockfile, type LockedPackage } from "../src/deps/lockfiles/index.ts";
import { failed, gates, type Policy } from "../src/policy.ts";
import { groupDependencies } from "../src/report/group.ts";
import type { Finding } from "../src/types.ts";

const info = (pkgs: LockedPackage[]) =>
  Object.fromEntries(pkgs.map((p) => [p.name, `${p.dev ? "dev" : p.dev === false ? "prod" : "?"} ${p.direct ? "direct" : p.via ? `via ${p.via}` : "-"}`]));

describe("dependency graph: production vs dev, direct vs transitive", () => {
  test("package-lock.json v3", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { express: "^4" }, devDependencies: { vitest: "^1" } },
        "node_modules/express": { version: "4.18.0", dependencies: { "proxy-addr": "~2" } },
        "node_modules/proxy-addr": { version: "2.0.7" },
        "node_modules/vitest": { version: "1.0.0", dev: true, dependencies: { tinypool: "*" } },
        "node_modules/tinypool": { version: "0.8.0", dev: true },
      },
    });
    expect(info(parseLockfile("package-lock.json", lock))).toEqual({
      express: "prod direct",
      "proxy-addr": "prod via express",
      vitest: "dev direct",
      tinypool: "dev via vitest",
    });
  });

  test("bun.lock with nested versions", () => {
    const lock = `{
      "lockfileVersion": 1,
      "workspaces": { "": { "name": "app", "dependencies": { "next": "16" }, "devDependencies": { "eslint": "9" } } },
      "packages": {
        "next": ["next@16.1.5", "", { "dependencies": { "postcss": "8.4.31" } }, "sha"],
        "next/postcss": ["postcss@8.4.31", "", {}, "sha"],
        "postcss": ["postcss@8.5.6", "", {}, "sha"],
        "eslint": ["eslint@9.0.0", "", { "dependencies": { "minimatch": "3" } }, "sha"],
        "minimatch": ["minimatch@3.1.2", "", {}, "sha"],
      }
    }`;
    const pkgs = parseLockfile("bun.lock", lock);
    const byKey = Object.fromEntries(pkgs.map((p) => [`${p.name}@${p.version}`, info([p])[p.name]]));
    expect(byKey).toEqual({
      "next@16.1.5": "prod direct",
      "postcss@8.4.31": "prod via next", // the nested copy next really uses
      "postcss@8.5.6": "? -", // hoisted copy nothing depends on: unknown
      "eslint@9.0.0": "dev direct",
      "minimatch@3.1.2": "dev via eslint",
    });
  });

  test("pnpm-lock.yaml v9 (importers + snapshots)", () => {
    const lock = [
      "lockfileVersion: '9.0'",
      "",
      "importers:",
      "",
      "  .:",
      "    dependencies:",
      "      express:",
      "        specifier: ^5",
      "        version: 5.2.1",
      "    devDependencies:",
      "      jest:",
      "        specifier: ^30",
      "        version: 30.0.0(@types/node@20.0.0)",
      "",
      "packages:",
      "",
      "  express@5.2.1:",
      "    resolution: {integrity: x}",
      "",
      "  proxy-addr@2.0.7:",
      "    resolution: {integrity: x}",
      "",
      "  jest@30.0.0:",
      "    resolution: {integrity: x}",
      "",
      "snapshots:",
      "",
      "  express@5.2.1:",
      "    dependencies:",
      "      proxy-addr: 2.0.7",
      "",
      "  proxy-addr@2.0.7: {}",
      "",
      "  jest@30.0.0(@types/node@20.0.0): {}",
    ].join("\n");
    expect(info(parseLockfile("pnpm-lock.yaml", lock))).toEqual({
      express: "prod direct",
      "proxy-addr": "prod via express",
      jest: "dev direct",
    });
  });

  test("yarn.lock v1 in a workspace monorepo", () => {
    const lock = [
      "# yarn lockfile v1",
      "",
      'express@^4.18.0:',
      '  version "4.18.0"',
      "  dependencies:",
      '    proxy-addr "~2.0.7"',
      "",
      'proxy-addr@~2.0.7:',
      '  version "2.0.7"',
      "",
      'jest@^29.0.0:',
      '  version "29.0.0"',
    ].join("\n");
    const files: Record<string, string> = {
      "package.json": JSON.stringify({ private: true, workspaces: ["packages/*"] }),
      "packages/api/package.json": JSON.stringify({ dependencies: { express: "^4.18.0" }, devDependencies: { jest: "^29.0.0" } }),
    };
    const pkgs = parseLockfile("yarn.lock", lock, (n) => files[n] ?? null, Object.keys(files));
    expect(info(pkgs)).toEqual({ express: "prod direct", "proxy-addr": "prod via express", jest: "dev direct" });
  });

  test("Python: dev requirements files and Pipfile develop", () => {
    expect(parseLockfile("requirements-dev.txt", "pytest==8.0.0\n")[0]!.dev).toBe(true);
    expect(parseLockfile("requirements.txt", "django==5.0.0\n")[0]!.dev).toBeUndefined();
    const pipfile = JSON.stringify({ default: { django: { version: "==5.0.0" } }, develop: { pytest: { version: "==8.0.0" } } });
    expect(info(parseLockfile("Pipfile.lock", pipfile))).toEqual({ django: "prod -", pytest: "dev -" });
  });
});

function vuln(name: string, version: string, severity: Finding["severity"], fixed: string[], extra: Partial<NonNullable<Finding["dependency"]>> = {}): Finding {
  return {
    kind: "dependency",
    category: "security",
    ruleId: `GHSA-${name}-${severity}`,
    severity,
    title: `${severity} issue in ${name}`,
    message: "",
    file: "bun.lock",
    line: 1,
    dependency: { ecosystem: "npm", name, version, vulnId: `GHSA-${name}-${severity}`, aliases: [], fixedVersions: fixed, url: "https://osv.dev", ...extra },
  };
}

describe("report grouping and fix hints", () => {
  test("one group per package; the fix covers every advisory", () => {
    const groups = groupDependencies([
      vuln("next", "16.1.5", "high", ["16.3.3"], { direct: true, dev: false }),
      vuln("next", "16.1.5", "critical", ["16.4.1"], { direct: true, dev: false }),
      vuln("vitest", "4.0.18", "critical", ["4.1.0"], { direct: true, dev: true }),
      vuln("proxy-addr", "2.0.7", "medium", [], { direct: false, dev: false, via: "express" }),
    ]);
    expect(groups.map((g) => `${g.name} ${g.worst} ${g.vulns.length} ${g.fixVersion ?? "-"}`)).toEqual([
      "next critical 2 16.4.1", // production first among equally severe
      "vitest critical 1 4.1.0",
      "proxy-addr medium 1 -",
    ]);
    expect(groups[0]!.hint).toBe("bun add next@^16.4.1");
    expect(groups[1]!.hint).toBe("bun add -d vitest@^4.1.0");
    expect(groups[2]!.unfixed).toBe(1);
  });

  test("transitive packages get an override hint", () => {
    expect(fixHint("package-lock.json", { name: "qs", direct: false, via: "express" }, "6.16.1")).toBe(
      'transitive dependency: update express, or force it with "overrides": { "qs": "^6.16.1" } in package.json',
    );
    expect(fixHint("app/requirements.txt", { name: "django" }, "5.2.15")).toBe("pin django==5.2.15 (or later) in requirements.txt");
    expect(fixHint("go.mod", { name: "golang.org/x/net" }, "0.38.0")).toBe("go get golang.org/x/net@v0.38.0");
  });
});

describe("fail policy", () => {
  const policy: Policy = { failOn: "high", failOnQuality: "none", failOnDev: false };
  const quality: Finding = { ...vuln("x", "1", "high", []), kind: "code", category: "quality", dependency: undefined };

  test("dev-only and quality findings don't fail by default", () => {
    expect(gates(vuln("vitest", "4.0.18", "critical", [], { dev: true }), policy)).toBe(false);
    expect(gates(vuln("next", "16.1.5", "high", [], { dev: false }), policy)).toBe(true);
    expect(gates(vuln("unknown", "1.0.0", "high", []), policy)).toBe(true); // dev unknown → counts
    expect(gates(quality, policy)).toBe(false);
  });

  test("both can be opted in", () => {
    expect(failed([vuln("vitest", "4.0.18", "critical", [], { dev: true })], { ...policy, failOnDev: true })).toBe(true);
    expect(failed([quality], { ...policy, failOnQuality: "medium" })).toBe(true);
  });
});

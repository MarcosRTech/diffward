import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseLockfile, selectLockfiles } from "../src/deps/lockfiles/index.ts";
import { parsePnpmLock, parseYarnLock } from "../src/deps/lockfiles/npm.ts";

const dir = join(import.meta.dir, "fixtures", "lockfiles");
const read = (f: string) => readFileSync(join(dir, f), "utf8");
const specs = (pkgs: { ecosystem: string; name: string; version: string }[]) =>
  pkgs.map((p) => `${p.ecosystem}:${p.name}@${p.version}`).sort();

describe("lockfile parsers", () => {
  test("package-lock.json v3 (nested, scoped, skips links and workspaces)", () => {
    const pkgs = parseLockfile("package-lock.json", read("package-lock.json"));
    expect(specs(pkgs)).toEqual(["npm:@babel/core@7.22.5", "npm:lodash@4.17.20", "npm:semver@6.3.0"]);
    expect(pkgs.find((p) => p.name === "lodash")?.line).toBe(12);
  });

  test("package-lock.json v1", () => {
    const v1 = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { lodash: { version: "4.17.20", dependencies: { minimist: { version: "0.0.8" } } } },
    });
    expect(specs(parseLockfile("package-lock.json", v1))).toEqual(["npm:lodash@4.17.20", "npm:minimist@0.0.8"]);
  });

  test("bun.lock (trailing commas, scoped, skips git deps)", () => {
    expect(specs(parseLockfile("bun.lock", read("bun.lock")))).toEqual(["npm:@types/node@20.1.0", "npm:lodash@4.17.20"]);
  });

  test("yarn.lock classic", () => {
    expect(specs(parseLockfile("yarn.lock", read("yarn.lock")))).toEqual([
      "npm:@babel/code-frame@7.12.13",
      "npm:lodash@4.17.15",
    ]);
  });

  test("yarn.lock berry (skips workspaces)", () => {
    expect(specs(parseYarnLock(read("yarn-berry.lock")))).toEqual(["npm:lodash@4.17.21"]);
  });

  test("pnpm-lock.yaml v9 (peer suffixes, ignores snapshots)", () => {
    expect(specs(parseLockfile("pnpm-lock.yaml", read("pnpm-lock.yaml")))).toEqual([
      "npm:@babel/core@7.22.5",
      "npm:lodash@4.17.20",
      "npm:react-dom@18.2.0",
    ]);
  });

  test("pnpm-lock.yaml v5", () => {
    expect(specs(parsePnpmLock(read("pnpm-v5.yaml")))).toEqual(["npm:@babel/core@7.22.5", "npm:lodash@4.17.20"]);
  });

  test("requirements.txt (pins only, extras, markers, normalized names)", () => {
    expect(specs(parseLockfile("requirements.txt", read("requirements.txt")))).toEqual([
      "PyPI:django@3.2.0",
      "PyPI:pyyaml@5.3",
      "PyPI:requests@2.25.1",
      "PyPI:some-package-name@1.0",
    ]);
  });

  test("requirements-dev.txt is recognized", () => {
    expect(parseLockfile("requirements-dev.txt", "pytest==6.0.0\n")).toHaveLength(1);
  });

  test("poetry.lock", () => {
    expect(specs(parseLockfile("poetry.lock", read("poetry.lock")))).toEqual(["PyPI:jinja2@2.10", "PyPI:markupsafe@1.1.1"]);
  });

  test("uv.lock skips the local project", () => {
    expect(specs(parseLockfile("uv.lock", read("uv.lock")))).toEqual(["PyPI:urllib3@1.26.4"]);
  });

  test("Pipfile.lock", () => {
    expect(specs(parseLockfile("Pipfile.lock", read("Pipfile.lock")))).toEqual(["PyPI:django@3.2.0", "PyPI:pytest@6.0.0"]);
  });

  test("Cargo.lock skips workspace crates", () => {
    expect(specs(parseLockfile("Cargo.lock", read("Cargo.lock")))).toEqual(["crates.io:time@0.1.43"]);
  });

  test("go.mod (single and block require)", () => {
    expect(specs(parseLockfile("go.mod", read("go.mod")))).toEqual([
      "Go:github.com/gin-gonic/gin@v1.6.0",
      "Go:github.com/stretchr/testify@v1.8.4",
      "Go:golang.org/x/net@v0.7.0",
    ]);
  });

  test("go.sum dedupes /go.mod lines", () => {
    expect(specs(parseLockfile("go.sum", read("go.sum")))).toEqual([
      "Go:github.com/gin-gonic/gin@v1.6.0",
      "Go:golang.org/x/net@v0.7.0",
    ]);
  });

  test("composer.lock (dev branches skipped, v prefix stripped)", () => {
    expect(specs(parseLockfile("composer.lock", read("composer.lock")))).toEqual([
      "Packagist:guzzlehttp/guzzle@7.4.0",
      "Packagist:phpunit/phpunit@9.5.0",
    ]);
  });

  test("Gemfile.lock (platform suffix stripped)", () => {
    expect(specs(parseLockfile("Gemfile.lock", read("Gemfile.lock")))).toEqual([
      "RubyGems:nokogiri@1.13.0",
      "RubyGems:rack@2.2.3",
    ]);
  });

  test("malformed lockfile gives a clear error", () => {
    expect(() => parseLockfile("package-lock.json", "{ nope")).toThrow(/failed to parse package-lock.json/);
  });

  test("go.sum is only used without a sibling go.mod", () => {
    expect(selectLockfiles(["a/go.mod", "a/go.sum", "b/go.sum", "README.md"])).toEqual(["a/go.mod", "b/go.sum"]);
  });
});

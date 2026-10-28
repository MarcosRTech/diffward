import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderRulesDoc } from "../scripts/rules-doc.ts";
import { VERSION } from "../src/version.ts";

test("docs/rules.md is up to date (run `bun scripts/rules-doc.ts`)", () => {
  expect(readFileSync(join(import.meta.dir, "..", "docs", "rules.md"), "utf8")).toBe(renderRulesDoc());
});

test("VERSION matches package.json", () => {
  const pkg = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8"));
  expect(VERSION).toBe(pkg.version);
});

test("--help banner only on UTF-8 terminals", async () => {
  const { banner, LOGO } = await import("../src/logo.ts");
  expect(banner({ tty: true, utf8: true, color: false })).toBe(`${LOGO}\n\n`);
  expect(banner({ tty: true, utf8: true, color: true })).toContain("\x1b[36m");
  expect(banner({ tty: false, utf8: true, color: false })).toBe("");
  expect(banner({ tty: true, utf8: false, color: false })).toBe("");
  expect(new Set(LOGO.split("\n").map((l) => l.length)).size).toBeLessThanOrEqual(2); // 60/61 columns
});

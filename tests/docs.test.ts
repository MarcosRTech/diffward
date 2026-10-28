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

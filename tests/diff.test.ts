import { describe, expect, test } from "bun:test";
import { parseUnifiedDiff } from "../src/diff.ts";
import { globToRegExp, makeMatcher } from "../src/glob.ts";

describe("parseUnifiedDiff", () => {
  test("tracks added lines in the new file, ignores deletions and context", () => {
    const patch = [
      "diff --git a/src/app.ts b/src/app.ts",
      "index 111..222 100644",
      "--- a/src/app.ts",
      "+++ b/src/app.ts",
      "@@ -10,3 +10,4 @@ function x() {",
      " context",
      "-removed",
      "+added one",
      "+added two",
      " context",
      "@@ -40 +41,0 @@",
      "-gone",
      "diff --git a/old.py b/old.py",
      "deleted file mode 100644",
      "--- a/old.py",
      "+++ /dev/null",
      "@@ -1 +0,0 @@",
      "-print(1)",
      "diff --git a/new.py b/new.py",
      "new file mode 100644",
      "--- /dev/null",
      "+++ b/new.py",
      "@@ -0,0 +1,2 @@",
      "+import os",
      "+os.system(x)",
      "\\ No newline at end of file",
    ].join("\n");
    const changed = parseUnifiedDiff(patch);
    expect([...changed.keys()]).toEqual(["src/app.ts", "new.py"]);
    expect([...changed.get("src/app.ts")!]).toEqual([11, 12]);
    expect([...changed.get("new.py")!]).toEqual([1, 2]);
  });

  test("handles quoted paths and CRLF", () => {
    const patch = 'diff --git "a/dir with space/x.js" "b/dir with space/x.js"\r\n+++ "b/dir with space/x.js"\r\n@@ -0,0 +5 @@\r\n+eval(a)\r\n';
    expect([...parseUnifiedDiff(patch).get("dir with space/x.js")!]).toEqual([5]);
  });
});

describe("glob", () => {
  test.each([
    ["tests/fixtures/", "tests/fixtures/a/b.ts", true],
    ["tests/fixtures/", "src/tests/fixtures/a.ts", false],
    ["fixtures/", "src/tests/fixtures/a.ts", true],
    ["*.min.js", "public/vendor/app.min.js", true],
    ["**/*.spec.ts", "src/a/b.spec.ts", true],
    ["**/*.spec.ts", "b.spec.ts", true],
    ["src/*.ts", "src/a/b.ts", false],
    ["/docs", "docs/x.md", true],
    ["docs", "x/docs/y.md", true],
  ])("%s ~ %s → %p", (pattern, path, expected) => {
    expect(globToRegExp(pattern).test(path)).toBe(expected);
  });

  test("ignores comments and blanks", () => {
    expect(makeMatcher(["# comment", "", "dist/"])("dist/x.js")).toBe(true);
  });
});

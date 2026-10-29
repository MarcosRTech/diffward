import { expect, test } from "bun:test";
import { colorLevel, createProgressUI, progressMode } from "../src/ui/progress.ts";
import type { Finding } from "../src/types.ts";

function fakeTerminal() {
  const chunks: string[] = [];
  const stream = { columns: 100, isTTY: true, write: (s: string) => (chunks.push(s), true) } as unknown as NodeJS.WriteStream;
  return { stream, text: () => chunks.join("").replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "") };
}

const finding = (severity: Finding["severity"], kind: Finding["kind"] = "code") =>
  ({ kind, severity, category: "security", ruleId: "x", title: "", message: "", file: "a.ts", line: 1 }) as Finding;

test("HUD shows phases, live counters and a clean summary", async () => {
  const term = fakeTerminal();
  const ui = createProgressUI({ stream: term.stream, title: "0.0.0 · full scan", subtitle: "scanning demo", code: true, deps: true, level: 3 });
  ui.onProgress({ type: "code", done: 5, total: 10, file: "src/very/long/path/to/a/file/handler.ts" });
  ui.onProgress({ type: "finding", finding: finding("critical") });
  ui.onProgress({ type: "deps", phase: "advisories", done: 3, total: 9, cached: 2 });
  await new Promise((r) => setTimeout(r, 160));
  const live = term.text();
  expect(live).toContain("diffward");
  expect(live).toContain("5 / 10 files");
  expect(live).toContain("OSV · 3 / 9 advisories · 2 cached");
  expect(live).toMatch(/● 1 critical/);
  expect(live).not.toContain("undefined");

  ui.onProgress({ type: "code-done", files: 10 });
  ui.onProgress({ type: "deps-done", packages: 40, vulnerable: 2, lockfiles: 1 });
  ui.stop("scanned 10 files and 40 packages in 0.2s");
  expect(term.text()).toContain("✔ scanned 10 files and 40 packages in 0.2s");
});

test("no line is wider than the terminal (wrapped lines break the redraw)", async () => {
  const term = fakeTerminal();
  (term.stream as { columns: number }).columns = 60;
  const ui = createProgressUI({ stream: term.stream, title: "0.0.0 · changes since origin/main", subtitle: "scanning a-very-long-repository-name-indeed", code: true, deps: true, level: 0 });
  ui.onProgress({ type: "code", done: 1, total: 99999, file: "a/".repeat(80) + "x.ts" });
  await new Promise((r) => setTimeout(r, 100));
  ui.stop();
  for (const line of term.text().split("\n")) expect(line.length).toBeLessThanOrEqual(60);
});

test("color detection", () => {
  expect(colorLevel({ NO_COLOR: "1", COLORTERM: "truecolor" })).toBe(0);
  expect(colorLevel({ COLORTERM: "truecolor" })).toBe(3);
  expect(colorLevel({ TERM: "xterm-256color" })).toBe(2);
  expect(colorLevel({ TERM: "xterm" })).toBe(1);
});

test("when the live display turns on, and why", () => {
  const on = (env: Record<string, string>, tty: boolean, flag?: boolean) => progressMode(env, tty, flag).on;
  expect(on({}, true)).toBe(true);
  expect(on({}, false)).toBe(false); // piped / redirected
  expect(on({ CI: "true" }, true)).toBe(false);
  expect(on({ CI: "false" }, true)).toBe(true);
  expect(on({ TERM: "dumb" }, true)).toBe(false);
  expect(on({ TERM_PROGRAM: "mintty" }, false)).toBe(true); // Git Bash looks like a pipe
  expect(on({ MSYSTEM: "MINGW64", TERM: "xterm-256color" }, false)).toBe(true);
  expect(on({ CI: "1" }, false, true)).toBe(true); // --progress wins
  expect(on({}, true, false)).toBe(false); // --no-progress wins
  expect(on({ DIFFWARD_PROGRESS: "1" }, false)).toBe(true);
  expect(on({ DIFFWARD_PROGRESS: "0" }, true)).toBe(false);
  expect(progressMode({ CI: "1" }, true, undefined).reason).toContain("CI");
});

test("the final frame stays on screen after a successful scan", async () => {
  const term = fakeTerminal();
  const ui = createProgressUI({ stream: term.stream, title: "0.0.0", subtitle: "scanning demo", code: true, deps: false, level: 0 });
  ui.onProgress({ type: "code", done: 3, total: 3 });
  ui.onProgress({ type: "code-done", files: 3 });
  ui.stop("scanned 3 files in 0.0s");
  const lines = term.text().split("\n");
  const tail = lines.slice(-12).join("\n");
  expect(tail).toContain("3 / 3 files");
  expect(tail).toContain("✔ code");
  expect(tail).toContain("✔ scanned 3 files in 0.0s");
});

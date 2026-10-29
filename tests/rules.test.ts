import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { scanCode } from "../src/code/index.ts";

/**
 * Fixtures are annotated like this (any comment syntax):
 *
 *   // ruleid: js/sql-injection     → the next line MUST be reported by that rule
 *   // ruleid: js/sql-injection high → ...and with exactly that severity
 *   // ok: js/sql-injection         → the next line must NOT be reported by that rule
 *
 * Any finding on a line without a `ruleid` marker fails the test, so every
 * fixture doubles as a false-positive check. Files named quality-* hold the
 * quality rules; the rest hold security rules.
 */
const ROOT = join(import.meta.dir, "fixtures", "code");

function expectations(text: string) {
  const lines = text.split("\n");
  const want: string[] = [];
  const ok: string[] = [];
  const severities: string[] = [];
  lines.forEach((line, i) => {
    for (const m of line.matchAll(/\b(ruleid|ok):\s*([a-z]+\/[a-z0-9-]+)(?:\s+(critical|high|medium|low|info)\b)?/g)) {
      // The marker applies to the next non-comment line.
      let target = i + 1;
      while (target < lines.length && /^\s*(?:\/\/|#|\{\/\*)/.test(lines[target]!)) target++;
      (m[1] === "ruleid" ? want : ok).push(`${m[2]}@${target + 1}`);
      if (m[3]) severities.push(`${m[2]}@${target + 1}:${m[3]}`);
    }
  });
  return { want, ok, severities };
}

/** Fixture files under a directory, as paths relative to it (fixtures can live in .github/workflows/...). */
function walk(dir: string, prefix = ""): string[] {
  return readdirSync(join(dir, prefix), { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(dir, join(prefix, e.name)) : [join(prefix, e.name)],
  );
}

for (const lang of readdirSync(ROOT)) {
  describe(`${lang} rules`, () => {
    for (const file of walk(join(ROOT, lang))) {
      test(file, () => {
        const text = readFileSync(join(ROOT, lang, file), "utf8");
        const { want, ok, severities } = expectations(text);
        // quality-*.ext fixtures cover quality rules, the others security rules.
        const category = /(?:^|\/)quality-/.test(file) ? "quality" : "security";
        const findings = scanCode(`${lang}/${file}`, text).filter((f) => f.category === category);
        const got = findings.map((f) => `${f.ruleId}@${f.line}`);
        const gotSeverity = findings.map((f) => `${f.ruleId}@${f.line}:${f.severity}`);

        const missing = want.filter((w) => !got.includes(w));
        const falsePositives = got.filter((g) => !want.includes(g));
        const wrongSeverity = severities.filter((s) => !gotSeverity.includes(s));
        expect({ missing, falsePositives, wrongSeverity }).toEqual({ missing: [], falsePositives: [], wrongSeverity: [] });
        // `ok` markers are covered by the false-positive check; make sure they exist.
        expect(ok.length + want.length).toBeGreaterThan(0);
      });
    }
  });
}

import type { Finding } from "../types.ts";
import { isLockfile } from "../deps/lockfiles/index.ts";
import { analyzeJs } from "./js/analyzer.ts";
import { analyzePython } from "./python/analyzer.ts";
import { rule, type RawFinding } from "./rules.ts";
import { scanSecrets } from "./secrets.ts";

const JS_EXT = /\.(?:[cm]?[jt]sx?)$/;
const PY_EXT = /\.pyw?$/;
const SKIP_EXT =
  /\.(?:min\.js|map|png|jpe?g|gif|webp|ico|bmp|tiff?|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|so|dylib|dll|exe|bin|o|a|woff2?|ttf|otf|eot|mp[34]|mov|avi|wasm|pyc|lock|sum|snap|svg|sarif)$/i;

export type Language = "javascript" | "python" | null;

export function languageOf(file: string): Language {
  if (/\.d\.[cm]?ts$/.test(file)) return null;
  if (JS_EXT.test(file)) return "javascript";
  if (PY_EXT.test(file)) return "python";
  return null;
}

export function shouldScanText(file: string): boolean {
  return !SKIP_EXT.test(file) && !isLockfile(file);
}

/** Runs every code rule that applies to the file. Never throws on bad syntax. */
export function scanCode(file: string, text: string): Finding[] {
  if (text.includes("\0")) return []; // binary
  const lang = languageOf(file);
  const raw: RawFinding[] = scanSecrets(text, { generic: lang !== null });

  // Minified/bundled output is not code anyone reviews; only look for secrets in it.
  const generated = lang === "javascript" && isGenerated(text);

  try {
    if (lang === "javascript" && !generated) raw.push(...analyzeJs(file, text));
    if (lang === "python") raw.push(...analyzePython(text));
  } catch (err) {
    // A parser crash must not hide the other findings; surface it as a warning.
    process.stderr.write(`diffward: warning: could not analyze ${file}: ${(err as Error).message}\n`);
  }

  const lines = text.split("\n");
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const r of raw) {
    const k = `${r.ruleId}:${r.line}`;
    if (seen.has(k) || isSuppressed(lines, r)) continue;
    seen.add(k);
    const meta = rule(r.ruleId);
    let snippet = (lines[r.line - 1] ?? "").trim();
    if (r.secret) snippet = snippet.split(r.secret).join(redact(r.secret));
    if (snippet.length > 200) snippet = `${snippet.slice(0, 200)}…`;
    findings.push({
      kind: "code",
      ruleId: r.ruleId,
      severity: r.severity ?? meta.severity,
      title: meta.title,
      message: r.detail ? `${meta.title} (${r.detail}).` : `${meta.title}.`,
      file,
      line: r.line,
      column: r.column,
      endLine: r.endLine,
      snippet,
      cwe: meta.cwe,
      help: meta.help,
    });
  }
  return findings;
}

function isGenerated(text: string): boolean {
  const head = text.slice(0, 500);
  if (/@generated|\/\*\s*eslint-disable\s*\*\/\s*\(\(\)\s*=>|__webpack_require__|__nccwpck_require__/.test(head)) return true;
  let long = 0;
  for (const line of text.split("\n", 5000)) if (line.length > 1000 && ++long >= 3) return true;
  return text.split("\n", 2000).some((l) => l.length > 5000);
}

function redact(secret: string): string {
  return secret.length <= 8 ? "****" : `${secret.slice(0, 4)}…(redacted)`;
}

/**
 * Inline suppressions, in any comment syntax:
 *   foo()  // diffward-ignore
 *   foo()  # diffward-ignore js/sql-injection
 *   // diffward-ignore-next-line py/weak-hash
 */
function isSuppressed(lines: string[], r: RawFinding): boolean {
  const matches = (line: string | undefined, directive: string) => {
    if (!line) return false;
    const m = new RegExp(`${directive}(?![\\w-])([^\\n]*)`).exec(line);
    if (!m) return false;
    const ids = m[1]!.split(/[\s,]+/).filter((s) => /^[a-z]+\/[a-z0-9-]+$/.test(s));
    return ids.length === 0 || ids.includes(r.ruleId);
  };
  const endLine = r.endLine ?? r.line;
  for (let l = r.line; l <= endLine; l++) if (matches(lines[l - 1], "diffward-ignore")) return true;
  return matches(lines[r.line - 2], "diffward-ignore-next-line");
}

import { createHash } from "node:crypto";
import { RULES } from "../code/rules.ts";
import type { ScanResult } from "../scan.ts";
import type { Finding, Severity } from "../types.ts";
import { HOMEPAGE, VERSION } from "../version.ts";

/** GitHub Code Scanning ranks alerts by this numeric property. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "2.0",
  info: "0.0",
};

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** SARIF 2.1.0, shaped for `github/codeql-action/upload-sarif`. */
export function toSarif(result: ScanResult): object {
  const rules = new Map<string, object>();
  for (const f of result.findings) {
    if (rules.has(f.ruleId)) continue;
    rules.set(f.ruleId, ruleDescriptor(f));
  }
  const ruleIndex = new Map([...rules.keys()].map((id, i) => [id, i]));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "diffward",
            version: VERSION,
            semanticVersion: VERSION,
            informationUri: HOMEPAGE,
            rules: [...rules.values()],
          },
        },
        automationDetails: { id: `diffward/${result.mode}/` },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          ruleIndex: ruleIndex.get(f.ruleId),
          level: LEVEL[f.severity],
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: encodeURI(f.file), uriBaseId: "%SRCROOT%" },
                region: {
                  startLine: f.line,
                  ...(f.column ? { startColumn: f.column } : {}),
                  ...(f.endLine && f.endLine > f.line ? { endLine: f.endLine } : {}),
                },
              },
            },
          ],
          partialFingerprints: { "diffward/v1": fingerprint(f) },
          properties: {
            severity: f.severity,
            "security-severity": SECURITY_SEVERITY[f.severity],
            ...(f.dependency ? { package: `${f.dependency.name}@${f.dependency.version}` } : {}),
          },
        })),
      },
    ],
  };
}

function ruleDescriptor(f: Finding): object {
  const meta = RULES.get(f.ruleId);
  const tags = ["security", ...(f.cwe ?? []).map((c) => `external/cwe/${c.toLowerCase()}`)];
  if (f.dependency) {
    tags.push("dependency", f.dependency.ecosystem);
    const ids = [f.dependency.vulnId, ...f.dependency.aliases].join(", ");
    return {
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: truncate(f.title, 120) },
      fullDescription: { text: `${f.title} (${ids})` },
      helpUri: f.dependency.url,
      help: { text: f.help ?? f.dependency.url, markdown: f.help ?? f.dependency.url },
      defaultConfiguration: { level: LEVEL[f.severity] },
      properties: { tags, precision: "high", "security-severity": SECURITY_SEVERITY[f.severity] },
    };
  }
  return {
    id: f.ruleId,
    name: f.ruleId,
    shortDescription: { text: meta?.title ?? f.title },
    fullDescription: { text: meta?.title ?? f.title },
    helpUri: `${HOMEPAGE}/blob/main/docs/rules.md#${f.ruleId.replace(/\//g, "")}`,
    help: { text: f.help ?? "", markdown: f.help ?? "" },
    defaultConfiguration: { level: LEVEL[meta?.severity ?? f.severity] },
    properties: {
      tags,
      precision: "medium",
      "security-severity": SECURITY_SEVERITY[meta?.severity ?? f.severity],
    },
  };
}

/**
 * Stable across unrelated edits: the rule, the file and the trimmed line text
 * (not the line number), so alerts survive code moving up or down.
 */
function fingerprint(f: Finding): string {
  const anchor = f.dependency ? `${f.dependency.name}@${f.dependency.version}` : (f.snippet ?? String(f.line));
  return createHash("sha256").update(`${f.ruleId}\0${f.file}\0${anchor}`).digest("hex").slice(0, 32);
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

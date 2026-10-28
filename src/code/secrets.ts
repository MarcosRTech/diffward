import type { RawFinding } from "./rules.ts";

const KNOWN_TOKENS: { name: string; re: RegExp }[] = [
  { name: "AWS access key id", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/ },
  { name: "AWS secret access key", re: /aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/i },
  { name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/ },
  { name: "GitLab token", re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/ },
  { name: "Slack token", re: /\b(xox[abposr]-[A-Za-z0-9-]{10,})\b/ },
  { name: "Slack webhook", re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,})/ },
  { name: "Stripe live key", re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b/ },
  { name: "Google API key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/ },
  { name: "OpenAI API key", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b/ },
  { name: "Anthropic API key", re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})/ },
  { name: "npm token", re: /\b(npm_[A-Za-z0-9]{36})\b/ },
  { name: "SendGrid API key", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/ },
  { name: "Twilio API key", re: /\b(SK[0-9a-f]{32})\b/ },
  { name: "Mailgun API key", re: /\b(key-[0-9a-f]{32})\b/ },
  { name: "Telegram bot token", re: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b/ },
  { name: "Discord webhook", re: /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{60,})/ },
  {
    name: "credentials in connection string",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql):\/\/[^:\s/"'@]+:([^@\s"'$<{]{6,})@/,
  },
];

const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/;

const SECRET_NAME =
  /(?:^|[^A-Za-z0-9])([A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)[A-Za-z0-9_-]*)["']?\s*(?::|=|:=)\s*(?:r|b)?(["'])([^"'\s]{8,})\2/i;

const PLACEHOLDER =
  /^(?:x+|\*+|\.+|-+)$|change.?me|example|placeholder|your[_-]|<|>|\$\{|\{\{|%\(|redacted|dummy|sample|fake|mock|todo|xxxx|\*\*\*|^(?:password|secret|test|null|none|undefined)\d*$/i;

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Line-based secret detection. Provider tokens and private keys are checked in
 * every text file; the generic `password = "..."` heuristic only in source code.
 */
export function scanSecrets(text: string, opts: { generic: boolean }): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.length > 4000) continue; // minified / generated

    if (PRIVATE_KEY.test(line)) {
      out.push({ ruleId: "secret/private-key", line: i + 1, column: line.search(PRIVATE_KEY) + 1 });
      continue;
    }

    let matched = false;
    for (const { name, re } of KNOWN_TOKENS) {
      const m = re.exec(line);
      if (!m || PLACEHOLDER.test(m[1]!)) continue;
      out.push({ ruleId: "secret/known-token", line: i + 1, column: m.index + 1, detail: name, secret: m[1] });
      matched = true;
      break;
    }
    if (matched || !opts.generic) continue;

    const g = SECRET_NAME.exec(line);
    if (!g) continue;
    const [, name, , value] = g as unknown as [string, string, string, string];
    if (PLACEHOLDER.test(value)) continue;
    if (/^[A-Z0-9_]+$/.test(value) && value.includes("_")) continue; // env var name, not a value
    if (/^(?:https?:)?\/|^\.{0,2}\//.test(value)) continue; // URL or path
    // Names that describe a secret rather than hold one (passwordField, SECRET_NAME, tokenUrl...).
    if (/(?:url|uri|path|field|label|name|header|env|var|prefix|suffix|type|id|mode|event|action|route|template|message|msg|text|title|placeholder|description|hint|error|regex|pattern)s?$/i.test(name)) continue;
    // Identifier-like words ("forgot-password", "admin.password.reset", "usablePassword"): labels, not secrets.
    if (/^[A-Za-z][A-Za-z0-9]*(?:[._:/ -][A-Za-z0-9]+)*[._-]?$/.test(value) && !/\d/.test(value)) continue;
    if (entropy(value) < 3) continue;
    out.push({ ruleId: "secret/hardcoded-password", line: i + 1, column: g.index + 1, detail: name, secret: value });
  }
  return out;
}

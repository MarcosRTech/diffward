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

/** Names that hold a secret in unquoted `KEY=value` / `key: value` / `?key=value` forms. */
const SECRET_WORD = /password|passwd|pwd|passphrase|secret|token|api_?key|apikey|access_?key|private_?key|credential|(?:^|[_.-]|[a-z])key$/i;

// .env / shell / Dockerfile:  [export] NAME=value
const ENV_ASSIGN = /^\s*(?:export\s+|ENV\s+|ARG\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(["']?)([^"'\s#]+)\2\s*(?:#.*)?$/;
// YAML:  name: value   (unquoted; quoted values are covered by SECRET_NAME)
const YAML_ASSIGN = /^\s*-?\s*([A-Za-z_][\w.-]*)\s*:\s+([^"'\s#|>&*!{[][^\s#]{7,})\s*$/;
// URLs:  ...?applicationKey=abc&...
const URL_PARAM = /[?&]([A-Za-z_][\w-]*)=([^&\s"'#<>`)]{16,})/g;
const AUTH_HEADER = /Authorization["']?\s*[:=]\s*["']?(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})/i;
const JWT = /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})/;

const PLACEHOLDER =
  /^(?:x+|\*+|\.+|-+)$|change.?me|example|placeholder|your[_-]|<|>|\$\{|\{\{|%\(|redacted|dummy|sample|fake|mock|todo|xxxx|\*\*\*|^(?:password|secret|test|null|none|undefined|true|false)\d*$/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value) || /^\$\(?[A-Za-z_]|^%[A-Za-z_]+%$/.test(value);
}

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
 * How much of the detector applies to a file:
 * - code:   source files (JS/TS, Python)
 * - config: YAML/JSON/TOML/INI/properties/Terraform/shell/Dockerfile/.env
 * - docs:   Markdown and text; examples there are usually fake, so only
 *           unambiguous formats are checked (provider tokens, keys, JWTs,
 *           Authorization headers, credentials in URLs)
 * - other:  anything else (provider tokens, private keys, JWTs)
 */
export type SecretScope = "code" | "config" | "docs" | "other";

export function secretScope(file: string): SecretScope {
  const base = file.slice(file.lastIndexOf("/") + 1).toLowerCase();
  if (/\.(?:[cm]?[jt]sx?|pyw?)$/.test(base)) return "code";
  if (
    /^\.env(?:\..+)?$|^(?:docker|container)file(?:\..+)?$|\.dockerfile$|^docker-compose[\w.-]*\.ya?ml$/.test(base) ||
    /\.(?:ya?ml|json|jsonc|toml|ini|cfg|conf|properties|tf|tfvars|hcl|sh|bash|zsh|ps1|bat|cmd|xml|gradle|npmrc|pypirc|netrc)$/.test(base) ||
    /^\.(?:npmrc|pypirc|netrc|pgpass)$/.test(base)
  ) {
    return "config";
  }
  if (/\.(?:md|mdx|markdown|txt|rst|adoc|html?)$/.test(base)) return "docs";
  return "other";
}

/** Shared checks for a value captured next to a secret-looking name. */
function looksSecret(name: string, value: string): boolean {
  if (PLACEHOLDER.test(value)) return false;
  if (/^\$\(?[A-Za-z_]|^%[A-Za-z_]+%$/.test(value)) return false; // $VAR, $(cmd), %VAR%: a reference, not a value
  if (/^[A-Z0-9_]+$/.test(value) && value.includes("_")) return false; // env var name, not a value
  if (/^(?:https?:)?\/|^\.{0,2}\//.test(value)) return false; // URL or path
  // Names that describe a secret rather than hold one (passwordField, SECRET_NAME, tokenUrl...).
  if (/(?:url|uri|path|field|label|name|header|env|var|prefix|suffix|type|id|mode|event|action|route|template|message|msg|text|title|placeholder|description|hint|error|regex|pattern|file|length|ttl|expiry|expires|count|max|min|enabled|required)s?$/i.test(name)) return false;
  // Identifier-like words ("forgot-password", "admin.password.reset", "usablePassword"): labels, not secrets.
  if (/^[A-Za-z][A-Za-z0-9]*(?:[._:/ -][A-Za-z0-9]+)*[._-]?$/.test(value) && !/\d/.test(value)) return false;
  // Numbers, booleans, durations, versions
  if (/^\d+(?:\.\d+)*[a-z]{0,2}$/i.test(value)) return false;
  return entropy(value) >= 3;
}

/** JWT payloads are readable: skip the jwt.io sample and downgrade expired tokens. */
function inspectJwt(token: string): { skip: boolean; expired: boolean } {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString("utf8")) as Record<string, unknown>;
    if (payload.sub === "1234567890" && payload.name === "John Doe") return { skip: true, expired: false };
    const exp = typeof payload.exp === "number" ? payload.exp : undefined;
    return { skip: false, expired: exp !== undefined && exp * 1000 < Date.now() };
  } catch {
    return { skip: true, expired: false }; // not a real JWT
  }
}

/**
 * Line-based secret detection. Which heuristics run depends on the file's
 * scope (see SecretScope); provider tokens and private keys run everywhere.
 */
export function scanSecrets(text: string, opts: { scope: SecretScope }): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = text.split("\n");
  const { scope } = opts;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.length > 4000) continue; // minified / generated
    const push = (ruleId: string, index: number, extra: Partial<RawFinding>) =>
      out.push({ ruleId, line: i + 1, column: index + 1, ...extra });

    if (PRIVATE_KEY.test(line)) {
      push("secret/private-key", line.search(PRIVATE_KEY), {});
      continue;
    }

    const known = KNOWN_TOKENS.map(({ name, re }) => ({ name, m: re.exec(line) })).find(({ m }) => m && !PLACEHOLDER.test(m[1]!));
    if (known?.m) {
      push("secret/known-token", known.m.index, { detail: known.name, secret: known.m[1] });
      continue;
    }

    const jwt = JWT.exec(line);
    if (jwt) {
      const info = inspectJwt(jwt[1]!);
      if (!info.skip) {
        push("secret/jwt", jwt.index, { secret: jwt[1], severity: info.expired ? "low" : undefined, detail: info.expired ? "expired token" : undefined });
        continue;
      }
    }

    const auth = AUTH_HEADER.exec(line);
    if (auth && !PLACEHOLDER.test(auth[2]!) && entropy(auth[2]!) >= 3) {
      push("secret/auth-header", auth.index, { detail: `${auth[1]} credentials`, secret: auth[2] });
      continue;
    }

    if (scope === "other") continue;

    // Credentials in URL query strings (not badge images in READMEs).
    let urlHit = false;
    if (!/shields\.io|badge|badgen\.net/i.test(line)) {
      for (const m of line.matchAll(URL_PARAM)) {
        const [, name, value] = m as unknown as [string, string, string];
        if (SECRET_WORD.test(name) && looksSecret(name, value)) {
          push("secret/hardcoded-password", m.index!, { detail: `${name} in a URL`, secret: value });
          urlHit = true;
          break;
        }
      }
    }
    if (urlHit || scope === "docs") continue;

    const g = SECRET_NAME.exec(line);
    if (g) {
      const [, name, , value] = g as unknown as [string, string, string, string];
      if (looksSecret(name, value)) {
        push("secret/hardcoded-password", g.index, { detail: name, secret: value });
        continue;
      }
    }

    if (scope !== "config") continue;
    const assign = ENV_ASSIGN.exec(line) ?? YAML_ASSIGN.exec(line);
    if (assign) {
      const name = assign[1]!;
      const value = assign.length > 3 ? assign[3]! : assign[2]!;
      if (SECRET_WORD.test(name) && looksSecret(name, value)) {
        push("secret/hardcoded-password", line.indexOf(name), { detail: name, secret: value });
      }
    }
  }
  return out;
}

/**
 * A committed `.env` file (not `.env.example`) with real values. Reported once,
 * on its first assignment, in addition to any individual secrets inside it.
 */
export function scanEnvFile(file: string, text: string): RawFinding[] {
  const base = file.slice(file.lastIndexOf("/") + 1);
  if (!/^\.env(?:\..+)?$/.test(base) || /\.(?:example|sample|template|tpl|dist|defaults?|schema|test|ci)$/i.test(base)) return [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = ENV_ASSIGN.exec(lines[i]!);
    if (m && m[3] && !PLACEHOLDER.test(m[3]) && SECRET_WORD.test(m[1]!)) {
      return [{ ruleId: "secret/env-file", line: i + 1, column: 1, detail: base }];
    }
  }
  return [];
}

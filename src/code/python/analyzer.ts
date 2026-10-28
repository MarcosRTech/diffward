import type { RawFinding } from "../rules.ts";

/**
 * Pattern rules for Python.
 *
 * Works on logical lines (a statement spanning several physical lines inside
 * brackets is joined) with comments removed. Like the JS analyzer, it tracks
 * names assigned from request data within the file so that "user input reaches
 * the sink" can be reported with higher severity.
 */
export function analyzePython(text: string): RawFinding[] {
  const statements = logicalLines(text);
  const tainted = new Set<string>();
  /** Names derived from the parameters of the current function (approximate scoping). */
  const params = new Set<string>();
  const dynamicSql = new Set<string>();
  const out: RawFinding[] = [];

  const mentions = (names: Set<string>, s: string) =>
    [...names].some((n) => new RegExp(`(?<![\\w.])${escape(n)}(?!\\w)`).test(s));
  const mentionsTaint = (s: string) => SOURCE.test(s) || mentions(tainted, s);
  // request data → critical, caller-supplied value → high, otherwise the rule default.
  const injectionSeverity = (s: string): RawFinding["severity"] =>
    mentionsTaint(s) ? "critical" : mentions(params, s) ? "high" : undefined;

  for (const st of statements) {
    const code = st.code;
    const report = (ruleId: string, index: number, extra: Partial<RawFinding> = {}) =>
      out.push({ ruleId, line: st.lineAt(index), column: st.columnAt(index), ...extra });

    const def = /^\s*(?:async\s+)?def\s+\w+\s*\(([\s\S]*)\)\s*(?:->[^:]+)?:\s*$/.exec(code);
    if (def) {
      params.clear();
      for (const p of def[1]!.split(",")) {
        const name = /^\s*\**([A-Za-z_]\w*)/.exec(p)?.[1];
        if (name && name !== "self" && name !== "cls") params.add(name);
      }
      continue;
    }

    // ---- taint and dynamic-SQL propagation through simple assignments
    const assign = /^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(code);
    if (assign) {
      const names = assign[1]!.split(",").map((n) => n.trim());
      const rhs = assign[2]!;
      const isTainted = mentionsTaint(rhs) && !SANITIZER.test(rhs);
      const isParam = mentions(params, rhs) && !SANITIZER.test(rhs);
      for (const n of names) {
        if (isTainted) tainted.add(n);
        else tainted.delete(n);
        if (isParam) params.add(n);
        else params.delete(n);
        if (SQL_KEYWORDS.test(rhs) && isDynamicString(rhs, dynamicSql)) dynamicSql.add(n);
        else dynamicSql.delete(n);
      }
    }
    // for x in request.args.getlist(...):
    const loop = /^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.+):\s*$/.exec(code);
    if (loop && mentionsTaint(loop[2]!)) tainted.add(loop[1]!);

    // ---- SQL injection
    for (const m of code.matchAll(/(?:\.(execute|executemany|executescript|raw|extra|mogrify)|\b(text|read_sql|read_sql_query))\s*\(/g)) {
      const arg = firstArg(code, m.index! + m[0].length);
      if (!arg) continue;
      const dynamic = isDynamicString(arg, dynamicSql);
      const sqlish = SQL_KEYWORDS.test(arg) || dynamicSql.has(arg.trim());
      if (dynamic && sqlish) {
        // Params passed separately, or identifiers quoted by the driver: only request data escalates.
        const hasParams = firstArg(code, m.index! + m[0].length) !== callArgs(code, m.index! + m[0].length).trim();
        const quoted = /quote_name|quote_ident|sql\.Identifier|escape_identifier/.test(arg);
        const severity = (hasParams || quoted) && !mentionsTaint(arg) ? undefined : injectionSeverity(arg);
        report("py/sql-injection", m.index!, { severity, detail: `${m[1] ?? m[2]}()` });
      }
    }

    // ---- command injection
    for (const m of code.matchAll(/\b(os\.system|os\.popen|subprocess\.getoutput|subprocess\.getstatusoutput|commands\.getoutput)\s*\(/g)) {
      const arg = firstArg(code, m.index! + m[0].length);
      if (arg && !isConstString(arg)) {
        report("py/command-injection", m.index!, { severity: injectionSeverity(arg), detail: m[1] });
      }
    }
    for (const m of code.matchAll(/\b(subprocess\.(?:run|call|check_call|check_output|Popen)|asyncio\.create_subprocess_shell)\s*\(/g)) {
      const args = callArgs(code, m.index! + m[0].length);
      const first = args.split(",")[0] ?? "";
      const shell = /shell\s*=\s*True/.test(args) || m[1] === "asyncio.create_subprocess_shell";
      if (shell && !isConstString(first)) {
        report("py/command-injection", m.index!, { severity: injectionSeverity(first), detail: `${m[1]} with shell=True` });
      }
    }

    // ---- code injection
    for (const m of code.matchAll(/(?<![\w.])(eval|exec)\s*\(/g)) {
      if (/^\s*(?:async\s+)?def\s/.test(code)) break;
      const arg = firstArg(code, m.index! + m[0].length);
      if (arg && !isConstString(arg)) {
        report("py/code-injection", m.index!, { severity: mentionsTaint(arg) ? "critical" : undefined, detail: `${m[1]}()` });
      }
    }

    // ---- deserialization
    for (const m of code.matchAll(/\b((?:c?[Pp]ickle|dill|marshal|cloudpickle|_pickle)\.loads?|shelve\.open|jsonpickle\.decode|yaml\.unsafe_load|yaml\.full_load|(?:pd|pandas)\.read_pickle)\s*\(/g)) {
      report("py/insecure-deserialization", m.index!, { severity: mentionsTaint(code) ? "critical" : undefined, detail: m[1] });
    }
    for (const m of code.matchAll(/\byaml\.load(?:_all)?\s*\(/g)) {
      const args = callArgs(code, m.index! + m[0].length);
      if (!/Loader\s*=\s*(?:yaml\.)?C?SafeLoader/.test(args)) {
        report("py/insecure-deserialization", m.index!, { detail: "yaml.load without SafeLoader" });
      }
    }
    for (const m of code.matchAll(/\btorch\.load\s*\(/g)) {
      const args = callArgs(code, m.index! + m[0].length);
      if (!/weights_only\s*=\s*True/.test(args)) {
        report("py/insecure-deserialization", m.index!, { severity: "medium", detail: "torch.load without weights_only=True" });
      }
    }

    // ---- path traversal
    for (const m of code.matchAll(/(?<![\w.])(open|send_file|FileResponse|Path|os\.remove|os\.unlink|os\.listdir|shutil\.\w+|os\.path\.join|io\.open|aiofiles\.open)\s*\(/g)) {
      const arg = firstArg(code, m.index! + m[0].length);
      if (!arg) continue;
      const args = m[1] === "os.path.join" ? callArgs(code, m.index! + m[0].length) : arg;
      if (mentionsTaint(args) && !SANITIZER.test(args) && !/safe_join|send_from_directory/.test(code)) {
        report("py/path-traversal", m.index!, { detail: `${m[1]}()` });
      }
    }

    // ---- SSRF
    for (const m of code.matchAll(/\b((?:requests|httpx|session|client|s)\.(?:get|post|put|patch|delete|head|request|stream)|urllib\.request\.urlopen|urlopen|urllib3\.request|aiohttp\.request)\s*\(/g)) {
      let arg = firstArg(code, m.index! + m[0].length);
      if (!arg) continue;
      if (/\.request$/.test(m[1]!)) arg = callArgs(code, m.index! + m[0].length).split(",")[1] ?? arg;
      if (mentionsTaint(arg) && !hasFixedOrigin(arg)) report("py/ssrf", m.index!, { detail: `${m[1]}()` });
    }

    // ---- crypto
    for (const m of code.matchAll(/\bhashlib\.(md5|sha1|new\s*\(\s*["'](?:md5|sha1|md4)["'])\s*\(?/g)) {
      const args = callArgs(code, m.index! + m[0].length);
      if (!/usedforsecurity\s*=\s*False/.test(args)) report("py/weak-hash", m.index!, { detail: m[1]!.replace(/new\s*\(\s*["']|["']/g, "") });
    }
    for (const m of code.matchAll(/\b(DES3?\.new|ARC[24]\.new|Blowfish\.new|AES\.MODE_ECB|modes\.ECB\s*\(|algorithms\.(?:TripleDES|ARC4|Blowfish|IDEA|CAST5))/g)) {
      report("py/weak-cipher", m.index!, { detail: m[1]!.replace(/\s*\($/, "") });
    }

    // ---- TLS
    for (const m of code.matchAll(/\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b|\bcert_reqs\s*=\s*(?:ssl\.)?CERT_NONE\b|\bverify_mode\s*=\s*(?:ssl\.)?CERT_NONE\b|\bcheck_hostname\s*=\s*False\b/g)) {
      report("py/tls-verification-disabled", m.index!, { detail: m[0] });
    }

    // ---- debug
    const dbg = /\.run\s*\([^)]*\bdebug\s*=\s*True/.exec(code);
    if (dbg) report("py/debug-enabled", dbg.index, { detail: "run(debug=True)" });

    // ---- insecure random
    const rnd = /^\s*([A-Za-z_][\w.]*)\s*=.*\brandom\.(?:random|randint|choice|choices|getrandbits|randrange|sample)\s*\(/.exec(code);
    if (rnd && SECURITY_NAME.test(rnd[1]!) && !/(?:count|length|delay|timeout|size)$/i.test(rnd[1]!)) {
      report("py/insecure-random", code.indexOf("random."), { detail: rnd[1] });
    }

    // ---- tempfile
    const tmp = /\b(?:tempfile\.)?mktemp\s*\(/.exec(code);
    if (tmp && !/mkstemp|mkdtemp/.test(tmp[0])) report("py/insecure-tempfile", tmp.index);

    // ---- HTTP without timeout (requests has none by default; httpx defaults to 5 s)
    for (const m of code.matchAll(/\brequests\.(get|post|put|patch|delete|head|options|request)\s*\(/g)) {
      if (!/\btimeout\s*=/.test(callArgs(code, m.index! + m[0].length))) {
        report("py/http-no-timeout", m.index!, { detail: `requests.${m[1]}()` });
      }
    }

    // ---- sensitive data in logs
    const logCall = /\b(?:logging|logger|log|self\.logger|self\.log|current_app\.logger|app\.logger)\.(?:debug|info|warning|warn|error|exception|critical)\s*\(|(?<![\w.])print\s*\(/.exec(code);
    if (logCall) {
      const args = callArgs(code, logCall.index + logCall[0].length);
      const hit = sensitiveInPython(args);
      if (hit) report("py/sensitive-log", logCall.index, { detail: hit });
    }
  }

  // ---- `except ...: pass` (same line, or a block whose only statement is pass)
  for (let i = 0; i < statements.length; i++) {
    const code = statements[i]!.code;
    const at = code.search(/\S/);
    const inline = /^\s*except\b[^:]*:\s*(?:pass|\.\.\.)\s*$/.test(code);
    const header = /^(\s*)except\b[^:]*:\s*$/.exec(code);
    const next = statements[i + 1]?.code;
    const after = statements[i + 2]?.code;
    const onlyPass =
      header !== null &&
      next !== undefined &&
      /^\s*(?:pass|\.\.\.)\s*$/.test(next) &&
      indent(next) > header[1]!.length &&
      !(after !== undefined && indent(after) > header[1]!.length);
    if (inline || onlyPass) out.push({ ruleId: "py/empty-except", line: statements[i]!.lineAt(at), column: at + 1 });
  }
  return out;
}

function indent(code: string): number {
  return /^[ \t]*/.exec(code)![0].length;
}

const PY_SENSITIVE =
  /^(?:password|passwd|pwd|secret|client_secret|access_token|refresh_token|id_token|token|auth_token|api_key|apikey|private_key|authorization|cookie|cookies|cpf|cnpj|ssn|card_number|cvv|cvc)$/i;

/** A sensitive variable/attribute passed to a log call (also inside f-string fields). */
function sensitiveInPython(args: string): string | null {
  const whole = /\brequest\.(?:headers|cookies|form|json|data)\b(?!\s*[.[(])/.exec(args);
  if (whole) return whole[0];
  // f-string fields: f"token={token}"
  for (const m of args.matchAll(/\{([A-Za-z_][\w.]*)(?:[!:][^}]*)?\}/g)) {
    if (PY_SENSITIVE.test(m[1]!.split(".").pop()!)) return m[1]!;
  }
  // names outside string literals: log.info("x %s", password)
  const code = args.replace(/[rbuRBU]{0,2}("""|'''|"|')(?:\\.|(?!\1)[\s\S])*\1/g, '""')
    // bool(token), len(password), mask_cpf(cpf): derived values, not the secret
    .replace(/\b(?:bool|len|type|isinstance|\w*mask\w*|\w*hash\w*|\w*redact\w*)\s*\([^()]*\)/gi, "0");
  for (const m of code.matchAll(/(?<![\w"'])([A-Za-z_][\w.]*)(?![\w(])/g)) {
    if (PY_SENSITIVE.test(m[1]!.split(".").pop()!)) return m[1]!;
  }
  return null;
}

const SOURCE =
  /\brequest\.(?:args|form|values|json|data|files|cookies|headers|GET|POST|body|query_params|path_params|get_json|get_data|stream)\b|\bevent\[\s*["'](?:body|queryStringParameters|pathParameters|headers)["']\s*\]/;
const SANITIZER = /\b(?:int|float|bool|secure_filename|os\.path\.basename|basename|quote|escape|uuid\.UUID)\s*\(/;
const SQL_KEYWORDS = /\b(?:select\s[\s\S]*\bfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|where\s|order\s+by|drop\s+table|create\s+table|alter\s+table|union\s+select)\b/i;
const SECURITY_NAME = /token|secret|password|passwd|nonce|salt|otp|session|csrf|api_?key|reset|verif|invite/i;

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** f-strings with fields, % formatting, .format() or concatenation with a non-literal. */
function isDynamicString(expr: string, dynamicNames: Set<string>): boolean {
  const e = expr.trim();
  if (dynamicNames.has(e)) return true;
  if (/^[rbuRBU]{0,2}[fF][rbRB]?("""|'''|"|')/.test(e) && /\{[^{}]*\}/.test(e)) return true;
  if (/^[rbuRBU]{0,2}("""|'''|"|')[\s\S]*\1\s*(?:%|\.format\s*\()/.test(e)) return true;
  if (/^[rbuRBU]{0,2}("""|'''|"|')[\s\S]*\1\s*\+\s*(?!["'])/.test(e)) return true;
  if (/\+\s*[rbuRBU]{0,2}["']/.test(e) && /^[A-Za-z_]/.test(e)) return true;
  return false;
}

function isConstString(expr: string): boolean {
  const e = expr.trim();
  if (/^[rbuRBU]{0,2}[fF]/.test(e) && /\{[^{}]*\}/.test(e)) return false;
  return /^(?:[rbuRBU]{0,2}("""|'''|"|')(?:(?!\1)[\s\S])*\1\s*)+$/.test(e) || /^\[(?:\s*[rbuRBU]{0,2}["'][^"']*["']\s*,?)*\]$/.test(e);
}

function hasFixedOrigin(arg: string): boolean {
  return /^\s*[fF]?["']https?:\/\/[^/{}"']+\//.test(arg);
}

/** Text between the opening paren at `start` and its matching close paren. */
function callArgs(code: string, start: number): string {
  let depth = 1;
  let quote: string | null = null;
  for (let i = start; i < code.length; i++) {
    const c = code[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) return code.slice(start, i);
    }
  }
  return code.slice(start);
}

/** First top-level argument of the call whose args start at `start`. */
function firstArg(code: string, start: number): string {
  const args = callArgs(code, start);
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < args.length; i++) {
    const c = args[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === "," && depth === 0) return args.slice(0, i).trim();
  }
  return args.trim();
}

interface Statement {
  code: string;
  lineAt(index: number): number;
  columnAt(index: number): number;
}

/**
 * Splits source into statements: comments stripped, bracketed continuations and
 * backslash continuations joined (with "\n" kept so offsets map back to lines),
 * and bare docstrings blanked.
 */
export function logicalLines(text: string): Statement[] {
  const out: Statement[] = [];
  const lines = text.split("\n");
  let buf = "";
  let startLine = 0;
  let depth = 0;
  let triple: string | null = null;

  const flush = (endLine: number) => {
    const code = buf;
    const first = startLine;
    buf = "";
    depth = 0;
    if (/^\s*[rbuRBU]{0,2}("""|''')/.test(code) && !/=/.test(code.split(/"""|'''/)[0]!)) return; // docstring
    if (!code.trim()) return;
    out.push({
      code,
      lineAt: (index) => first + 1 + (code.slice(0, index).match(/\n/g)?.length ?? 0),
      columnAt: (index) => index - code.lastIndexOf("\n", index - 1),
    });
    void endLine;
  };

  for (let ln = 0; ln < lines.length; ln++) {
    const raw = lines[ln]!;
    if (buf === "" ) startLine = ln;
    let line = "";
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i]!;
      if (triple) {
        line += c;
        if (raw.startsWith(triple, i)) {
          line += triple.slice(1);
          i += 2;
          triple = null;
        }
        continue;
      }
      if (raw.startsWith('"""', i) || raw.startsWith("'''", i)) {
        triple = raw.slice(i, i + 3);
        line += triple;
        i += 2;
        continue;
      }
      if (c === '"' || c === "'") {
        // single-line string literal
        let j = i + 1;
        while (j < raw.length && raw[j] !== c) j += raw[j] === "\\" ? 2 : 1;
        line += raw.slice(i, j + 1);
        i = j;
        continue;
      }
      if (c === "#") break;
      if ("([{".includes(c)) depth++;
      if (")]}".includes(c)) depth = Math.max(0, depth - 1);
      line += c;
    }
    buf += (buf ? "\n" : "") + line;
    const continued = triple !== null || depth > 0 || /\\\s*$/.test(line);
    if (!continued) flush(ln);
  }
  if (buf) flush(lines.length - 1);
  return out;
}

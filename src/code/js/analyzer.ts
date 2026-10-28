import ts from "typescript";
import type { RawFinding } from "../rules.ts";
import {
  collectAliases,
  dotted,
  isConstString,
  isFixedOrigin,
  isPlaceholderList,
  isRequestSource,
  isSanitized,
  objectProp,
  propName,
  REQUEST_OBJECTS,
  requiredModule,
  resolveCallee,
  stringValue,
  unwrap,
} from "./ast.ts";
import { analyzeQuality } from "./quality.ts";

/**
 * AST rules for JavaScript/TypeScript.
 *
 * Taint tracking is deliberately simple and local: an expression is "tainted"
 * when it reads from a well-known request source (req.query, req.body,
 * event.queryStringParameters, searchParams.get(...), ...) or from a variable
 * that was assigned from one earlier in the same function. That is enough to
 * separate "user input reaches the sink" (higher severity) from "the string is
 * merely dynamic", without whole-program analysis.
 */
export function analyzeJs(fileName: string, text: string): RawFinding[] {
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, scriptKind(fileName));
  const security = new JsAnalyzer(sf);
  return [...security.run(), ...analyzeQuality(fileName, sf, security.aliases)];
}

function scriptKind(fileName: string): ts.ScriptKind {
  if (/\.tsx$/.test(fileName)) return ts.ScriptKind.TSX;
  if (/\.(?:ts|mts|cts)$/.test(fileName)) return ts.ScriptKind.TS;
  if (/\.jsx$/.test(fileName)) return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

const SANITIZERS = new Set(["Number", "parseInt", "parseFloat", "Boolean", "encodeURIComponent", "escape", "sanitize", "basename"]);
const SQL_KEYWORDS = /\b(?:select\s[\s\S]*\bfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|where\s|order\s+by|drop\s+table|create\s+table|alter\s+table|exec(?:ute)?\s|union\s+select)\b/i;
const SECURITY_NAME = /token|secret|password|passwd|nonce|salt|otp|session|csrf|api_?key|apikey|auth|reset|verif|invite|code/i;

type Scope = Map<string, VarInfo>;
interface VarInfo {
  tainted: boolean;
  /** Derived from a parameter of the enclosing function (caller-controlled). */
  param: boolean;
  /** Initializer is a non-constant string (template with substitutions / concatenation). */
  dynamicString: boolean;
  sqlLike: boolean;
  /** `const X = "literal"` (or built only from other constants). */
  constant?: boolean;
  /** Named like a request object (`request`, `event`...) but typed as something else. */
  notRequest?: boolean;
  /** `const options = { query: sql, params }`: kept to find SQL passed as an options object. */
  objectInit?: ts.ObjectLiteralExpression;
}

/** I/O calls: their result is data from our own backend/DB, not the caller's input. */
const IO_CALLS =
  /^(?:fetch|get|post|put|patch|delete|head|request|query|execute|send|invoke|findOne|findMany|findUnique|findFirst|findAll|create|update|upsert)$/;
const REQUEST_TYPE = /Request|Req\b|Context|Ctx|Event|Incoming|NextApi|^\s*(?:any|unknown)\s*$/;

class JsAnalyzer {
  private findings: RawFinding[] = [];
  private scopes: Scope[] = [new Map()];
  /** Local names bound to child_process / fs / http-client imports. */
  readonly aliases: Map<string, string>;

  constructor(readonly sf: ts.SourceFile) {
    this.aliases = collectAliases(sf);
  }

  run(): RawFinding[] {
    // Module-level constants may be declared below the functions that use them.
    for (const st of this.sf.statements) {
      if (ts.isVariableStatement(st)) for (const d of st.declarationList.declarations) if (d.initializer) this.onVariable(d, d.initializer);
    }
    this.visit(this.sf);
    return this.findings;
  }

  /** Canonical dotted name of a callee, resolving import aliases. */
  calleeName(expr: ts.Expression): string {
    return resolveCallee(expr, this.aliases);
  }

  // ---------------------------------------------------------------- scopes

  private lookup(name: string): VarInfo | undefined {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const v = this.scopes[i]!.get(name);
      if (v) return v;
    }
    return undefined;
  }

  private declare(name: string, info: VarInfo) {
    this.scopes[this.scopes.length - 1]!.set(name, info);
  }

  private bindPattern(name: ts.BindingName, info: VarInfo) {
    if (ts.isIdentifier(name)) this.declare(name.text, info);
    else for (const el of name.elements) if (!ts.isOmittedExpression(el)) this.bindPattern(el.name, info);
  }

  // ---------------------------------------------------------------- taint

  private isTainted(expr: ts.Node | undefined): boolean {
    return this.reaches(expr, "tainted");
  }

  private fromParam(expr: ts.Node | undefined): boolean {
    return this.reaches(expr, "param");
  }

  /**
   * Severity for injection sinks: request data → critical, a value the caller
   * passes in → high, any other dynamic string → the rule default (medium).
   */
  private injectionSeverity(...exprs: (ts.Node | undefined)[]): RawFinding["severity"] {
    if (exprs.some((e) => this.isTainted(e))) return "critical";
    if (exprs.some((e) => this.fromParam(e))) return "high";
    return undefined;
  }

  /** Whether data marked `field` flows into `expr`. */
  private reaches(expr: ts.Node | undefined, field: "tainted" | "param"): boolean {
    if (!expr) return false;
    const recurse = (e: ts.Node | undefined) => this.reaches(e, field);
    if (ts.isIdentifier(expr)) return this.lookup(expr.text)?.[field] ?? false;
    if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
      if (field === "tainted" && isRequestSource(expr) && !this.isPlainObject(expr)) return true;
      return recurse(expr.expression);
    }
    if (ts.isCallExpression(expr)) {
      const callee = dotted(expr.expression);
      const last = callee.split(".").pop() ?? "";
      if (SANITIZERS.has(last)) return false;
      // searchParams.get("x"), formData.get("x"), req.param("x"), req.get("x"), await req.json()
      if (field === "tainted" && ts.isPropertyAccessExpression(expr.expression) && !this.isPlainObject(expr.expression)) {
        const obj = expr.expression.expression;
        const method = expr.expression.name.text;
        if (/^(?:get|getAll)$/.test(method) && /(?:searchParams|query|formData|params|headers)$/i.test(dotted(obj))) return true;
        if (/^(?:param|get|header|json|text|formData)$/.test(method) && REQUEST_OBJECTS.test(dotted(obj))) return true;
      }
      if (IO_CALLS.test(last)) return recurse(expr.expression);
      return expr.arguments.some(recurse) || recurse(expr.expression);
    }
    if (ts.isTemplateExpression(expr)) return expr.templateSpans.some((s) => recurse(s.expression));
    if (ts.isBinaryExpression(expr)) return recurse(expr.left) || recurse(expr.right);
    if (ts.isConditionalExpression(expr)) return recurse(expr.whenTrue) || recurse(expr.whenFalse);
    if (
      ts.isParenthesizedExpression(expr) ||
      ts.isAwaitExpression(expr) ||
      ts.isAsExpression(expr) ||
      ts.isNonNullExpression(expr) ||
      ts.isSpreadElement(expr) ||
      ts.isSatisfiesExpression(expr)
    ) {
      return recurse((expr as ts.ParenthesizedExpression).expression);
    }
    if (ts.isArrayLiteralExpression(expr)) return expr.elements.some(recurse);
    if (ts.isObjectLiteralExpression(expr)) {
      return expr.properties.some(
        (p) =>
          (ts.isPropertyAssignment(p) && recurse(p.initializer)) ||
          (ts.isShorthandPropertyAssignment(p) && recurse(p.name)) ||
          (ts.isSpreadAssignment(p) && recurse(p.expression)),
      );
    }
    return false;
  }

  /** `request.url` where `request` is a local typed as something other than an HTTP request. */
  private isPlainObject(expr: ts.Expression): boolean {
    const root = dotted(expr).split(".")[0];
    return root ? (this.lookup(root)?.notRequest ?? false) : false;
  }

  /** Literals, `const` identifiers bound to literals, and expressions built only from those. */
  private isConstExpr(expr: ts.Expression): boolean {
    expr = unwrap(expr);
    if (isConstString(expr)) return true;
    if (ts.isIdentifier(expr)) return this.lookup(expr.text)?.constant ?? false;
    if (ts.isPropertyAccessExpression(expr)) {
      // ENUM.MEMBER / CONSTANTS.KEY in SCREAMING_CASE
      return /^[A-Z][A-Z0-9_]*$/.test(expr.name.text) && /^[A-Z][A-Za-z0-9_]*$/.test(dotted(expr.expression));
    }
    if (ts.isTemplateExpression(expr)) return expr.templateSpans.every((s) => this.isConstExpr(s.expression));
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return this.isConstExpr(expr.left) && this.isConstExpr(expr.right);
    }
    if (ts.isConditionalExpression(expr)) return this.isConstExpr(expr.whenTrue) && this.isConstExpr(expr.whenFalse);
    return isPlaceholderList(expr);
  }

  /** A string whose value is not a compile-time constant. */
  private isDynamicString(expr: ts.Expression | undefined): boolean {
    if (!expr) return false;
    expr = unwrap(expr);
    if (ts.isTemplateExpression(expr)) return !this.isConstExpr(expr);
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return !this.isConstExpr(expr);
    }
    if (ts.isIdentifier(expr)) return this.lookup(expr.text)?.dynamicString ?? false;
    if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression)) {
      const m = expr.expression.name.text;
      if (m === "concat" || m === "replace" || m === "join") return this.isDynamicString(expr.expression.expression) || expr.arguments.some((a) => !isConstString(a));
    }
    return false;
  }

  private looksLikeSql(expr: ts.Expression): boolean {
    expr = unwrap(expr);
    if (ts.isIdentifier(expr)) return this.lookup(expr.text)?.sqlLike ?? false;
    return SQL_KEYWORDS.test(expr.getText(this.sf));
  }

  // ---------------------------------------------------------------- visitor

  private visit = (node: ts.Node): void => {
    const opensScope = ts.isFunctionLike(node) || ts.isBlock(node) || ts.isSourceFile(node);
    if (opensScope && !ts.isSourceFile(node)) this.scopes.push(new Map());

    if (ts.isFunctionLike(node)) this.bindHandlerParams(node);
    if (ts.isVariableDeclaration(node) && node.initializer) this.onVariable(node, node.initializer);
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) this.onAssignment(node);
    if (ts.isCallExpression(node)) this.onCall(node);
    if (ts.isNewExpression(node)) this.onNew(node);
    if (ts.isPropertyAssignment(node)) this.onPropertyAssignment(node);
    if (ts.isJsxAttribute(node)) this.onJsxAttribute(node);

    ts.forEachChild(node, this.visit);
    if (opensScope && !ts.isSourceFile(node)) this.scopes.pop();
  };

  /** Parameters are caller-controlled; destructured request parts are request data. */
  private bindHandlerParams(fn: ts.SignatureDeclaration) {
    for (const p of fn.parameters) {
      const typed = p.type && !REQUEST_TYPE.test(p.type.getText(this.sf));
      const notRequest = ts.isIdentifier(p.name) && REQUEST_OBJECTS.test(p.name.text) && Boolean(typed);
      this.bindPattern(p.name, { tainted: false, param: true, dynamicString: false, sqlLike: false, notRequest });
      // Destructured request parts: ({ body, query, params }) => ...
      if (ts.isObjectBindingPattern(p.name) && fn.parameters.length <= 3) {
        for (const el of p.name.elements) {
          const prop = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : "";
          if (/^(?:body|query|params|queryStringParameters|pathParameters|headers|cookies)$/.test(prop)) {
            this.bindPattern(el.name, { tainted: true, param: true, dynamicString: false, sqlLike: false });
          }
        }
      }
    }
  }

  private onVariable(decl: ts.VariableDeclaration, init: ts.Expression) {
    const name = decl.name;
    const isConst = ts.isVariableDeclarationList(decl.parent) && (decl.parent.flags & ts.NodeFlags.Const) !== 0;
    const info: VarInfo = {
      tainted: this.isTainted(init),
      param: this.fromParam(init),
      dynamicString: this.isDynamicString(init),
      sqlLike: SQL_KEYWORDS.test(init.getText(this.sf)),
      constant: isConst && ts.isIdentifier(name) && this.isConstExpr(init),
      objectInit: ts.isObjectLiteralExpression(unwrap(init)) ? (unwrap(init) as ts.ObjectLiteralExpression) : undefined,
    };
    this.bindPattern(name, info);
    if (ts.isIdentifier(name)) this.checkInsecureRandom(name.text, init);
  }

  private onAssignment(node: ts.BinaryExpression) {
    const target = node.left;
    if (ts.isIdentifier(target)) {
      const existing = this.lookup(target.text);
      const tainted = this.isTainted(node.right);
      if (existing) {
        existing.tainted ||= tainted;
        existing.param ||= this.fromParam(node.right);
        existing.dynamicString ||= this.isDynamicString(node.right);
      } else if (tainted) {
        this.declare(target.text, { tainted, param: this.fromParam(node.right), dynamicString: this.isDynamicString(node.right), sqlLike: false });
      }
      this.checkInsecureRandom(target.text, node.right);
    }

    if (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
      const prop = ts.isPropertyAccessExpression(target) ? target.name.text : stringValue(target.argumentExpression);
      // el.innerHTML = ...
      if (prop === "innerHTML" || prop === "outerHTML") {
        if (!isConstString(node.right)) {
          const tainted = this.isTainted(node.right);
          this.report(node, "js/xss", { severity: tainted ? "high" : undefined, detail: `${prop} assignment` });
        }
      }
      // process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"
      if (prop === "NODE_TLS_REJECT_UNAUTHORIZED" && stringValue(node.right) === "0") {
        this.report(node, "js/tls-verification-disabled", { detail: "NODE_TLS_REJECT_UNAUTHORIZED=0" });
      }
      if (prop) this.checkInsecureRandom(prop, node.right);
    }
  }

  private onPropertyAssignment(node: ts.PropertyAssignment) {
    const key = propName(node.name);
    if (key === "rejectUnauthorized" && node.initializer.kind === ts.SyntaxKind.FalseKeyword) {
      this.report(node, "js/tls-verification-disabled", { detail: "rejectUnauthorized: false" });
    }
    if (key === "algorithms" || key === "algorithm") {
      const values = ts.isArrayLiteralExpression(node.initializer) ? node.initializer.elements : [node.initializer];
      if (values.some((v) => stringValue(v)?.toLowerCase() === "none")) {
        this.report(node, "js/jwt-none-algorithm");
      }
    }
    if (key === "__html" && !isConstString(node.initializer)) {
      // dangerouslySetInnerHTML={{ __html: value }}
      const tainted = this.isTainted(node.initializer);
      if (!isSanitized(node.initializer)) {
        this.report(node, "js/xss", { severity: tainted ? "high" : undefined, detail: "dangerouslySetInnerHTML" });
      }
    }
    if (key) this.checkInsecureRandom(key, node.initializer);
  }

  private onJsxAttribute(_node: ts.JsxAttribute) {
    // dangerouslySetInnerHTML is handled via its `__html` property assignment.
  }

  private onNew(node: ts.NewExpression) {
    const name = this.calleeName(node.expression);
    if (name === "Function" && node.arguments?.some((a) => !isConstString(a))) {
      this.report(node, "js/code-injection", {
        severity: node.arguments.some((a) => this.isTainted(a)) ? "critical" : undefined,
        detail: "new Function()",
      });
    }
  }

  private onCall(node: ts.CallExpression) {
    const name = this.calleeName(node.expression);
    const last = name.split(".").pop() ?? "";
    const args = node.arguments;
    const first = args[0];

    // ---- code injection
    if ((name === "eval" || name === "Function") && first && !isConstString(first)) {
      this.report(node, "js/code-injection", { severity: this.isTainted(first) ? "critical" : undefined, detail: `${name}()` });
    }
    if ((name === "setTimeout" || name === "setInterval") && first && this.isDynamicString(first)) {
      this.report(node, "js/code-injection", { detail: `${name}() with a string` });
    }
    if (/^vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)$/.test(name) && first && !isConstString(first)) {
      this.report(node, "js/code-injection", { severity: this.isTainted(first) ? "critical" : undefined, detail: name });
    }

    // ---- command injection
    if (/^child_process\.(?:exec|execSync)$/.test(name) || (/^(?:exec|execSync)$/.test(name) && this.aliases.has(name))) {
      if (first && !isConstString(first)) {
        if (this.isTainted(first) || this.isDynamicString(first)) {
          this.report(node, "js/command-injection", { severity: this.injectionSeverity(first), detail: name });
        }
      }
    }
    if (/^child_process\.(?:spawn|spawnSync|execFile|execFileSync)$/.test(name)) {
      const opts = args.find((a) => ts.isObjectLiteralExpression(a)) as ts.ObjectLiteralExpression | undefined;
      const shell = opts?.properties.some(
        (p) => ts.isPropertyAssignment(p) && propName(p.name) === "shell" && p.initializer.kind !== ts.SyntaxKind.FalseKeyword,
      );
      const anyDynamic = args.some((a) => a !== opts && (this.isDynamicString(a) || this.isTainted(a)));
      if (shell && anyDynamic) {
        this.report(node, "js/command-injection", {
          severity: this.injectionSeverity(...args.filter((a) => a !== opts)),
          detail: `${name} with shell: true`,
        });
      }
    }
    // execa / zx style: $`...${x}` is safe (escaped); execaCommand(string) is not.
    if (/^execa\.(?:execaCommand|execaCommandSync|command|commandSync)$/.test(name) && first && this.isTainted(first)) {
      this.report(node, "js/command-injection", { severity: "critical", detail: name });
    }

    // ---- SQL injection
    const sqlCall = this.sqlArgument(args);
    if (/^(?:query|execute|raw|whereRaw|orderByRaw|havingRaw|joinRaw|selectRaw|fromRaw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe|exec|prepare|all|get|run|createQueryJob)$/.test(last) && sqlCall) {
      const sql = sqlCall.sql;
      const tainted = this.isTainted(sql);
      const dynamic = this.isDynamicString(sql);
      const unsafeApi = /Unsafe$|^unsafe$/.test(last);
      const sqlish = this.looksLikeSql(sql) || unsafeApi || /Raw$|^raw$/.test(last);
      // `.get`, `.all`, `.run` are common names; require clear SQL evidence for them.
      const weakName = /^(?:get|all|run|exec|prepare)$/.test(last);
      if (dynamic && sqlish && (!weakName || this.looksLikeSql(sql))) {
        // A bindings argument means values are parameterized; the dynamic part is
        // usually identifiers or placeholder lists, so only request data escalates.
        const severity = sqlCall.bindings && !tainted ? undefined : this.injectionSeverity(sql);
        this.report(node, "js/sql-injection", { severity, detail: `${last}()` });
      } else if (tainted && (unsafeApi || /Raw$|^raw$/.test(last))) {
        this.report(node, "js/sql-injection", { severity: "critical", detail: `${last}()` });
      }
    }

    // ---- path traversal (only with request data: plain dynamic paths are everywhere)
    if (/^(?:fs|fs\/promises|fs-extra)\.\w+$/.test(name) || /^(?:sendFile|download|createReadStream|createWriteStream|readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|readdir|appendFile)$/.test(last)) {
      // res.sendFile(p, { root }) / res.download(p, { root }) reject paths escaping root.
      const rootOpt = /^(?:sendFile|download)$/.test(last) && args.some((a) => ts.isObjectLiteralExpression(a) && objectProp(a, "root"));
      if (first && this.isTainted(first) && !rootOpt && !this.isContained(first) && !isSanitized(first)) {
        this.report(node, "js/path-traversal", { detail: `${last}()` });
      }
    }

    // ---- SSRF
    if (
      name === "fetch" ||
      /^(?:axios|got|ky|needle|superagent|undici|node-fetch|request)(?:\.(?:get|post|put|patch|delete|head|request|stream))?$/.test(name) ||
      /^(?:http|https)\.(?:get|request)$/.test(name) ||
      /^undici\.(?:fetch|request)$/.test(name)
    ) {
      const target = first && ts.isObjectLiteralExpression(first) ? objectProp(first, "url") ?? objectProp(first, "host") ?? objectProp(first, "hostname") : first;
      if (target && this.isTainted(target) && !isFixedOrigin(target)) {
        this.report(node, "js/ssrf", { detail: `${name}()` });
      }
    }

    // ---- open redirect
    if (last === "redirect" && args.length > 0) {
      const target = args[args.length - 1]!;
      if (this.isTainted(target) && !isFixedOrigin(target)) this.report(node, "js/open-redirect");
    }

    // ---- XSS
    if (/^document\.(?:write|writeln)$/.test(name) && first && !isConstString(first)) {
      this.report(node, "js/xss", { severity: this.isTainted(first) ? "high" : undefined, detail: name });
    }
    if (last === "insertAdjacentHTML" && args[1] && !isConstString(args[1]) && !isSanitized(args[1])) {
      this.report(node, "js/xss", { severity: this.isTainted(args[1]) ? "high" : undefined, detail: "insertAdjacentHTML" });
    }

    // ---- deserialization
    if (/^node-serialize\.unserialize$|^serialize\.unserialize$/.test(name) || (last === "unserialize" && this.aliases.get(name.split(".")[0]!)?.startsWith("node-serialize"))) {
      this.report(node, "js/insecure-deserialization", { detail: "node-serialize unserialize()" });
    }

    // ---- crypto
    if (/^(?:crypto\.)?(?:createHash|createHmac)$/.test(name) || /^crypto\.(?:createHash|createHmac)$/.test(name)) {
      const algo = stringValue(first)?.toLowerCase();
      if (algo && /^(?:md4|md5|sha1|sha-1|ripemd160)$/.test(algo) && last === "createHash") {
        this.report(node, "js/weak-hash", { detail: algo });
      }
    }
    if (/(?:^|\.)(?:createCipheriv|createDecipheriv|createCipher|createDecipher)$/.test(name)) {
      const algo = stringValue(first)?.toLowerCase();
      if (algo && /(?:^des|rc4|rc2|blowfish|^bf-|-ecb$|^aes-\d+-ecb)/.test(algo)) {
        this.report(node, "js/weak-cipher", { detail: algo });
      } else if (/(?:^|\.)create(?:De)?[Cc]ipher$/.test(name)) {
        this.report(node, "js/weak-cipher", { detail: `${last}() derives the key with MD5 and no IV` });
      }
    }
    if (/^jsonwebtoken\.verify$|^jwt\.verify$/.test(name) && args[1]) {
      const secret = stringValue(args[1]);
      if (secret === "") this.report(node, "js/jwt-none-algorithm", { detail: "empty verification secret" });
    }
  }

  /**
   * The SQL text of a query call: the first argument, or the `query`/`sql`/`text`
   * property when the driver takes an options object (BigQuery, pg, Sequelize),
   * also through a local `const options = { ... }`.
   */
  private sqlArgument(args: ts.NodeArray<ts.Expression>): { sql: ts.Expression; bindings: boolean } | null {
    const first = args[0];
    if (!first) return null;
    let obj: ts.ObjectLiteralExpression | undefined;
    const e = unwrap(first);
    if (ts.isObjectLiteralExpression(e)) obj = e;
    else if (ts.isIdentifier(e)) obj = this.lookup(e.text)?.objectInit;
    if (!obj) return { sql: first, bindings: args.length > 1 };
    const sql = objectProp(obj, "query") ?? objectProp(obj, "sql") ?? objectProp(obj, "text");
    if (!sql) return null;
    const bindings = ["params", "values", "bindings", "replacements", "parameters"].some((k) => objectProp(obj!, k));
    return { sql, bindings: bindings || args.length > 1 };
  }

  /** path.basename(x) strips directories; containment checks (startsWith) are not tracked. */
  private isContained(expr: ts.Expression): boolean {
    const e = unwrap(expr);
    return ts.isCallExpression(e) && /(?:^|\.)basename$/.test(dotted(e.expression));
  }

  private checkInsecureRandom(name: string, value: ts.Expression) {
    if (!SECURITY_NAME.test(name) || /^(?:is|has|should|enable|use)[A-Z_]|Count$|Length$|Delay$|Timeout$|Ms$/.test(name)) return;
    let found: ts.Node | undefined;
    const walk = (n: ts.Node) => {
      if (found) return;
      if (ts.isCallExpression(n) && dotted(n.expression) === "Math.random") found = n;
      else ts.forEachChild(n, walk);
    };
    walk(value);
    if (found) this.report(found, "js/insecure-random", { detail: name });
  }

  report(node: ts.Node, ruleId: string, extra: Partial<RawFinding> = {}) {
    const start = this.sf.getLineAndCharacterOfPosition(node.getStart(this.sf));
    const end = this.sf.getLineAndCharacterOfPosition(node.getEnd());
    this.findings.push({ ruleId, line: start.line + 1, column: start.character + 1, endLine: end.line + 1, ...extra });
  }
}

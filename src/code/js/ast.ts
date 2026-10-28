import ts from "typescript";

/** Shared AST helpers for the JavaScript/TypeScript rules. */

export const REQUEST_OBJECTS = /^(?:req|request|ctx\.request|ctx|context\.req|c\.req|event|evt)$/;
export const REQUEST_FIELDS = /^(?:body|query|params|headers|cookies|signedCookies|queryStringParameters|pathParameters|multiValueQueryStringParameters|rawQuery|search|hash|url|originalUrl|path|files|file)$/;

/** Local name → canonical module path ("cp" → "child_process", "exec" → "child_process.exec"). */
export function collectAliases(sf: ts.SourceFile): Map<string, string> {
  const aliases = new Map<string, string>();
  const bind = (local: string, canonical: string) => aliases.set(local, canonical);
  const visit = (node: ts.Node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const mod = node.moduleSpecifier.text.replace(/^node:/, "");
      const clause = node.importClause;
      if (clause?.name) bind(clause.name.text, mod);
      const nb = clause?.namedBindings;
      if (nb && ts.isNamespaceImport(nb)) bind(nb.name.text, mod);
      if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) bind(el.name.text, `${mod}.${(el.propertyName ?? el.name).text}`);
      }
    }
    // const cp = require("child_process") / const { exec } = require("child_process")
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const mod = requiredModule(node.initializer);
      if (mod) {
        if (ts.isIdentifier(node.name)) bind(node.name.text, mod);
        else if (ts.isObjectBindingPattern(node.name)) {
          for (const el of node.name.elements) {
            if (!ts.isIdentifier(el.name)) continue;
            const prop = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
            bind(el.name.text, `${mod}.${prop}`);
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return aliases;
}

/** Canonical dotted name of a callee, resolving import aliases. */
export function resolveCallee(expr: ts.Expression, aliases: Map<string, string>): string {
  const e = unwrap(expr);
  // `Function("a", "...")(x)` calls the *result* of a call; it is not Function itself.
  if (ts.isCallExpression(e)) return "";
  // require("child_process").exec(...)
  if (ts.isPropertyAccessExpression(e)) {
    const mod = requiredModule(e.expression);
    if (mod) return `${mod}.${e.name.text}`;
  }
  const text = dotted(expr);
  if (!text) return "";
  const [head, ...rest] = text.split(".");
  const alias = aliases.get(head!);
  return alias ? [alias, ...rest].join(".") : text;
}


export function requiredModule(expr: ts.Expression): string | null {
  const e = unwrap(expr);
  if (ts.isCallExpression(e) && ts.isIdentifier(e.expression) && e.expression.text === "require") {
    const arg = e.arguments[0];
    if (arg && ts.isStringLiteral(arg)) return arg.text.replace(/^node:/, "");
  }
  // const { promises: fs } = require("fs") is rare; await import("x") is handled the same way.
  if (ts.isAwaitExpression(e)) return requiredModule(e.expression);
  if (ts.isCallExpression(e) && e.expression.kind === ts.SyntaxKind.ImportKeyword) {
    const arg = e.arguments[0];
    if (arg && ts.isStringLiteral(arg)) return arg.text.replace(/^node:/, "");
  }
  return null;
}

export function unwrap(e: ts.Expression): ts.Expression {
  while (
    ts.isParenthesizedExpression(e) ||
    ts.isAsExpression(e) ||
    ts.isNonNullExpression(e) ||
    ts.isAwaitExpression(e) ||
    ts.isSatisfiesExpression(e) ||
    ts.isTypeAssertionExpression(e)
  ) {
    e = e.expression;
  }
  return e;
}

/** "a.b.c" for identifier/property chains, "" otherwise. */
export function dotted(e: ts.Expression): string {
  e = unwrap(e);
  if (ts.isIdentifier(e)) return e.text;
  if (e.kind === ts.SyntaxKind.ThisKeyword) return "this";
  if (ts.isPropertyAccessExpression(e)) {
    const left = dotted(e.expression);
    return left ? `${left}.${e.name.text}` : e.name.text;
  }
  if (ts.isElementAccessExpression(e)) {
    const key = stringValue(e.argumentExpression);
    const left = dotted(e.expression);
    return key && left ? `${left}.${key}` : left;
  }
  if (ts.isCallExpression(e)) return dotted(e.expression);
  return "";
}

export function isRequestSource(e: ts.PropertyAccessExpression | ts.ElementAccessExpression): boolean {
  const field = ts.isPropertyAccessExpression(e) ? e.name.text : stringValue(e.argumentExpression);
  if (!field) return false;
  const obj = dotted(e.expression);
  if (REQUEST_FIELDS.test(field) && REQUEST_OBJECTS.test(obj)) return true;
  // location.search / location.hash, document.URL. CLI arguments (process.argv)
  // come from the operator, so they are not treated as attacker-controlled.
  if (/(?:^|\.)location$/.test(obj) && /^(?:search|hash|href)$/.test(field)) return true;
  if (obj === "document" && /^(?:URL|documentURI|referrer|cookie)$/.test(field)) return true;
  return false;
}

export function stringValue(e: ts.Node | undefined): string | undefined {
  if (!e) return undefined;
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return e.text;
  return undefined;
}

export function isConstString(e: ts.Expression): boolean {
  e = unwrap(e);
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e) || ts.isNumericLiteral(e)) return true;
  if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return isConstString(e.left) && isConstString(e.right);
  }
  return false;
}

/**
 * Placeholder lists for bound parameters: `ids.map(() => "?").join(", ")`,
 * `ids.map((_, i) => `$${i + 1}`).join()`, `Array(n).fill("?").join()`.
 */
export function isPlaceholderList(e: ts.Expression): boolean {
  e = unwrap(e);
  if (!ts.isCallExpression(e) || !ts.isPropertyAccessExpression(e.expression) || e.expression.name.text !== "join") return false;
  const inner = unwrap(e.expression.expression);
  if (!ts.isCallExpression(inner) || !ts.isPropertyAccessExpression(inner.expression)) return false;
  const method = inner.expression.name.text;
  const arg = inner.arguments[0];
  if (method === "fill") return Boolean(arg && isConstString(arg));
  if (method !== "map" || !arg || !(ts.isArrowFunction(arg) || ts.isFunctionExpression(arg))) return false;
  const body = ts.isArrowFunction(arg) && !ts.isBlock(arg.body) ? unwrap(arg.body) : undefined;
  if (!body) return false;
  if (isConstString(body)) return true;
  // `$${i + 1}` / `:p${i}` — a fixed prefix plus the index (never the element itself)
  const index = arg.parameters[1]?.name;
  if (!index || !ts.isIdentifier(index) || !ts.isTemplateExpression(body)) return false;
  return body.templateSpans.every((s) => {
    const words = s.expression.getText().match(/[A-Za-z_$][\w$]*/g) ?? [];
    return /^[\w\s+]+$/.test(s.expression.getText()) && words.every((w) => w === index.text);
  });
}

/** `https://api.example.com/${id}` keeps a fixed origin, so it is not SSRF / open redirect. */
export function isFixedOrigin(e: ts.Expression): boolean {
  e = unwrap(e);
  const head = ts.isTemplateExpression(e)
    ? e.head.text
    : ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken
      ? (stringValue(leftmost(e)) ?? "")
      : "";
  return /^https?:\/\/[^/?#]+[/?#]/.test(head) || (head.startsWith("/") && !head.startsWith("//"));
}

export function leftmost(e: ts.BinaryExpression): ts.Expression {
  let cur: ts.Expression = e;
  while (ts.isBinaryExpression(cur)) cur = cur.left;
  return cur;
}

export function isSanitized(e: ts.Expression): boolean {
  e = unwrap(e);
  return ts.isCallExpression(e) && /sanitize|purify|escape/i.test(dotted(e.expression));
}

export function objectProp(obj: ts.ObjectLiteralExpression, key: string): ts.Expression | undefined {
  for (const p of obj.properties) {
    if (ts.isPropertyAssignment(p) && propName(p.name) === key) return p.initializer;
    if (ts.isShorthandPropertyAssignment(p) && p.name.text === key) return p.name;
  }
  return undefined;
}

export function propName(n: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(n) || ts.isStringLiteral(n) || ts.isPrivateIdentifier(n)) return n.text;
  return undefined;
}

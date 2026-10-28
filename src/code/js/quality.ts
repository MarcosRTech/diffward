import ts from "typescript";
import type { RawFinding } from "../rules.ts";
import { dotted, objectProp, propName, REQUEST_OBJECTS, resolveCallee, unwrap } from "./ast.ts";

/**
 * Bad-practice rules for JavaScript/TypeScript: the patterns behind slow
 * endpoints, frozen event loops and lost errors rather than exploits. They
 * report as category "quality" (except js/sensitive-log, a data leak).
 */
export function analyzeQuality(fileName: string, sf: ts.SourceFile, aliases: Map<string, string>): RawFinding[] {
  const out: RawFinding[] = [];
  const callee = (e: ts.Expression) => resolveCallee(e, aliases);
  const report = (node: ts.Node, ruleId: string, extra: Partial<RawFinding> = {}) => {
    const start = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    out.push({ ruleId, line: start.line + 1, column: start.character + 1, ...extra });
  };

  const text = sf.getFullText();
  const serverSide = isServerSide(fileName, text);
  const axiosDefaultsTimeout = /axios\.defaults\.timeout\s*=/.test(text);
  const asyncNames = collectAsyncNames(sf);
  // Seeds, migrations and scripts run once by hand: sequential awaits are fine there.
  const oneOffScript = /(?:^|\/)(?:seeds?|seeders?|migrations?|scripts?|fixtures?)\//.test(fileName) || /\.seed\.[cm]?[jt]s$/.test(fileName);
  const loopHeader = (loop: ts.Node): string => {
    if (ts.isForOfStatement(loop) || ts.isForInStatement(loop)) return `${loop.initializer.getText(sf)} ${loop.expression.getText(sf)}`;
    if (ts.isForStatement(loop)) {
      // `i += BATCH_SIZE` steps through the data in batches
      const step = loop.incrementor?.getText(sf) ?? "";
      return /\+=\s*(?!1\b)[\w.]+/.test(step) ? "batch" : (loop.initializer?.getText(sf) ?? "");
    }
    if (ts.isWhileStatement(loop) || ts.isDoStatement(loop)) return loop.expression.getText(sf);
    return "";
  };
  const loopsReported = new Set<ts.Node>();

  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const name = callee(node.expression);
      const last = name.split(".").pop() ?? "";
      checkHttpTimeout(node, name);
      checkUnboundedQuery(node, last);
      checkSensitiveLog(node, name);
      checkSyncIo(node, name);
      checkForEachAsync(node, last);
    }
    if (ts.isAwaitExpression(node)) checkAwaitInLoop(node);
    if (ts.isExpressionStatement(node)) checkFloating(node);
    if (ts.isCatchClause(node)) checkEmptyCatch(node);
    ts.forEachChild(node, visit);
  };

  // ------------------------------------------------------------ HTTP timeout

  function checkHttpTimeout(node: ts.CallExpression, name: string) {
    const axiosCall = /^axios(?:\.(get|delete|head|options|post|put|patch|request|create))?$/.exec(name);
    if (axiosCall && !axiosDefaultsTimeout && serverSide) {
      const method = axiosCall[1];
      const configIndex = !method || method === "request" || method === "create" ? 0 : /^(?:post|put|patch)$/.test(method) ? 2 : 1;
      if (!method && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])) return; // axios(url, config): rare
      const config = node.arguments[configIndex];
      if (lacksOption(config, ["timeout", "signal", "cancelToken"])) {
        report(node, "js/http-no-timeout", { detail: method === "create" ? "axios.create() without a default timeout" : `${name}()` });
      }
      return;
    }
    if (name === "fetch" && serverSide && lacksOption(node.arguments[1], ["signal"])) {
      report(node, "js/http-no-timeout", { detail: "fetch() without an AbortSignal" });
    }
  }

  /** True when `config` is absent or an object literal without any of `keys`. */
  function lacksOption(config: ts.Expression | undefined, keys: string[]): boolean {
    if (!config) return true;
    const c = unwrap(config);
    if (!ts.isObjectLiteralExpression(c)) return false; // a variable: can't tell
    if (c.properties.some((p) => ts.isSpreadAssignment(p))) return false;
    return !keys.some((k) => objectProp(c, k));
  }

  // ------------------------------------------------------- unbounded queries

  function checkUnboundedQuery(node: ts.CallExpression, last: string) {
    if (!/^(?:findMany|findAll|findAndCount|find)$/.test(last)) return;
    if (!isOrmCall(node.expression, last)) return;
    const arg = node.arguments[0];
    if (arg && !ts.isObjectLiteralExpression(unwrap(arg))) return;
    // `find({ personId })` on a hand-written repository is a domain filter, not ORM options.
    if (arg && !onlyOrmOptions(unwrap(arg) as ts.ObjectLiteralExpression)) return;
    if (!lacksOption(arg, ["where", "take", "limit", "first", "last", "cursor", "skip", "filter"])) return;
    // Chained limits: collection.find({}).limit(10) / qb.findMany().take(5)
    const parent = node.parent;
    if (ts.isPropertyAccessExpression(parent) && /^(?:limit|take|first|paginate|cursor)$/.test(parent.name.text)) return;
    report(node, "js/unbounded-query", { detail: `${last}() without where/take` });
  }

  // ------------------------------------------------------------ sensitive log

  function checkSensitiveLog(node: ts.CallExpression, name: string) {
    if (!/^(?:console|logger|log|this\.logger|this\.log|req\.log|fastify\.log|app\.log)\.(?:log|info|debug|warn|error|trace|fatal)$/.test(name)) {
      return;
    }
    for (const arg of node.arguments) {
      const hit = sensitiveIn(arg);
      if (hit) {
        report(node, "js/sensitive-log", { detail: hit });
        return;
      }
    }
  }

  function sensitiveIn(e: ts.Expression): string | null {
    e = unwrap(e);
    if (ts.isIdentifier(e) || ts.isPropertyAccessExpression(e)) {
      const path = dotted(e);
      const parts = path.split(".");
      const lastPart = parts[parts.length - 1] ?? "";
      if (SENSITIVE_NAME.test(lastPart)) return path;
      // the whole body/headers of a request
      if (parts.length === 2 && REQUEST_OBJECTS.test(parts[0]!) && /^(?:body|headers|cookies)$/.test(lastPart)) return path;
      return null;
    }
    if (ts.isTemplateExpression(e)) {
      for (const span of e.templateSpans) {
        const hit = sensitiveIn(span.expression);
        if (hit) return hit;
      }
    }
    if (ts.isObjectLiteralExpression(e)) {
      for (const p of e.properties) {
        if (ts.isShorthandPropertyAssignment(p) && SENSITIVE_NAME.test(p.name.text)) return p.name.text;
        if (ts.isPropertyAssignment(p)) {
          const key = propName(p.name);
          const value = unwrap(p.initializer);
          const literal = ts.isStringLiteralLike(value) || ts.isNumericLiteral(value) || value.kind === ts.SyntaxKind.TrueKeyword || value.kind === ts.SyntaxKind.FalseKeyword;
          if (key && SENSITIVE_NAME.test(key) && !literal && !isMasked(value)) return key;
          const nested = sensitiveIn(p.initializer);
          if (nested) return nested;
        }
      }
    }
    return null;
  }

  // ------------------------------------------------------------ blocking I/O

  function checkSyncIo(node: ts.CallExpression, name: string) {
    if (!/^(?:fs\.\w+Sync|fs-extra\.\w+Sync|crypto\.(?:pbkdf2Sync|scryptSync|generateKeyPairSync)|child_process\.(?:execSync|spawnSync|execFileSync)|zlib\.\w+Sync)$/.test(name)) {
      return;
    }
    const fn = enclosingFunction(node);
    if (fn && looksLikeHandler(fn)) report(node, "js/sync-io-in-handler", { detail: name });
  }

  // ------------------------------------------------------------ N+1

  function checkAwaitInLoop(node: ts.AwaitExpression) {
    if (oneOffScript) return;
    const call = unwrap(node.expression);
    if (!ts.isCallExpression(call)) return;
    const last = callee(call.expression).split(".").pop() ?? "";
    if (!IO_METHODS.test(last)) return;
    const loop = enclosingLoop(node);
    if (!loop || loopsReported.has(loop)) return;
    // Looping over chunks/pages is the batched version of the fix.
    if (BATCH_LOOP.test(loopHeader(loop))) return;
    loopsReported.add(loop);
    report(node, "js/await-in-loop", { detail: `${last}() per iteration` });
  }

  // ------------------------------------------------------------ promises

  function checkForEachAsync(node: ts.CallExpression, last: string) {
    if (last !== "forEach") return;
    const cb = node.arguments[0];
    if (cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) && hasAsync(cb)) {
      report(node, "js/floating-promise", { severity: "medium", detail: "async callback in forEach is never awaited" });
    }
  }

  function checkFloating(stmt: ts.ExpressionStatement) {
    // In the browser a lost rejection is a console error, not a crashed process.
    if (!serverSide) return;
    const e = stmt.expression;
    if (!ts.isCallExpression(e)) return;
    if (ts.isSourceFile(stmt.parent)) return; // top-level `main()` in scripts
    if (!enclosingFunction(stmt)) return;
    const target = e.expression;
    let name: string | undefined;
    if (ts.isIdentifier(target)) name = target.text;
    else if (ts.isPropertyAccessExpression(target) && target.expression.kind === ts.SyntaxKind.ThisKeyword) name = `this.${target.name.text}`;
    if (name && asyncNames.has(name)) report(stmt, "js/floating-promise", { detail: `${name}()` });
  }

  // ------------------------------------------------------------ catch

  function checkEmptyCatch(clause: ts.CatchClause) {
    const block = clause.block;
    if (block.statements.length > 0) return;
    const inner = block.getText(sf).slice(1, -1);
    if (/\/\/|\/\*/.test(inner)) return; // an explanatory comment counts as intent
    report(clause, "js/empty-catch");
  }

  visit(sf);
  return out;
}

const SENSITIVE_NAME =
  /^(?:password|passwd|pass|pwd|secret|clientSecret|client_secret|accessToken|access_token|refreshToken|refresh_token|idToken|token|authToken|apiKey|api_key|privateKey|private_key|authorization|cookie|cookies|cpf|cnpj|ssn|cardNumber|card_number|cvv|cvc|pan)$/i;

// *Many methods are excluded: calling createMany per chunk is the batched fix.
const IO_METHODS =
  /^(?:query|execute|raw|\$queryRaw|\$executeRaw|findOne|findUnique|findFirst|findMany|findAll|findById|find|count|aggregate|create|update|upsert|delete|save|insert|exec|get|post|put|patch|request|fetch|send|invoke|getItem|putItem|getObject|putObject)$/;

const BATCH_LOOP = /chunk|batch|page|slice|lote/i;

/** Prisma findMany / TypeORM find / Sequelize findAll option names. */
const ORM_OPTIONS = new Set([
  "where", "select", "include", "orderBy", "order", "cursor", "take", "skip", "distinct", "omit",
  "relations", "relationLoadStrategy", "withDeleted", "cache", "lock", "loadRelationIds", "loadEagerRelations",
  "attributes", "limit", "offset", "group", "raw", "paranoid", "transaction", "comment",
]);

function onlyOrmOptions(obj: ts.ObjectLiteralExpression): boolean {
  return obj.properties.every((p) => {
    const name = p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) ? p.name.text : undefined;
    return name !== undefined && ORM_OPTIONS.has(name);
  });
}

/**
 * Only ORM shapes: Prisma delegates (`prisma.user.findMany`, `tx.user.findMany`),
 * TypeORM/Mongo repositories (`userRepository.find`), Sequelize models
 * (`User.findAll`). A project's own `somethingService.findMany(filters)` takes
 * domain filters, not ORM options, and is left alone.
 */
function isOrmCall(expr: ts.Expression, method: string): boolean {
  const parts = dotted(expr).split(".");
  const owner = parts[parts.length - 2] ?? "";
  const client = parts[parts.length - 3] ?? "";
  if (method === "findMany") return /prisma|^(?:client|db|tx|trx|transaction)$/i.test(client);
  if (method === "findAll") return /^[A-Z]\w*$/.test(owner) || /prisma|^(?:client|db|tx)$/i.test(client);
  return /repo(?:sitory)?$|collection$|model$|manager$/i.test(owner) && !/service|dao$/i.test(owner);
}

function isMasked(e: ts.Expression): boolean {
  return ts.isCallExpression(e) && /mask|redact|hash|last4|truncate/i.test(dotted(e.expression));
}

function hasAsync(fn: ts.FunctionLikeDeclaration): boolean {
  return fn.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false;
}

/** Names of async functions and methods declared in the file ("save", "this.save"). */
function collectAsyncNames(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name && hasAsync(node)) names.add(node.name.text);
    if (ts.isMethodDeclaration(node) && hasAsync(node)) {
      const n = propName(node.name);
      if (n) names.add(`this.${n}`);
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = unwrap(node.initializer);
      if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && hasAsync(init)) names.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return names;
}

function enclosingFunction(node: ts.Node): ts.FunctionLikeDeclaration | undefined {
  for (let n = node.parent; n; n = n.parent) {
    if (ts.isFunctionLike(n) && "body" in n) return n as ts.FunctionLikeDeclaration;
  }
  return undefined;
}

/** The nearest loop around `node` within the same function (`for await` excluded). */
function enclosingLoop(node: ts.Node): ts.Node | undefined {
  for (let n = node.parent; n; n = n.parent) {
    if (ts.isFunctionLike(n)) return undefined;
    if (ts.isForOfStatement(n)) return n.awaitModifier ? undefined : n;
    if (ts.isForStatement(n) || ts.isForInStatement(n) || ts.isWhileStatement(n) || ts.isDoStatement(n)) return n;
  }
  return undefined;
}

function looksLikeHandler(fn: ts.FunctionLikeDeclaration): boolean {
  return fn.parameters.some((p) => {
    const name = ts.isIdentifier(p.name) ? p.name.text : "";
    const type = p.type?.getText() ?? "";
    return /^(?:req|request|ctx|event)$/.test(name) || /\b(?:Request|NextRequest|FastifyRequest|Context)\b/.test(type);
  });
}

/**
 * fetch() has no default timeout on the server, but in the browser the user
 * can just reload; only server code is checked.
 */
function isServerSide(fileName: string, text: string): boolean {
  if (/^\s*["']use client["']/.test(text)) return false;
  if (/(?:^|\/)(?:components|hooks|public|pages|containers|views|webapp[\w-]*|frontend|front-end|spa)\//.test(fileName)) return false;
  if (/\.(?:jsx|tsx)$/.test(fileName)) return false;
  if (/from ["'](?:react|react-dom|vue|svelte|@angular\/core)["']/.test(text)) return false;
  return (
    /(?:^|\/)(?:server|api|routes?|controllers?|services?|jobs?|workers?|lambdas?|functions|handlers?|cron|integrations?|clients?|infrastructure|adapters?|gateways?|repositor(?:y|ies))\//.test(fileName) ||
    /(?:^|\/)(?:route|server|handler|worker|index)\.[cm]?[jt]s$/.test(fileName) ||
    /from ["'](?:express|fastify|hono|koa|@nestjs\/[\w-]+|next\/server)["']/.test(text)
  );
}

import express from "express";
import { exec, execFile, spawn } from "node:child_process";
import * as cp from "child_process";
import mysql from "mysql2/promise";

const app = express();
const db = await mysql.createConnection({});

app.get("/users", async (req, res) => {
  const id = req.query.id;
  const name = req.params.name;

  // ruleid: js/sql-injection critical
  await db.query(`SELECT * FROM users WHERE id = ${id}`);

  // ruleid: js/sql-injection
  await db.execute("SELECT * FROM users WHERE name = '" + name + "'");

  const sql = `DELETE FROM sessions WHERE user = ${req.body.user}`;
  // ruleid: js/sql-injection
  await db.query(sql);

  // ok: js/sql-injection
  await db.query("SELECT * FROM users WHERE id = ?", [id]);

  // ok: js/sql-injection
  await db.execute(`SELECT * FROM users WHERE id = $1`, [id]);

  const table = "users";
  // ok: js/sql-injection
  await db.query(`SELECT count(*) FROM ${table} WHERE active = 1`);

  const column = pickColumn();
  // ruleid: js/sql-injection medium
  await db.query(`SELECT ${column} FROM users WHERE active = 1`);

  // ruleid: js/command-injection critical
  exec(`git log --author=${req.query.author}`);

  // ruleid: js/command-injection
  cp.execSync("convert " + name + " out.png");

  // ok: js/command-injection
  execFile("git", ["log", `--author=${req.query.author}`]);

  // ok: js/command-injection
  exec("ls -la");

  // ruleid: js/command-injection
  spawn("sh", ["-c", `echo ${id}`], { shell: true });

  // ok: js/command-injection
  spawn("echo", [String(id)]);

  // ruleid: js/code-injection
  eval(req.body.expression);

  // ruleid: js/code-injection
  const fn = new Function("a", req.body.code);

  // ok: js/code-injection
  eval("1 + 1");

  res.json({ ok: true, fn });
});

// Prisma
declare const prisma: any;
export async function search(term: string) {
  // ruleid: js/sql-injection high
  return prisma.$queryRawUnsafe(`SELECT * FROM posts WHERE title LIKE '%${term}%'`);
}

export async function safeSearch(term: string) {
  // ok: js/sql-injection
  return prisma.$queryRaw`SELECT * FROM posts WHERE title LIKE ${term}`;
}

export function notSql(map: Map<string, string>, key: string) {
  // ok: js/sql-injection
  return map.get(`prefix:${key}`);
}

// CLI scripts: argv comes from the operator, not an attacker.
export function backup(dbName: string) {
  const file = `${dbName}-${Date.now()}.sql`;
  // ruleid: js/command-injection high
  exec(`pg_dump ${dbName} > ${file}`);
  // ruleid: js/command-injection medium
  exec(`pg_dump app > ${process.argv[2]}`);
}

declare const trx: any;
export function byIds(column: string, ids: number[]) {
  // Placeholders built dynamically, values bound separately.
  // ok: js/sql-injection
  await trx.raw(`SELECT * FROM items WHERE ?? IN (${ids.map(() => "?").join(", ")})`, [column, ...ids]);
  // ok: js/sql-injection
  await trx.raw(`SELECT * FROM items WHERE id IN (${ids.map((_, i) => `$${i + 1}`).join(", ")})`, ids);
  // Bindings present but a caller-supplied identifier in the SQL text: stays medium.
  // ruleid: js/sql-injection medium
  return trx.raw(`SELECT * FROM items ORDER BY ${column} LIMIT ?`, [10]);
}

export async function byKeys(keys: string[]) {
  const quoted = keys.map((key) => `"${key}"`).join(",");
  // Looks like a placeholder list, but it interpolates the values themselves.
  // ruleid: js/sql-injection high
  return prisma.$queryRawUnsafe(`SELECT id FROM statements WHERE pix_key IN (${quoted})`);
}

const STATUS_FILTER = "status <> 'deleted'";
export function listItems() {
  // ok: js/sql-injection
  return db.query(`SELECT * FROM items WHERE ${STATUS_FILTER}`);
}

declare function pickColumn(): string;

// ok: js/code-injection
Function("r", "regeneratorRuntime = r")(globalThis);

export const inline = (req: any) =>
  // ruleid: js/command-injection critical
  require("child_process").exec(`ls ${req.query.dir}`);

declare const bigquery: any;
declare const pg: any;
export async function report(table: string, from: string) {
  // ruleid: js/sql-injection high
  await bigquery.query({ query: `SELECT * FROM ${table} WHERE day >= '${from}'` });
  const options = { query: `SELECT * FROM events WHERE day >= ${from}`, location: "US" };
  // ruleid: js/sql-injection high
  await bigquery.query(options);
  // ok: js/sql-injection
  await bigquery.query({ query: "SELECT * FROM events WHERE day >= @from", params: { from } });
  // Identifier in the text but values bound: stays at the default.
  // ruleid: js/sql-injection medium
  await pg.query({ text: `SELECT * FROM ${table} WHERE id = $1`, values: [from] });
}

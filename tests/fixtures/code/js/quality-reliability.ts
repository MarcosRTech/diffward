import axios from "axios";
import fs from "node:fs";
import { pbkdf2Sync } from "node:crypto";
import type { Request, Response } from "express";

declare const prisma: any;
declare const userRepository: any;
declare const db: any;

export async function partner(id: string) {
  // ruleid: js/http-no-timeout
  const a = await axios.get(`https://partner.example.com/items/${id}`);
  // ruleid: js/http-no-timeout
  const b = await axios.post("https://partner.example.com/items", { id }, { headers: { x: "1" } });
  // ok: js/http-no-timeout
  const c = await axios.get("https://partner.example.com/health", { timeout: 5_000 });
  // ok: js/http-no-timeout
  const d = await axios.post("https://partner.example.com/items", { id }, { timeout: 5_000 });
  // ruleid: js/http-no-timeout
  const res = await fetch(`https://partner.example.com/x/${id}`);
  // ok: js/http-no-timeout
  const res2 = await fetch("https://partner.example.com/y", { signal: AbortSignal.timeout(5_000) });
  return [a, b, c, d, res, res2];
}

// ruleid: js/http-no-timeout
export const client = axios.create({ baseURL: "https://partner.example.com" });
// ok: js/http-no-timeout
export const safeClient = axios.create({ baseURL: "https://partner.example.com", timeout: 10_000 });

export async function listUsers() {
  // ruleid: js/unbounded-query
  const all = await prisma.user.findMany();
  // ruleid: js/unbounded-query
  const all2 = await prisma.user.findMany({ include: { posts: true } });
  // ok: js/unbounded-query
  const page = await prisma.user.findMany({ take: 50, skip: 0 });
  // ok: js/unbounded-query
  const active = await prisma.user.findMany({ where: { active: true } });
  // ruleid: js/unbounded-query
  const everyone = await userRepository.find();
  // ok: js/unbounded-query
  const first = [1, 2, 3].find((n) => n > 1);
  return [all, all2, page, active, everyone, first];
}

export async function enrich(ids: number[]) {
  const out = [];
  for (const id of ids) {
    // ruleid: js/await-in-loop
    out.push(await prisma.order.findUnique({ where: { id } }));
    // reported once per loop
    out.push(await prisma.customer.findUnique({ where: { id } }));
  }
  // ok: js/await-in-loop
  const batch = await prisma.order.findMany({ where: { id: { in: ids } } });
  for (const id of ids) {
    // ok: js/await-in-loop
    await new Promise((r) => setTimeout(r, id));
  }
  return [out, batch];
}

async function notify(userId: string) {
  await db.query("INSERT INTO notifications (user_id) VALUES ($1)", [userId]);
}

export function onSignup(userId: string, ids: string[]) {
  // ruleid: js/floating-promise
  notify(userId);
  // ok: js/floating-promise
  notify(userId).catch(() => undefined);
  // ok: js/floating-promise
  void notify(userId);
  // ruleid: js/floating-promise
  ids.forEach(async (id) => {
    await notify(id);
  });
}

export function parse(raw: string) {
  try {
    return JSON.parse(raw);
    // ruleid: js/empty-catch
  } catch {}
  try {
    return JSON.parse(raw);
  } catch {
    // ok: js/empty-catch
    // not JSON: callers fall back to the raw string
  }
  return raw;
}

export function handler(req: Request, res: Response) {
  // ruleid: js/sync-io-in-handler
  const tpl = fs.readFileSync("./template.html", "utf8");
  // ruleid: js/sync-io-in-handler
  const key = pbkdf2Sync(req.body.password, "salt", 100_000, 32, "sha256");
  res.send(tpl + key.toString("hex"));
}

// ok: js/sync-io-in-handler
const config = fs.readFileSync("./config.json", "utf8");
export { config };

declare const partnerService: any;
export async function ownWrappers(personId: number, rows: unknown[][]) {
  // A project's own service method takes domain filters, not ORM options.
  // ok: js/unbounded-query
  const partners = await partnerService.findMany({ personId });
  for (const chunk of rows) {
    // Inserting chunk by chunk is the batched fix, not an N+1.
    // ok: js/await-in-loop
    await prisma.event.createMany({ data: chunk });
  }
  return partners;
}

declare const personRepository: any;
export async function domainRepository(personId: number) {
  // ok: js/unbounded-query
  return personRepository.find({ personId });
}

export async function sendInBatches(items: string[]) {
  const BATCH = 500;
  for (let i = 0; i < items.length; i += BATCH) {
    // ok: js/await-in-loop
    await axios.post("https://partner.example.com/bulk", items.slice(i, i + BATCH), { timeout: 10_000 });
  }
}

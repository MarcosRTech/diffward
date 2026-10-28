import fs from "node:fs";
import path from "node:path";
import axios from "axios";
import type { Request, Response } from "express";

export async function download(req: Request, res: Response) {
  const file = req.query.file as string;

  // ruleid: js/path-traversal
  res.sendFile(path.join("/srv/uploads", file));

  // ruleid: js/path-traversal
  fs.readFile(`./data/${req.params.name}`, () => {});

  // ok: js/path-traversal
  res.sendFile(path.basename(file), { root: "/srv/uploads" });

  // ok: js/path-traversal
  fs.readFileSync("./config.json");
}

export async function proxy(req: Request, res: Response) {
  const target = req.body.url;

  // ruleid: js/ssrf
  const r = await fetch(target);

  // ruleid: js/ssrf
  await axios.get(req.query.callback as string);

  // ok: js/ssrf
  await fetch(`https://api.example.com/items/${req.params.id}`);

  // ok: js/ssrf
  await fetch("https://api.example.com/health");

  // ruleid: js/open-redirect
  res.redirect(req.query.next as string);

  // ok: js/open-redirect
  res.redirect(`/profile/${req.params.id}`);

  return r;
}

// Lambda handler
export const handler = async (event: any) => {
  const url = event.queryStringParameters.url;
  // ruleid: js/ssrf
  return fetch(url);
};

// Next.js route handler
export async function GET(request: Request & { nextUrl: URL }) {
  const to = request.nextUrl.searchParams.get("to");
  // ruleid: js/ssrf
  return fetch(to!);
}

export function render(el: HTMLElement, comment: { body: string }, name: string) {
  // ruleid: js/xss
  el.innerHTML = comment.body;

  // ruleid: js/xss
  el.innerHTML = `<b>${location.hash}</b>`;

  // ok: js/xss
  el.textContent = comment.body;

  // ok: js/xss
  el.innerHTML = "<br>";

  // ruleid: js/xss
  document.write("<p>" + name + "</p>");
}

// A parameter named `request` that is not an HTTP request.
export async function callPartner(request: { url: string; body: unknown }) {
  // ok: js/ssrf
  return axios.request({ url: request.url, data: request.body });
}

// Data returned by our own backend is not the caller's input.
export async function renderPdf(req: Request) {
  const generated = await axios.post("https://pdf.internal.example/generate", req.body);
  // ok: js/ssrf
  return axios.get(generated.data.url);
}

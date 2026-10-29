import { NestFactory } from "@nestjs/core";
import cors from "cors";
import express from "express";
import { createDecipheriv, createHmac } from "node:crypto";
import jwt from "jsonwebtoken";

declare const AppModule: unknown;
declare const key: Buffer, iv: Buffer, tag: Buffer;

export async function bootstrap() {
  const app = await NestFactory.create(AppModule as never);
  // ruleid: js/cors-any-origin
  app.enableCors();
  // ruleid: js/cors-any-origin high
  app.enableCors({ origin: true, credentials: true });
  // ok: js/cors-any-origin
  app.enableCors({ origin: ["https://app.example.com"], credentials: true });
}

const server = express();
// ruleid: js/cors-any-origin
server.use(cors());
// ok: js/cors-any-origin
server.use(cors({ origin: "https://app.example.com" }));
server.get("/public", (_req, res) => {
  // ruleid: js/cors-any-origin
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.send("ok");
});

export const nextHeaders = [
  // ruleid: js/cors-any-origin
  { key: "Access-Control-Allow-Origin", value: "*" },
];

export function decrypt(data: Buffer) {
  // ruleid: js/gcm-no-tag-length
  const d1 = createDecipheriv("aes-256-gcm", key, iv);
  // ok: js/gcm-no-tag-length
  const d2 = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  // ok: js/gcm-no-tag-length
  const d3 = createDecipheriv("aes-256-cbc", key, iv);
  d1.setAuthTag(tag);
  return [d1.update(data), d2, d3];
}

export function sign(payload: object, body: string) {
  // ruleid: secret/hardcoded-password high
  const token = jwt.sign(payload, "my-jwt-signing-secret");
  // ok: secret/hardcoded-password
  const token2 = jwt.sign(payload, process.env.JWT_SECRET!);
  // ruleid: secret/hardcoded-password
  const mac = createHmac("sha256", "webhook-shared-key-01").update(body).digest("hex");
  return [token, token2, mac];
}

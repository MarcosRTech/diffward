import type { Request } from "express";

declare const logger: { info(...a: unknown[]): void; error(...a: unknown[]): void };

export function login(req: Request, user: { id: string; password: string; cpf: string }, token: string) {
  // ruleid: js/sensitive-log
  console.log("login attempt", req.body);
  // ruleid: js/sensitive-log
  logger.info({ userId: user.id, password: user.password });
  // ruleid: js/sensitive-log
  logger.info({ userId: user.id, token });
  // ruleid: js/sensitive-log
  console.log(`issued token ${token}`);
  // ruleid: js/sensitive-log
  logger.error("bad cpf", user.cpf);
  // ok: js/sensitive-log
  logger.info({ userId: user.id, hasToken: Boolean(token) });
  // ok: js/sensitive-log
  logger.info("token refreshed", { userId: user.id });
  // ok: js/sensitive-log
  logger.info({ userId: user.id, cpf: maskCpf(user.cpf) });
}

declare function maskCpf(cpf: string): string;

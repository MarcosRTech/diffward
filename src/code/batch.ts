import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.ts";
import { scanCode } from "./index.ts";

export const MAX_FILE_BYTES = 2 * 1024 * 1024;

export interface FileResult {
  file: string;
  /** False when the file was skipped (deleted, too large, unreadable). */
  scanned: boolean;
  findings: Finding[];
}

export function analyzeFile(root: string, file: string): FileResult {
  try {
    const path = join(root, file);
    if (statSync(path).size > MAX_FILE_BYTES) return { file, scanned: false, findings: [] };
    return { file, scanned: true, findings: scanCode(file, readFileSync(path, "utf8")) };
  } catch (err) {
    if (process.env.DIFFWARD_DEBUG) process.stderr.write(`diffward: ${file}: ${(err as Error).message}\n`);
    return { file, scanned: false, findings: [] }; // deleted in the working tree, permissions...
  }
}

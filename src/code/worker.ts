// Worker thread: reads and analyzes a batch of files, posts the findings back.
import { parentPort } from "node:worker_threads";
import { analyzeFile, type FileResult } from "./batch.ts";

parentPort?.on("message", (msg: { root: string; files: string[] }) => {
  const results: FileResult[] = msg.files.map((f) => analyzeFile(msg.root, f));
  parentPort!.postMessage(results);
});

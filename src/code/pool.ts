import { availableParallelism, cpus } from "node:os";
import { Worker } from "node:worker_threads";
import { analyzeFile, type FileResult } from "./batch.ts";

const BATCH = 48;
const MIN_FILES_FOR_WORKERS = 300;

/**
 * Analyzes files on worker threads (one per core, up to 8), falling back to
 * the main thread for small scans or where workers can't start (e.g. the Node
 * bundle). Either way the event loop keeps turning, so progress UI stays live.
 */
export async function analyzeFiles(
  root: string,
  files: string[],
  onFile: (r: FileResult) => void,
): Promise<void> {
  const cores = typeof availableParallelism === "function" ? availableParallelism() : cpus().length;
  const size = Math.min(8, Math.max(1, cores - 1), Math.ceil(files.length / BATCH));
  if (files.length >= MIN_FILES_FOR_WORKERS && size > 1 && process.env.DIFFWARD_WORKERS !== "0") {
    const rest = await runWorkers(root, files, size, onFile).catch((err: Error) => {
      if (process.env.DIFFWARD_DEBUG) process.stderr.write(`diffward: workers unavailable (${err.message}); using one thread\n`);
      return files; // workers never started: analyze everything here
    });
    if (rest === null) return; // all done in workers
    files = rest; // finish whatever the workers left
  }
  let last = Date.now();
  for (const f of files) {
    onFile(analyzeFile(root, f));
    if (Date.now() - last > 16) {
      await new Promise((r) => setImmediate(r)); // let timers (the spinner) run
      last = Date.now();
    }
  }
}

/**
 * Running from source the worker sits next to this file. In a `bun build
 * --compile` binary it is embedded as an extra entrypoint at code/worker.js,
 * relative to the binary (see the build:bin script).
 */
function workerUrl(): URL {
  return import.meta.url.includes("$bunfs")
    ? new URL("./code/worker.js", import.meta.url)
    : new URL("./worker.ts", import.meta.url);
}

/** Resolves null when every file was analyzed; rejects/returns leftovers if workers fail to start. */
function runWorkers(root: string, files: string[], size: number, onFile: (r: FileResult) => void): Promise<string[] | null> {
  return new Promise((resolve, reject) => {
    let next = 0;
    let pending = files.length;
    let alive = 0;
    let started = false;
    const workers: Worker[] = [];
    const finish = (leftovers: string[] | null) => {
      for (const w of workers) void w.terminate();
      resolve(leftovers);
    };
    const feed = (w: Worker) => {
      if (next >= files.length) return;
      const batch = files.slice(next, next + BATCH);
      next += batch.length;
      w.postMessage({ root, files: batch });
    };
    for (let i = 0; i < size; i++) {
      let w: Worker;
      try {
        w = new Worker(workerUrl());
      } catch (err) {
        if (!workers.length) return reject(err);
        break;
      }
      workers.push(w);
      alive++;
      w.on("message", (results: FileResult[]) => {
        started = true;
        for (const r of results) onFile(r);
        pending -= results.length;
        if (pending === 0) finish(null);
        else feed(w);
      });
      w.on("error", (err) => {
        alive--;
        // If no batch ever came back, workers don't work here: hand everything back.
        if (!started && alive === 0) reject(err);
        else if (alive === 0) finish(files.slice(next));
      });
      feed(w);
    }
  });
}

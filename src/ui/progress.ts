import type { ProgressEvent } from "../scan.ts";
import type { Severity } from "../types.ts";

/**
 * Live scan HUD drawn on stderr while a scan runs: a shimmering title, a
 * scanning beam, gradient progress bars with a travelling glint, the file being
 * analyzed, OSV progress and live finding counters that flash on new
 * critical/high results. Only for interactive terminals; the caller decides.
 */

type ColorLevel = 0 | 1 | 2 | 3; // none, 16, 256, truecolor
type RGB = [number, number, number];

const FPS_MS = 70;
const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const PALETTE: RGB[] = [
  [0, 229, 255], // cyan
  [64, 140, 255], // blue
  [168, 85, 247], // violet
  [255, 64, 160], // magenta
  [0, 229, 255],
];
const SEVERITY_RGB: Record<Severity, RGB> = {
  critical: [255, 61, 87],
  high: [255, 145, 48],
  medium: [255, 214, 10],
  low: [64, 196, 255],
  info: [150, 150, 150],
};

export function colorLevel(env: NodeJS.ProcessEnv = process.env): ColorLevel {
  if (env.NO_COLOR) return 0;
  if (/truecolor|24bit/i.test(env.COLORTERM ?? "")) return 3;
  if (/iTerm|WezTerm|vscode|ghostty|Hyper|Apple_Terminal|WarpTerminal/i.test(env.TERM_PROGRAM ?? "")) {
    return env.TERM_PROGRAM === "Apple_Terminal" ? 2 : 3;
  }
  if (env.WT_SESSION) return 3; // Windows Terminal
  if (/256/.test(env.TERM ?? "")) return 2;
  return 1;
}

function mix(a: RGB, b: RGB, t: number): RGB {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t].map(Math.round) as RGB;
}

/** Position 0..1 along the looping palette. */
function gradient(t: number): RGB {
  const x = ((t % 1) + 1) % 1;
  const seg = x * (PALETTE.length - 1);
  const i = Math.floor(seg);
  return mix(PALETTE[i]!, PALETTE[Math.min(i + 1, PALETTE.length - 1)]!, seg - i);
}

function fg(level: ColorLevel, [r, g, b]: RGB, text: string, bold = false): string {
  if (level === 0) return text;
  const b1 = bold ? "\x1b[1m" : "";
  if (level === 3) return `${b1}\x1b[38;2;${r};${g};${b}m${text}\x1b[0m`;
  if (level === 2) {
    const c = 16 + 36 * Math.round((r / 255) * 5) + 6 * Math.round((g / 255) * 5) + Math.round((b / 255) * 5);
    return `${b1}\x1b[38;5;${c}m${text}\x1b[0m`;
  }
  // 16 colors: nearest of cyan / blue / magenta / red / yellow / white
  const code = r > 200 && g < 120 ? 31 : r > 200 && g > 180 ? 33 : r > 150 && b > 120 ? 35 : b > 200 && r < 100 ? (g > 180 ? 36 : 34) : 37;
  return `${b1}\x1b[${code}m${text}\x1b[0m`;
}

const dim = (level: ColorLevel, s: string) => (level ? `\x1b[2m${s}\x1b[0m` : s);

/** Visible width, ignoring ANSI escapes. */
function width(s: string): number {
  return s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").length;
}

/** Cut a colored string to `max` visible columns (lines must never wrap). */
function clip(s: string, max: number): string {
  let out = "";
  let visible = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\x1b") {
      const m = /^\x1b\[[0-9;?]*[A-Za-z]/.exec(s.slice(i));
      if (m) {
        out += m[0];
        i += m[0].length - 1;
        continue;
      }
    }
    if (visible >= max) break;
    out += s[i];
    visible++;
  }
  return out + "\x1b[0m";
}

function fmt(n: number): string {
  return n.toLocaleString("en-US");
}

function shorten(path: string, max: number): string {
  if (path.length <= max) return path;
  const parts = path.split("/");
  const file = parts.pop()!;
  let head = parts.shift() ?? "";
  while (`${head}/…/${file}`.length > max && head.length > 4) head = head.slice(0, -1);
  const s = `${head}/…/${file}`;
  return s.length > max ? `…${s.slice(-(max - 1))}` : s;
}

interface State {
  code?: { done: number; total: number; file?: string; finished?: boolean };
  deps?: { phase: string; done: number; total: number; cached?: number; finished?: boolean; packages?: number; vulnerable?: number };
  counts: Record<Severity, number>;
  codeFindings: number;
  codeDoneAt?: number;
  flashUntil: number;
  flashSeverity?: Severity;
}

export interface ProgressUI {
  onProgress(e: ProgressEvent): void;
  /** Erase the HUD and print a one-line summary. */
  stop(summary?: string): void;
}

export function createProgressUI(opts: {
  stream: NodeJS.WriteStream;
  title: string;
  subtitle: string;
  code: boolean;
  deps: boolean;
  level?: ColorLevel;
}): ProgressUI {
  const out = opts.stream;
  const level = opts.level ?? colorLevel();
  const started = Date.now();
  const state: State = { counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, codeFindings: 0, flashUntil: 0 };
  let frame = 0;
  let drawn = 0;
  let stopped = false;

  const restore = () => out.write("\x1b[?25h");
  const onExit = () => restore();
  const onSigint = () => {
    erase();
    restore();
    process.exit(130);
  };
  process.on("exit", onExit);
  process.on("SIGINT", onSigint);
  out.write("\x1b[?25l");

  function erase() {
    if (drawn) out.write(`\x1b[${drawn}F\x1b[0J`);
    drawn = 0;
  }

  function bar(done: number, total: number, cols: number, finished: boolean): string {
    const pct = total > 0 ? Math.min(1, done / total) : finished ? 1 : 0;
    const filled = Math.round(pct * cols);
    const glint = finished ? -1 : Math.floor((frame * 0.9) % Math.max(filled + 6, 8)) - 3;
    let s = "";
    for (let i = 0; i < cols; i++) {
      if (i < filled) {
        let c = gradient(i / cols * 0.75 + frame * 0.01);
        const d = Math.abs(i - glint);
        if (d < 3) c = mix(c, [255, 255, 255], (3 - d) / 3.2);
        s += fg(level, c, "━");
      } else if (i === filled && !finished) {
        s += fg(level, gradient(frame * 0.02), "╸");
      } else {
        s += dim(level, "─");
      }
    }
    return s;
  }

  function spinner(offset: number, finished: boolean): string {
    if (finished) return fg(level, [0, 230, 118], "✔", true);
    return fg(level, gradient(frame * 0.03 + offset / 10), SPINNER[(frame + offset) % SPINNER.length]!, true);
  }

  function render(): string[] {
    const cols = Math.max(40, Math.min(out.columns || 80, 120));
    const elapsed = ((Date.now() - started) / 1000).toFixed(1);
    const lines: string[] = [];

    // Title: gradient sweeping through the letters.
    const word = "diffward";
    let title = "";
    for (let i = 0; i < word.length; i++) title += fg(level, gradient(i / 14 - frame * 0.025), word[i]!, true);
    const left = `  ${fg(level, gradient(frame * 0.02), "◆", true)} ${title} ${dim(level, opts.title)}`;
    const right = dim(level, `${elapsed}s`);
    lines.push(left + " ".repeat(Math.max(1, cols - width(left) - width(right) - 2)) + right);

    // Scanning beam: a comet bouncing across the track.
    const track = Math.max(20, cols - 6);
    const period = (track - 1) * 2;
    const p = frame % period;
    const head = p < track ? p : period - p;
    const dir = p < track ? -1 : 1;
    let beam = "";
    for (let i = 0; i < track; i++) {
      const d = (i - head) * dir;
      if (d === 0) beam += fg(level, [255, 255, 255], "█", true);
      else if (d > 0 && d <= 10) beam += fg(level, mix(gradient(i / track + frame * 0.01), [20, 20, 30], d / 11), "▇▆▅▄▃▂▂▁▁▁"[d - 1]!);
      else beam += dim(level, "·");
    }
    lines.push(`  ${beam}`);
    lines.push(`  ${dim(level, opts.subtitle)}`);
    lines.push("");

    const barCols = Math.max(12, Math.min(34, cols - 62));
    if (opts.code) {
      const c = state.code ?? { done: 0, total: 0 };
      const pct = c.total ? Math.floor((c.done / c.total) * 100) : c.finished ? 100 : 0;
      lines.push(
        `  ${spinner(0, Boolean(c.finished))} ${"code".padEnd(9)}${bar(c.done, c.total, barCols, Boolean(c.finished))} ${String(pct).padStart(3)}%  ${dim(level, `${fmt(c.done)} / ${fmt(c.total)} files`)}`,
      );
      const file = c.finished
        ? `analyzed in ${(((state.codeDoneAt ?? Date.now()) - started) / 1000).toFixed(1)}s · ${fmt(state.codeFindings)} findings`
        : c.file
          ? shorten(c.file, cols - 16)
          : "listing files…";
      lines.push(`  ${dim(level, `            └ ${file}`)}`);
    }
    if (opts.deps) {
      const d = state.deps;
      let label = "reading lockfiles…";
      let done = 0;
      let total = 0;
      if (d) {
        done = d.done;
        total = d.total;
        if (d.finished) label = `${fmt(d.packages ?? 0)} packages · ${fmt(d.vulnerable ?? 0)} advisories`;
        else if (d.phase === "query") label = `OSV · querying ${fmt(d.total)} packages`;
        else label = `OSV · ${fmt(d.done)} / ${fmt(d.total)} advisories${d.cached ? ` · ${fmt(d.cached)} cached` : ""}`;
      }
      const pct = total ? Math.floor((done / total) * 100) : d?.finished ? 100 : 0;
      lines.push(`  ${spinner(4, Boolean(d?.finished))} ${"packages".padEnd(9)}${bar(done, total, barCols, Boolean(d?.finished))} ${String(pct).padStart(3)}%  ${dim(level, label)}`);
    }
    lines.push("");

    // Live counters; the severity that just got a new finding flashes.
    const flashing = Date.now() < state.flashUntil;
    const sev = (["critical", "high", "medium", "low"] as Severity[]).map((s) => {
      const n = state.counts[s];
      const lit = flashing && state.flashSeverity === s && frame % 2 === 0;
      const color = n ? SEVERITY_RGB[s] : ([90, 90, 90] as RGB);
      const dot = fg(level, lit ? [255, 255, 255] : color, "●", true);
      const num = n ? fg(level, lit ? [255, 255, 255] : color, fmt(n), true) : dim(level, "0");
      return `${dot} ${num} ${dim(level, s)}`;
    });
    lines.push(`  ${dim(level, "findings")}   ${sev.join("   ")}`);
    return lines.map((l) => clip(l, cols - 1));
  }

  function draw() {
    if (stopped) return;
    frame++;
    const lines = render();
    let buf = drawn ? `\x1b[${drawn}F` : "";
    for (const l of lines) buf += `\x1b[2K${l}\n`;
    out.write(buf);
    drawn = lines.length;
  }

  const timer = setInterval(draw, FPS_MS);
  draw();

  return {
    onProgress(e) {
      switch (e.type) {
        case "code":
          state.code = { ...state.code, done: e.done, total: e.total, file: e.file ?? state.code?.file };
          break;
        case "code-done":
          state.code = { ...(state.code ?? { done: e.files, total: e.files }), finished: true };
          state.codeDoneAt = Date.now();
          break;
        case "deps":
          state.deps = { phase: e.phase, done: e.done, total: e.total, cached: e.cached };
          break;
        case "deps-done":
          state.deps = { phase: "done", done: 1, total: 1, finished: true, packages: e.packages, vulnerable: e.vulnerable };
          break;
        case "finding": {
          const s = e.finding.severity;
          state.counts[s]++;
          if (e.finding.kind === "code") state.codeFindings++;
          if (s === "critical" || s === "high") {
            state.flashSeverity = s;
            state.flashUntil = Date.now() + 450;
          }
          break;
        }
      }
    },
    stop(summary) {
      if (stopped) return;
      stopped = true;
      clearInterval(timer);
      erase();
      restore();
      process.off("exit", onExit);
      process.off("SIGINT", onSigint);
      if (summary) out.write(`  ${fg(level, [0, 230, 118], "✔", true)} ${summary}\n\n`);
    },
  };
}

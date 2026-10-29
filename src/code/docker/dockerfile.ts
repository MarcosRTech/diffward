import type { RawFinding } from "../rules.ts";

export function isDockerfile(file: string): boolean {
  const base = file.slice(file.lastIndexOf("/") + 1).toLowerCase();
  return /^(?:docker|container)file(?:\.[\w.-]+)?$/.test(base) || base.endsWith(".dockerfile");
}

interface Instruction {
  op: string;
  args: string;
  line: number;
}

/** Instructions with `\` continuations joined, comments and blank lines dropped. */
function instructions(text: string): Instruction[] {
  const out: Instruction[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let raw = lines[i]!.trim();
    if (!raw || raw.startsWith("#")) continue;
    while (raw.endsWith("\\") && i + 1 < lines.length) {
      raw = `${raw.slice(0, -1)} ${lines[++i]!.trim()}`;
    }
    const m = /^([A-Za-z]+)\s+([\s\S]*)$/.exec(raw);
    if (m) out.push({ op: m[1]!.toUpperCase(), args: m[2]!.trim(), line: start + 1 });
  }
  return out;
}

export function analyzeDockerfile(text: string): RawFinding[] {
  const out: RawFinding[] = [];
  const ins = instructions(text);
  const stages: { alias?: string; image: string; line: number; user?: string }[] = [];

  for (const i of ins) {
    if (i.op === "FROM") {
      const m = /^(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(i.args);
      const image = m?.[1] ?? "";
      const parent = stages.find((s) => s.alias && s.alias.toLowerCase() === image.toLowerCase());
      stages.push({ alias: m?.[2], image, line: i.line, user: parent?.user });
      if (!parent && image !== "scratch" && !image.includes("$")) {
        const tagged = /@sha256:|:[^/]+$/.test(image);
        if (!tagged || /:latest$/.test(image)) {
          out.push({ ruleId: "docker/latest-tag", line: i.line, detail: tagged ? image : `${image} (no tag)` });
        }
      }
    } else if (i.op === "USER" && stages.length) {
      stages[stages.length - 1]!.user = i.args.split(/\s+/)[0];
    } else if (i.op === "RUN" && /\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/.test(i.args)) {
      out.push({ ruleId: "docker/curl-pipe-shell", line: i.line });
    } else if (i.op === "ADD" && /(?:^|\s)https?:\/\//.test(i.args) && !/--checksum=/.test(i.args)) {
      out.push({ ruleId: "docker/add-remote", line: i.line });
    }
  }

  const final = stages[stages.length - 1];
  if (final) {
    const user = final.user?.split(":")[0];
    const nonRootBase = /nonroot|distroless\S*:nonroot|^cgr\.dev\/|chainguard/i.test(final.image) || final.image === "scratch";
    if (!nonRootBase && (!user || user === "root" || user === "0")) {
      out.push({ ruleId: "docker/root-user", line: final.line, detail: user ? `USER ${final.user}` : "no USER in the final stage" });
    }
  }
  return out;
}

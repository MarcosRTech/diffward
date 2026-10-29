import { expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LOGO } from "../src/logo.ts";

/**
 * Runs install.sh on a pseudo-terminal (the gradient logo only appears on a TTY)
 * with a pinned version that a fake `diffward` already reports, so it prints the
 * banner and exits without touching the network. The logo text must survive
 * coloring byte-for-byte: awk splitting UTF-8 characters once printed "????".
 */
const PTY = `
import os, subprocess, sys, select, fcntl, termios, struct
master, slave = os.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
p = subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL, stdout=slave, stderr=slave)
os.close(slave)
buf = b""
while True:
    r, _, _ = select.select([master], [], [], 0.3)
    if r:
        try: d = os.read(master, 65536)
        except OSError: break
        if not d: break
        buf += d
    elif p.poll() is not None: break
p.wait()
sys.stdout.buffer.write(buf)
`;

for (const shell of ["sh", "dash"]) {
  for (const colorterm of ["truecolor", ""]) {
    const hasShell = Bun.which(shell) && Bun.which("python3");
    test.skipIf(!hasShell)(`install.sh logo renders intact (${shell}, ${colorterm || "256 colors"})`, async () => {
      const dir = mkdtempSync(join(tmpdir(), "diffward-installer-"));
      const fake = join(dir, "diffward");
      writeFileSync(fake, "#!/bin/sh\necho 9.9.9\n");
      chmodSync(fake, 0o755);
      const proc = Bun.spawn(["python3", "-c", PTY, shell, join(import.meta.dir, "..", "install.sh")], {
        env: { PATH: process.env.PATH!, HOME: dir, LANG: "en_US.UTF-8", TERM: "xterm-256color", COLORTERM: colorterm, DIFFWARD_VERSION: "v9.9.9", DIFFWARD_INSTALL_DIR: dir },
        stdout: "pipe",
      });
      const bytes = new Uint8Array(await new Response(proc.stdout).arrayBuffer());
      await proc.exited;
      rmSync(dir, { recursive: true, force: true });
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); // throws on broken bytes
      const plain = text.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").replace(/\r/g, "");
      expect(plain.split("\n").slice(0, 6).map((l) => l.trimEnd()).join("\n")).toBe(LOGO);
      expect(text).toMatch(/\x1b\[38;[25];/); // it is actually colored
      expect(plain).toContain("is already installed and up to date");
    });
  }
}

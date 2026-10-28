/** The official diffward logo (ANSI Shadow lettering). */
export const LOGO = [
  "██████╗ ██╗███████╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗",
  "██╔══██╗██║██╔════╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗",
  "██║  ██║██║█████╗  █████╗  ██║ █╗ ██║███████║██████╔╝██║  ██║",
  "██║  ██║██║██╔══╝  ██╔══╝  ██║███╗██║██╔══██║██╔══██╗██║  ██║",
  "██████╔╝██║██║     ██║     ╚███╔███╔╝██║  ██║██║  ██║██████╔╝",
  "╚═════╝ ╚═╝╚═╝     ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝",
].join("\n");

export const TAGLINE = "Security scanner for pull requests";

/**
 * The logo for interactive terminals only: piped or redirected help stays
 * plain text, and terminals without UTF-8 get just the name.
 */
export function banner(opts: { color: boolean; tty: boolean; utf8: boolean }): string {
  if (!opts.tty || !opts.utf8) return "";
  const logo = opts.color ? `\x1b[36m${LOGO}\x1b[0m` : LOGO;
  return `${logo}\n\n`;
}

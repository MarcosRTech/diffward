/**
 * Minimal gitignore-style glob matcher: `**`, `*`, `?` and trailing `/`.
 * A pattern without `/` matches any path segment (like .gitignore).
 */
export function globToRegExp(pattern: string): RegExp {
  let p = pattern.trim().replace(/\\/g, "/");
  const dirOnly = p.endsWith("/");
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.includes("/");
  if (p.startsWith("/")) p = p.slice(1);

  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    if (c === "*") {
      if (p[i + 1] === "*") {
        const slash = p[i + 2] === "/";
        re += slash ? "(?:.*/)?" : ".*";
        i += slash ? 2 : 1;
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  const prefix = anchored ? "^" : "^(?:.*/)?";
  // Matching a directory also matches everything below it.
  return new RegExp(`${prefix}${re}(?:/.*)?$`);
}

export function makeMatcher(patterns: string[]): (path: string) => boolean {
  const res = patterns.filter((p) => p.trim() && !p.startsWith("#")).map(globToRegExp);
  return (path) => res.some((r) => r.test(path));
}

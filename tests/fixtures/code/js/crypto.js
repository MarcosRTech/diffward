const crypto = require("crypto");
const https = require("https");
const jwt = require("jsonwebtoken");
const serialize = require("node-serialize");

// ruleid: js/weak-hash
const etag = crypto.createHash("md5").update("x").digest("hex");

// ok: js/weak-hash
const digest = crypto.createHash("sha256").update("x").digest("hex");

// ruleid: js/weak-cipher
const c1 = crypto.createCipheriv("des-ede3-cbc", Buffer.alloc(24), Buffer.alloc(8));

// ruleid: js/weak-cipher
const c2 = crypto.createCipheriv("aes-128-ecb", Buffer.alloc(16), null);

// ok: js/weak-cipher
const c3 = crypto.createCipheriv("aes-256-gcm", Buffer.alloc(32), crypto.randomBytes(12));

// ruleid: js/insecure-random
const resetToken = Math.random().toString(36).slice(2);

// ok: js/insecure-random
const jitter = Math.random() * 100;

// ok: js/insecure-random
const sessionId = crypto.randomUUID();

const agent = new https.Agent({
  // ruleid: js/tls-verification-disabled
  rejectUnauthorized: false,
});

// ruleid: js/tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

function verify(token, key) {
  // ruleid: js/jwt-none-algorithm
  return jwt.verify(token, key, { algorithms: ["HS256", "none"] });
}

function load(cookie) {
  // ruleid: js/insecure-deserialization
  return serialize.unserialize(cookie);
}

function suppressed(name) {
  return crypto.createHash("sha1").update(name).digest("hex"); // diffward-ignore js/weak-hash
}

module.exports = { etag, digest, c1, c2, c3, resetToken, jitter, sessionId, agent, verify, load, suppressed };

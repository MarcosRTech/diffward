// ruleid: secret/known-token
const awsKey = "AKIAZ7Q3EXAMPL3K5B2W";

// ruleid: secret/known-token
const gh = "ghp_Zq8xV2mN4bT6yH1cK9wL3pR5sD7fG0aJ2eUi";

// ruleid: secret/hardcoded-password
const dbPassword = "Sup3r-S3cr3t-Pa55!";

// ok: secret/hardcoded-password
const password = process.env.DB_PASSWORD;

// ok: secret/hardcoded-password
const apiKey = "YOUR_API_KEY";

// ok: secret/hardcoded-password
const passwordResetPath = "/account/reset-password";

// ok: secret/hardcoded-password
const secretName = "PROD_DB_PASSWORD";

export const config = {
  // ruleid: secret/hardcoded-password
  clientSecret: "f3a9c1e07b2d4c8e9a6b5d4c3b2a1f0e",
  // ok: secret/hardcoded-password
  apiKey: "changeme",
  // ruleid: secret/known-token
  database: "postgres://admin:h4rdc0ded-pw@db.internal:5432/app",
};

export { awsKey, gh, dbPassword, password, apiKey, passwordResetPath, secretName };

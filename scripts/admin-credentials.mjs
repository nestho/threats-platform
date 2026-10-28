#!/usr/bin/env node
/**
 * Generate the two admin credentials, locally.
 *
 * Prints a password (unless one is supplied), its PBKDF2 hash for
 * ADMIN_PASSWORD_HASH, a base32 TOTP secret, and an otpauth:// URI for an
 * authenticator app. It writes nothing to disk.
 *
 * Never paste the output into a chat, an issue, or a commit. Set the hash and
 * secret with `wrangler secret put` and keep the password in a password
 * manager.
 */

import { randomBytes } from "node:crypto";
import { hashPassword } from "../worker/src/auth.mjs";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ISSUER = "threats.top";
const ACCOUNT = "admin";

function base32(bytes) {
  let value = 0;
  let bits = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(value >>> bits) & 31];
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function generatePassword() {
  // 18 random bytes -> 24 base64url characters, no padding.
  return randomBytes(18)
    .toString("base64url")
    .replace(/[_-]/g, "");
}

const password = process.env.ADMIN_PASSWORD || generatePassword();
const generated = !process.env.ADMIN_PASSWORD;
const secret = base32(randomBytes(20));
const hash = await hashPassword(password);

const uri = new URL(`otpauth://totp/${ISSUER}:${ACCOUNT}`);
uri.searchParams.set("secret", secret);
uri.searchParams.set("issuer", ISSUER);
uri.searchParams.set("algorithm", "SHA1");
uri.searchParams.set("digits", "6");
uri.searchParams.set("period", "30");

const rule = "─".repeat(64);
console.log(rule);
console.log("Threats Pro admin credentials — generated locally, not stored");
console.log(rule);
if (generated) {
  console.log(`Password (shown once): ${password}`);
} else {
  console.log("Password: supplied through ADMIN_PASSWORD (not printed)");
}
console.log("");
console.log("ADMIN_PASSWORD_HASH:");
console.log(hash);
console.log("");
console.log("TOTP_SECRET:");
console.log(secret);
console.log("");
console.log("Authenticator enrolment URI:");
console.log(uri.toString());
console.log("");
console.log("Next steps:");
console.log("  cd worker");
console.log("  npx wrangler secret put ADMIN_PASSWORD_HASH   # paste the hash");
console.log("  npx wrangler secret put TOTP_SECRET           # paste the secret");
console.log("");
console.log("Enrol the URI in an authenticator app before signing in.");
console.log("Do not commit this output or paste it into a chat.");
console.log(rule);

/**
 * Licence key shape and hashing. Keys are shown once, so only the salt-hashed
 * value and an eight-character prefix are ever stored.
 */

import { bytesToHex } from "./auth.mjs";

const KEY_PATTERN = /^THREATS-PRO-[0-9A-HJKMNP-TV-Z]{20}$/;

export function normalizeLicense(value) {
  return typeof value === "string" ? value.trim().toUpperCase() : "";
}

export function isLicenseShape(key) {
  return KEY_PATTERN.test(normalizeLicense(key));
}

export async function hashLicense(key, salt) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${salt}:${normalizeLicense(key)}`),
  );
  return bytesToHex(new Uint8Array(digest));
}

export function parseBearer(header) {
  if (typeof header !== "string") return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

/**
 * Authentication primitives for the API Worker.
 *
 * Everything here runs on the Workers runtime (WebCrypto only) so the same
 * code is exercised by `node --test`. SHA-1 and base32 are implemented in
 * plain JS because Workers has no synchronous digest and TOTP verification
 * must not interleave with other requests through the event loop.
 */

const PBKDF2_ITERATIONS = 210_000;
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const subtle = globalThis.crypto.subtle;

export function bytesToHex(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function randomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToB64url(bytes);
}

export function timingSafeEqual(a, b) {
  const left = typeof a === "string" ? encoder.encode(a) : a;
  const right = typeof b === "string" ? encoder.encode(b) : b;
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

export async function pbkdf2(password, salt, iterations) {
  const key = await subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password, { iterations = PBKDF2_ITERATIONS } = {}) {
  const salt = new Uint8Array(16);
  globalThis.crypto.getRandomValues(salt);
  const hash = await pbkdf2(password, salt, iterations);
  return [
    "pbkdf2_sha256",
    iterations,
    bytesToB64url(salt),
    bytesToB64url(hash),
  ].join("$");
}

export async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 10_000_000) {
    return false;
  }
  let salt;
  let expected;
  try {
    salt = b64urlToBytes(parts[2]);
    expected = b64urlToBytes(parts[3]);
  } catch {
    return false;
  }
  const actual = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(actual, expected);
}

export async function hashIp(ip, salt) {
  const digest = await subtle.digest("SHA-256", encoder.encode(`${salt}:${ip}`));
  return bytesToHex(new Uint8Array(digest));
}

// --- TOTP -----------------------------------------------------------------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(value) {
  const clean = String(value).toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let buffer = 0;
  let bits = 0;
  const out = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error("invalid base32 character");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function rotl32(value, count) {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}

function sha1(message) {
  const bitLength = message.length * 8;
  const padded = new Uint8Array(Math.ceil((message.length + 9) / 64) * 64);
  padded.set(message);
  padded[message.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x1_0000_0000));
  view.setUint32(padded.length - 4, bitLength >>> 0);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const words = new Uint32Array(80);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) words[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 80; i += 1) {
      words[i] = rotl32(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
    }
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for (let i = 0; i < 80; i += 1) {
      let f;
      let k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const temp = (rotl32(a, 5) + f + e + k + words[i]) >>> 0;
      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = temp;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0);
  outView.setUint32(4, h1);
  outView.setUint32(8, h2);
  outView.setUint32(12, h3);
  outView.setUint32(16, h4);
  return out;
}

function hmacSha1(key, message) {
  const blockSize = 64;
  const normalized = key.length > blockSize ? sha1(key) : key;
  const padded = new Uint8Array(blockSize);
  padded.set(normalized);
  const inner = new Uint8Array(blockSize + message.length);
  const outer = new Uint8Array(blockSize + 20);
  for (let i = 0; i < blockSize; i += 1) {
    inner[i] = padded[i] ^ 0x36;
    outer[i] = padded[i] ^ 0x5c;
  }
  inner.set(message, blockSize);
  outer.set(sha1(inner), blockSize);
  return sha1(outer);
}

function hotp(secret, counter) {
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
  const digest = hmacSha1(base32Decode(secret), counterBytes);
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = new DataView(digest.buffer, digest.byteOffset, digest.byteLength).getUint32(offset) & 0x7fffffff;
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

export function totpCode(secret, nowMs) {
  return hotp(secret, Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS));
}

export function verifyTotp(secret, code, lastStep = -1, nowMs = Date.now()) {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return { ok: false, step: null };
  const current = Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS);
  for (const drift of [-1, 0, 1]) {
    const step = current + drift;
    if (step <= lastStep) continue;
    if (timingSafeEqual(hotp(secret, step), code)) return { ok: true, step };
  }
  return { ok: false, step: null };
}

// --- Sessions -------------------------------------------------------------

async function hmacSha256(secret, message) {
  const key = await subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle.sign("HMAC", key, encoder.encode(message)));
}

export async function signSession(payload, secret) {
  const body = bytesToB64url(encoder.encode(JSON.stringify(payload)));
  const signature = bytesToB64url(await hmacSha256(secret, body));
  return `${body}.${signature}`;
}

export async function verifySession(token, secret, nowMs = Date.now()) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, signature] = parts;
  if (!body || !signature) return null;
  const expected = bytesToB64url(await hmacSha256(secret, body));
  if (!timingSafeEqual(signature, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(decoder.decode(b64urlToBytes(body)));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== "object") return null;
  if (!Number.isFinite(payload.exp) || payload.exp * 1000 <= nowMs) return null;
  return payload;
}

// --- Cookies --------------------------------------------------------------

export function parseCookies(header) {
  const cookies = {};
  if (typeof header !== "string") return cookies;
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf("=");
    if (index < 1) continue;
    cookies[trimmed.slice(0, index)] = trimmed.slice(index + 1);
  }
  return cookies;
}

export function buildCookie(name, value, { maxAge, secure = true } = {}) {
  const attributes = [`${name}=${value}`, "Path=/", "HttpOnly"];
  if (secure) attributes.push("Secure");
  attributes.push("SameSite=Strict");
  if (Number.isFinite(maxAge)) attributes.push(`Max-Age=${maxAge}`);
  return attributes.join("; ");
}

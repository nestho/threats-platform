/**
 * Auth primitives. Vectors are from RFC 6070 (PBKDF2) and RFC 6238 (TOTP).
 *
 *     node --test worker/test/auth.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  base32Decode,
  buildCookie,
  bytesToHex,
  hashIp,
  hashPassword,
  parseCookies,
  pbkdf2,
  randomToken,
  signSession,
  timingSafeEqual,
  totpCode,
  verifyPassword,
  verifySession,
  verifyTotp,
} from "../src/auth.mjs";

const utf8 = (value) => new TextEncoder().encode(value);
const SECRET = "12345678901234567890";
const SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("pbkdf2 matches the published SHA-256 vectors", async () => {
  assert.equal(
    bytesToHex(await pbkdf2("password", utf8("salt"), 1)),
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
  );
  assert.equal(
    bytesToHex(await pbkdf2("password", utf8("salt"), 2)),
    "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
  );
  assert.equal(
    bytesToHex(await pbkdf2("password", utf8("salt"), 4096)),
    "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
  );
});

test("a password hash verifies only with the right password", async () => {
  const stored = await hashPassword("correct horse", { iterations: 1000 });
  assert.match(stored, /^pbkdf2_sha256\$1000\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  assert.equal(await verifyPassword("correct horse", stored), true);
  assert.equal(await verifyPassword("correct horsf", stored), false);
  assert.equal(await verifyPassword("correct horse", "not-a-hash"), false);
  assert.equal(await verifyPassword("correct horse", stored.replace("$1000$", "$2000$")), false);
});

test("two hashes of the same password use different salts", async () => {
  const a = await hashPassword("same", { iterations: 1000 });
  const b = await hashPassword("same", { iterations: 1000 });
  assert.notEqual(a, b);
  assert.equal(await verifyPassword("same", a), true);
  assert.equal(await verifyPassword("same", b), true);
});

test("totp matches the RFC 6238 SHA-1 vectors", () => {
  assert.deepEqual([...base32Decode(SECRET_B32)], [...utf8(SECRET)]);
  assert.equal(totpCode(SECRET_B32, 59_000), "287082");
  assert.equal(totpCode(SECRET_B32, 1_111_111_109_000), "081804");
  assert.equal(totpCode(SECRET_B32, 1_111_111_111_000), "050471");
});

test("totp accepts one step of drift and refuses a replay", () => {
  const now = 59_000;
  assert.equal(verifyTotp(SECRET_B32, "287082", -1, now).ok, true);
  const accepted = verifyTotp(SECRET_B32, "287082", -1, now);
  assert.equal(verifyTotp(SECRET_B32, "287082", accepted.step, now).ok, false);
  assert.equal(verifyTotp(SECRET_B32, "000000", -1, now).ok, false);
  assert.equal(verifyTotp(SECRET_B32, "28708", -1, now).ok, false);
});

test("sessions round-trip and reject tampering or expiry", async () => {
  const now = 1_700_000_000_000;
  const payload = {
    sub: "admin",
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + 60,
    csrf: "csrf-token",
  };
  const token = await signSession(payload, "session-secret");
  assert.deepEqual(await verifySession(token, "session-secret", now), payload);
  assert.equal(await verifySession(token, "other-secret", now), null);
  assert.equal(await verifySession(token, "session-secret", now + 61_000), null);

  const [body, signature] = token.split(".");
  const forged = `${payload.sub === "admin" ? body.slice(0, -2) + "xx" : body}.${signature}`;
  assert.equal(await verifySession(forged, "session-secret", now), null);
  assert.equal(await verifySession(`${body}`, "session-secret", now), null);
  assert.equal(await verifySession(`${body}.${signature}x`, "session-secret", now), null);
});

test("ip hashes are salted and stable", async () => {
  const a = await hashIp("203.0.113.7", "salt-a");
  const b = await hashIp("203.0.113.7", "salt-a");
  const c = await hashIp("203.0.113.7", "salt-b");
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test("timing-safe comparison handles strings and bytes", () => {
  assert.equal(timingSafeEqual("abc", "abc"), true);
  assert.equal(timingSafeEqual("abc", "abd"), false);
  assert.equal(timingSafeEqual("abc", "abcd"), false);
  assert.equal(timingSafeEqual(utf8("abc"), utf8("abc")), true);
});

test("cookies parse and serialise with hardened flags", () => {
  const header = "a=1; admin_session=abc.def; b=2";
  assert.equal(parseCookies(header).admin_session, "abc.def");
  const cookie = buildCookie("admin_session", "abc.def", { maxAge: 3600, secure: true });
  assert.match(cookie, /^admin_session=abc\.def; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600$/);
  const cleared = buildCookie("admin_session", "", { maxAge: 0, secure: true });
  assert.match(cleared, /Max-Age=0/);
});

test("random tokens are url-safe and unique", () => {
  const a = randomToken(16);
  assert.match(a, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(a, randomToken(16));
});

/**
 * Tests for the retired legacy admin Worker.
 *
 *     node --test worker
 *
 * The important assertion is negative: no request may reach GitHub, because
 * the previous implementation committed directly to `main`. These tests fail
 * if that write path is ever reintroduced by accident.
 */
import assert from "node:assert/strict";
import test from "node:test";

const { default: worker } = await import("./admin.js");

function request(path, method = "GET") {
  return new Request(`https://threats.top${path}`, { method });
}

test("health: unauthenticated and minimal", async () => {
  const response = await worker.fetch(request("/health"));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    service: "threats-edge",
    admin_api: "retired",
  });
});

test("legacy read routes are gone", async () => {
  const response = await worker.fetch(request("/list"));
  assert.equal(response.status, 410);
  const body = await response.json();
  assert.match(body.error, /retired/i);
});

test("legacy write routes are gone", async () => {
  for (const path of ["/add", "/saas/watchlist", "/saas/verify", "/saas/stix"]) {
    const response = await worker.fetch(request(path, "POST"));
    assert.equal(response.status, 410, `${path} must not be writable`);
  }
});

test("unknown routes are also retired, not a second surface", async () => {
  const response = await worker.fetch(request("/anything"));
  assert.equal(response.status, 410);
});

test("preflight is answered without touching a backend", async () => {
  const response = await worker.fetch(request("/add", "OPTIONS"));
  assert.equal(response.status, 204);
});

test("no request calls out to GitHub", async () => {
  let called = false;
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    called = true;
    return new Response("unexpected", { status: 500 });
  };
  try {
    for (const path of ["/health", "/list", "/add", "/saas/watchlist"]) {
      await worker.fetch(request(path, path === "/health" ? "GET" : "POST"));
    }
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(called, false, "the Worker must have no network write path");
});

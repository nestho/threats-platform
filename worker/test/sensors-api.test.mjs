import assert from "node:assert/strict";
import test from "node:test";

import { createApp } from "../src/index.mjs";
import { createFakeRepo } from "./fake-repo.mjs";

const NOW = Date.parse("2026-11-14T12:34:30Z");
const TOKEN = "sensor-ingest-test-token";

function makeApp(repo = createFakeRepo(), overrides = {}) {
  return createApp({
    repo,
    env: { SENSOR_INGEST_TOKEN: TOKEN, ...overrides },
    now: () => NOW,
  });
}

function request(path, { method = "GET", body, token, headers = {} } = {}) {
  return new Request(`https://api.threats.top${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

const sample = {
  events: [
    { minute: "2026-11-14T12:33:00Z", country: "US", count: 4, src_ip: "203.0.113.8", password: "discard-me" },
    { minute: "2026-11-14T12:33:00Z", country: "GB", count: 2 },
  ],
};

test("Cowrie ingestion requires a configured bearer token", async () => {
  const blocked = await makeApp().handle(request("/api/sensors/cowrie/events", {
    method: "POST",
    body: sample,
  }));
  assert.equal(blocked.status, 401);

  const unconfigured = await makeApp(createFakeRepo(), { SENSOR_INGEST_TOKEN: "" }).handle(
    request("/api/sensors/cowrie/events", { method: "POST", body: sample, token: TOKEN }),
  );
  assert.equal(unconfigured.status, 503);
});

test("Cowrie ingestion validates and stores only country-minute aggregates", async () => {
  const repo = createFakeRepo();
  const app = makeApp(repo);
  const response = await app.handle(request("/api/sensors/cowrie/events", {
    method: "POST",
    body: sample,
    token: TOKEN,
  }));
  assert.equal(response.status, 202);
  assert.equal((await response.json()).accepted, 2);

  const duplicate = await app.handle(request("/api/sensors/cowrie/events", {
    method: "POST",
    body: { events: [{ minute: "2026-11-14T12:33:00Z", country: "US", count: 9 }] },
    token: TOKEN,
  }));
  assert.equal(duplicate.status, 202);

  const feed = await app.handle(request("/api/sensors/events?hours=1"));
  const body = await feed.json();
  assert.equal(body.source, "Cowrie SSH honeypot connections observed by this project");
  assert.equal(body.sensor_last_seen, "2026-11-14T12:34:30Z");
  assert.equal(body.events.length, 2);
  assert.equal(body.events.find((event) => event.country === "US").count, 9);
  assert.deepEqual(body.events[0], {
    id: "cowrie-ssh:2026-11-14T12:33:00Z:GB",
    kind: "sensor",
    ts: "2026-11-14T12:33:00Z",
    country: "GB",
    count: 2,
  });
  assert.equal(body.events.some((event) => "ip" in event || "src_ip" in event), false);
});

test("an empty authenticated batch records a sensor heartbeat", async () => {
  const app = makeApp();
  const response = await app.handle(request("/api/sensors/cowrie/events", {
    method: "POST",
    body: { events: [] },
    token: TOKEN,
  }));
  assert.equal(response.status, 202);
  assert.equal((await response.json()).accepted, 0);

  const feed = await app.handle(request("/api/sensors/events"));
  const body = await feed.json();
  assert.equal(body.sensor_configured, true);
  assert.equal(body.sensor_last_seen, "2026-11-14T12:34:30Z");
  assert.deepEqual(body.events, []);
});

test("invalid aggregates are rejected without partially writing the batch", async () => {
  const repo = createFakeRepo();
  const app = makeApp(repo);
  const response = await app.handle(request("/api/sensors/cowrie/events", {
    method: "POST",
    token: TOKEN,
    body: {
      events: [
        { minute: "2026-11-14T12:33:00Z", country: "US", count: 4 },
        { minute: "2026-11-14T12:33:10Z", country: "US", count: 0 },
      ],
    },
  }));
  assert.equal(response.status, 400);
  assert.equal((await (await app.handle(request("/api/sensors/events"))).json()).events.length, 0);
});

test("the public sensor window is bounded", async () => {
  const response = await makeApp().handle(request("/api/sensors/events?hours=999"));
  assert.equal(response.status, 400);
});

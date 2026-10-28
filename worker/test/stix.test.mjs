/**
 * STIX 2.1 export: deterministic IDs, honest indicator metadata, and the
 * licence-gated route.
 *
 *     node --test worker/test/stix.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import { licensePrefix } from "../src/codes.mjs";
import { createApp } from "../src/index.mjs";
import { hashLicense } from "../src/license.mjs";
import { buildBundle, uuidv5 } from "../src/stix.mjs";
import { createFakeRepo } from "./fake-repo.mjs";

const CVES = {
  updated_at: "2026-10-28T13:18:52Z",
  actively_exploited: {
    items: [
      {
        id: "CVE-2026-0001",
        vendor: "Adobe",
        product: "Commerce",
        name: "Adobe Commerce RCE",
        date_added: "2026-10-27",
        ransomware_use: "Known",
        description: "Remote code execution.",
        link: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
      },
      {
        id: "CVE-2026-0002",
        vendor: "Cisco",
        product: "IOS",
        name: "",
        date_added: "2026-10-20",
        ransomware_use: null,
        description: "",
        link: "",
      },
    ],
  },
};

const IOCS = {
  updated_at: "2026-10-28T13:19:09Z",
  items: [
    {
      id: "ioc-1",
      type: "url",
      value: "hxxps://evil.example/login",
      context: "active phishing URL",
      severity: "HIGH",
      first_seen: "2026-10-28T12:00:00Z",
      last_seen: "2026-10-28T13:00:00Z",
    },
    {
      id: "ioc-2",
      type: "domain",
      value: "evil[.]example",
      context: "phishing domain",
      severity: "HIGH",
      first_seen: "2026-10-28T11:00:00Z",
      last_seen: "2026-10-28T13:10:00Z",
    },
    {
      id: "ioc-3",
      type: "url",
      value: "hxxp://third.example/payload",
      context: "",
      severity: "MEDIUM",
      first_seen: "2026-10-28T10:00:00Z",
      last_seen: "2026-10-28T12:30:00Z",
    },
  ],
};

const NOW = "2026-10-28T12:00:00Z";

test("uuidv5 uses SHA-1 and sets the version and variant bits", async () => {
  const id = await uuidv5("https://threats.top/test");
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(id, await uuidv5("https://threats.top/test"));
  assert.notEqual(id, await uuidv5("https://threats.top/other"));
});

test("the bundle is deterministic, typed, and complete", async () => {
  const first = await buildBundle({ cves: CVES, iocs: IOCS });
  const second = await buildBundle({ cves: CVES, iocs: IOCS });
  assert.deepEqual(first, second);

  assert.equal(first.type, "bundle");
  assert.match(first.id, /^bundle--[0-9a-f-]{36}$/);

  const vulnerabilities = first.objects.filter((object) => object.type === "vulnerability");
  const indicators = first.objects.filter((object) => object.type === "indicator");
  const reports = first.objects.filter((object) => object.type === "report");

  assert.equal(vulnerabilities.length, 2);
  assert.equal(indicators.length, 3);
  assert.equal(reports.length, 1);

  for (const object of first.objects) {
    assert.match(object.id, /^(vulnerability|indicator|report)--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }

  assert.equal(vulnerabilities[0].created, "2026-10-27T00:00:00Z");
  assert.equal(vulnerabilities[0].external_references[0].external_id, "CVE-2026-0001");
  assert.equal(vulnerabilities[1].name, "Cisco IOS");
  assert.equal(vulnerabilities[0].x_threats_kev, true);

  assert.equal(indicators[0].pattern, "[url:value = 'hxxps://evil.example/login']");
  assert.equal(indicators[1].pattern, "[domain-name:value = 'evil[.]example']");
  assert.equal(indicators[0].x_threats_defanged, true);
  assert.equal(indicators[0].created, "2026-10-28T12:00:00Z");
  assert.equal(indicators[0].modified, "2026-10-28T13:00:00Z");

  assert.equal(reports[0].published, "2026-10-28T13:19:09Z");
  assert.equal(reports[0].object_refs.length, vulnerabilities.length + indicators.length);
  assert.deepEqual(
    reports[0].object_refs,
    first.objects.filter((object) => object.type !== "report").map((object) => object.id),
  );
});

test("ransomware claims are not exported", async () => {
  const bundle = await buildBundle({ cves: CVES, iocs: IOCS });
  assert.doesNotMatch(JSON.stringify(bundle), /ransomware/i);
});

test("the indicator cap is applied", async () => {
  const bundle = await buildBundle({ cves: CVES, iocs: IOCS, cap: 1 });
  assert.equal(bundle.objects.filter((object) => object.type === "indicator").length, 1);
});

async function seedLicense(repo) {
  const salt = "license-salt";
  await repo.upsertCustomer({
    id: "cus_1",
    email: "ada@example.com",
    name: "Ada Lovelace",
    phone: null,
    now: NOW,
  });
  await repo.insertSubscription({
    id: "sub_1",
    customer_id: "cus_1",
    plan: "pro",
    status: "active",
    started_at: NOW,
    expires_at: "2026-11-28T12:00:00Z",
    source_order_id: null,
    note: null,
    created_at: NOW,
    updated_at: NOW,
  });
  const key = "THREATS-PRO-0123456789ABCDEFGHJK";
  await repo.insertLicense({
    id: "lic_1",
    subscription_id: "sub_1",
    customer_id: "cus_1",
    key_hash: await hashLicense(key, salt),
    key_prefix: licensePrefix(key),
    status: "active",
    created_at: NOW,
    last_used_at: null,
    revoked_at: null,
  });
  return { key, salt };
}

function makeApp(repo, feedFetch, env = {}) {
  return createApp({
    repo,
    env: {
      ALLOWED_ORIGINS: "https://threats.top",
      SITE_ORIGIN: "https://threats.top",
      IP_HASH_SALT: "ip-salt",
      LICENSE_SALT: "license-salt",
      feedFetch,
      ...env,
    },
    now: () => Date.parse(NOW),
  });
}

const stubFeed = async (url) =>
  new Response(JSON.stringify(url.endsWith("cves.json") ? CVES : IOCS), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

test("a licensed request downloads the bundle as STIX JSON", async () => {
  const repo = createFakeRepo();
  const { key } = await seedLicense(repo);
  const seen = [];
  const app = makeApp(repo, async (url) => {
    seen.push(url);
    return stubFeed(url);
  });

  const response = await app.handle(
    new Request("https://api.threats.top/api/stix", { headers: { authorization: `Bearer ${key}` } }),
  );

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /^application\/stix\+json;version=2\.1/);
  assert.match(response.headers.get("content-disposition"), /threats-stix-2026-10-28\.json/);

  const body = await response.json();
  assert.equal(body.type, "bundle");
  assert.equal(body.objects.filter((object) => object.type === "vulnerability").length, 2);
  assert.deepEqual(seen.sort(), [
    "https://threats.top/data/cves.json",
    "https://threats.top/data/iocs.json",
  ]);
});

test("the STIX rate limit is enforced per licence", async () => {
  const repo = createFakeRepo();
  const { key } = await seedLicense(repo);
  await repo.putSetting("stix_rate_per_min", 1);
  const app = makeApp(repo, stubFeed);
  const request = () =>
    new Request("https://api.threats.top/api/stix", { headers: { authorization: `Bearer ${key}` } });

  assert.equal((await app.handle(request())).status, 200);
  const limited = await app.handle(request());
  assert.equal(limited.status, 429);
  assert.equal((await limited.json()).error.code, "rate_limited");
});

test("a feed outage is reported without leaking the cause", async () => {
  const repo = createFakeRepo();
  const { key } = await seedLicense(repo);
  const app = makeApp(repo, async () => new Response("upstream boom", { status: 503 }));

  const response = await app.handle(
    new Request("https://api.threats.top/api/stix", { headers: { authorization: `Bearer ${key}` } }),
  );

  assert.equal(response.status, 502);
  const body = await response.json();
  assert.equal(body.error.code, "feed_unavailable");
  assert.doesNotMatch(JSON.stringify(body), /upstream boom/);
});

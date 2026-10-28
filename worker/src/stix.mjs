/**
 * STIX 2.1 export of the public feeds.
 *
 * Only facts the feeds actually publish are exported: CISA KEV entries become
 * `vulnerability` objects and the defanged IOC feed becomes `indicator`
 * objects that say so in `x_threats_defanged`. Ransomware victim claims are
 * not indicators and are deliberately absent.
 */

const NAMESPACE = "6ba7b8109dad11d180b400c04fd430c8";
const MAX_INDICATORS = 1000;
const encoder = new TextEncoder();

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function formatUuid(bytes) {
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

export async function uuidv5(name) {
  const namespace = hexToBytes(NAMESPACE);
  const payload = new Uint8Array(namespace.length + name.length);
  const encoded = encoder.encode(name);
  payload.set(namespace);
  payload.set(encoded, namespace.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", payload));
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  return formatUuid(digest);
}

const patternValue = (value) => String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");

const PATTERN_TYPES = {
  url: "url",
  domain: "domain-name",
  ipv4: "ipv4-addr",
};

const isoDay = (value) => (value && !String(value).includes("T") ? `${value}T00:00:00Z` : value);

function kevObject(item, origin) {
  const created = isoDay(item.date_added);
  return {
    type: "vulnerability",
    spec_version: "2.1",
    id: null,
    created,
    modified: created,
    name: item.name?.trim() || [item.vendor, item.product].filter(Boolean).join(" ") || item.id,
    description: item.description || undefined,
    labels: ["known-exploited"],
    external_references: item.link
      ? [{ source_name: "cve", external_id: item.id, url: item.link }]
      : [{ source_name: "cve", external_id: item.id }],
    x_threats_kev: true,
    x_threats_origin: origin,
  };
}

function indicatorObject(item, snapshot, origin) {
  const patternType = PATTERN_TYPES[item.type];
  if (!patternType) return null;
  return {
    type: "indicator",
    spec_version: "2.1",
    id: null,
    created: item.first_seen ?? snapshot,
    modified: item.last_seen ?? snapshot,
    name: `${item.type}: ${item.value}`,
    description: item.context || undefined,
    pattern: `[${patternType}:value = '${patternValue(item.value)}']`,
    pattern_type: "stix",
    valid_from: item.first_seen ?? snapshot,
    indicator_types: ["malicious-activity"],
    x_threats_defanged: true,
    x_threats_severity: item.severity ?? undefined,
    x_threats_origin: origin,
  };
}

export async function buildBundle({ cves, iocs, cap = MAX_INDICATORS, origin = "https://threats.top" }) {
  const kev = cves?.actively_exploited?.items ?? [];
  const indicators = (iocs?.items ?? []).slice(0, cap);
  const cveSnapshot = cves?.updated_at ?? iocs?.updated_at ?? new Date(0).toISOString();
  const iocSnapshot = iocs?.updated_at ?? cveSnapshot;
  const snapshot = cveSnapshot > iocSnapshot ? cveSnapshot : iocSnapshot;

  const objects = [];

  for (const item of kev) {
    const object = kevObject(item, origin);
    object.id = `vulnerability--${await uuidv5(`${origin}/cve/${item.id}`)}`;
    objects.push(object);
  }

  for (const item of indicators) {
    const object = indicatorObject(item, snapshot, origin);
    if (!object) continue;
    object.id = `indicator--${await uuidv5(`${origin}/ioc/${item.id}`)}`;
    objects.push(object);
  }

  const report = {
    type: "report",
    spec_version: "2.1",
    id: `report--${await uuidv5(`${origin}/stix/${snapshot}`)}`,
    created: snapshot,
    modified: snapshot,
    published: snapshot,
    name: "Threats.top public feed snapshot",
    description:
      "Known-exploited CVEs from CISA KEV and defanged indicators published by threats.top. " +
      "Indicators are exported exactly as published, which means they remain defanged.",
    report_types: ["threat-report"],
    object_refs: objects.map((object) => object.id),
    x_threats_origin: origin,
  };

  return {
    type: "bundle",
    id: `bundle--${await uuidv5(`${origin}/stix/bundle/${snapshot}`)}`,
    objects: [...objects, report],
  };
}

export async function fetchFeed(origin, path, fetchImpl = fetch, cache) {
  const url = new URL(path, origin).toString();
  const key = new Request(url, { method: "GET" });
  if (cache) {
    const hit = await cache.match(key);
    if (hit) return hit.json();
  }
  const response = await fetchImpl(url, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`feed ${path} returned ${response.status}`);
  const data = await response.json();
  if (cache) {
    await cache.put(
      key,
      new Response(JSON.stringify(data), {
        headers: { "content-type": "application/json", "cache-control": "max-age=300" },
      }),
    );
  }
  return data;
}

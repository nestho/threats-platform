import { timingSafeEqual } from "./auth.mjs";
import { bodyFailure, fail, json, readJsonBody } from "./http.mjs";

const SENSOR = "cowrie-ssh";
const MAX_BATCH = 50;
const MAX_COUNT = 1_000_000_000;
const MINUTE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00Z$/;
const COUNTRY = /^[A-Z]{2}$/;

function iso(ms) {
  return new Date(ms).toISOString().replace(".000Z", "Z");
}

function validMinute(value, now) {
  if (typeof value !== "string" || !MINUTE.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed)
    && iso(parsed) === value
    && parsed <= now + 5 * 60_000
    && parsed >= now - 7 * 86_400_000;
}

function unauthorized(ctx) {
  const expected = ctx.env.SENSOR_INGEST_TOKEN;
  const authorization = ctx.request.headers.get("authorization") ?? "";
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return !expected || !match || !timingSafeEqual(match[1], expected);
}

export async function ingestCowrie(ctx) {
  if (!ctx.env.SENSOR_INGEST_TOKEN) {
    return fail(503, "sensor_ingest_unconfigured", "Sensor ingestion is not configured.");
  }
  if (unauthorized(ctx)) {
    return fail(401, "unauthorized", "A valid sensor token is required.");
  }

  const body = await readJsonBody(ctx.request, 32_768);
  if (!body.ok) return bodyFailure(body);
  if (!Array.isArray(body.value?.events) || body.value.events.length > MAX_BATCH) {
    return fail(400, "invalid_events", `Send no more than ${MAX_BATCH} aggregated events.`);
  }

  const seen = new Set();
  const events = [];
  for (const event of body.value.events) {
    const minute = event?.minute;
    const country = event?.country;
    const count = event?.count;
    const key = `${minute}|${country}`;
    if (
      !validMinute(minute, ctx.now()) ||
      typeof country !== "string" ||
      !COUNTRY.test(country) ||
      !Number.isSafeInteger(count) ||
      count < 1 ||
      count > MAX_COUNT ||
      seen.has(key)
    ) {
      return fail(400, "invalid_event", "Each event needs a valid minute, ISO country code, and positive count.");
    }
    seen.add(key);
    events.push({ sensor: SENSOR, minute, country, count });
  }

  const ingestedAt = iso(ctx.now());
  await ctx.repo.upsertSensorEvents(events, ingestedAt);
  await ctx.repo.touchSensor(SENSOR, ingestedAt);
  return json({ accepted: events.length, updated_at: ingestedAt }, { status: 202 });
}

export async function listSensorEvents(ctx) {
  const rawHours = ctx.url.searchParams.get("hours") ?? "72";
  const hours = Number(rawHours);
  if (!Number.isInteger(hours) || hours < 1 || hours > 168) {
    return fail(400, "invalid_window", "The hours parameter must be an integer from 1 to 168.");
  }

  const since = iso(ctx.now() - hours * 3_600_000);
  const rows = await ctx.repo.listSensorEvents({ since, limit: 10_000 });
  const status = await ctx.repo.getSensorStatus(SENSOR);
  return json({
    schema_version: 1,
    source: "Cowrie SSH honeypot connections observed by this project",
    sensor_configured: Boolean(ctx.env.SENSOR_INGEST_TOKEN),
    sensor_last_seen: status?.last_seen ?? null,
    updated_at: rows[0]?.ingested_at ?? null,
    window_hours: hours,
    events: rows.map((row) => ({
      id: `${row.sensor}:${row.minute}:${row.country}`,
      kind: "sensor",
      ts: row.minute,
      country: row.country,
      count: row.count,
    })),
  });
}

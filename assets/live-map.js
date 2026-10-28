/**
 * Model helpers for the live threat map.
 *
 * The page animates claims and phishing hosts from data/live.json. That feed is
 * a rolling snapshot refreshed by the collectors, not a socket: "live" here
 * means "the last collection is recent and events are landing in it", and the
 * page says so with an explicit LIVE / DELAYED / STALE / OFFLINE banner rather
 * than implying a permanent stream.
 *
 * Everything here is pure so the arithmetic -- 72-hour window, hourly buckets,
 * replay head, pulse sizing -- is testable without a DOM.
 */

export const WINDOW_HOURS = 72;

const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;
const ISO2 = /^[A-Z]{2}$/;

/* Ingest bands, as multiples of the source cadence. An hourly feed that is two
 * hours old is delayed, not broken; one that is ten hours old is stale. */
const LIVE_FACTOR = 1.5;
const DELAYED_FACTOR = 6;
const STALE_FACTOR = 24;

/** Parsed timestamp in ms, or null when the feed value is unusable. */
export function eventTime(event) {
  if (!event || typeof event.ts !== 'string') return null;
  const time = Date.parse(event.ts);
  return Number.isNaN(time) ? null : time;
}

/**
 * Events inside the window that ends at `end`.
 *
 * `end` is the right edge of the feed window (effectively "now"), and `head` is
 * the replay head the map is showing. The timeline moves `head` backwards
 * through the window to replay it, so the window itself never shifts and the
 * sparkline keeps its full 72-hour reference.
 *
 * The start is exclusive, so an event exactly 72 hours old belongs to the
 * previous window rather than to both.
 */
export function eventsInWindow(events, { end = Date.now(), head = end, hours = WINDOW_HOURS } = {}) {
  const start = end - hours * HOUR_MS;
  const limit = Math.min(head, end);
  const kept = [];
  for (const event of Array.isArray(events) ? events : []) {
    const time = eventTime(event);
    if (time === null || time > limit || time <= start) continue;
    kept.push(event);
  }
  return kept;
}

/** One bucket per hour, oldest first, for the timeline and its sparkline. */
export function hourlyBuckets(events, { end = Date.now(), hours = WINDOW_HOURS } = {}) {
  const buckets = Array.from({ length: hours }, (_, index) => ({
    start: end - (hours - index) * HOUR_MS,
    claims: 0,
    hosts: 0,
    total: 0,
  }));

  for (const event of eventsInWindow(events, { end, hours })) {
    const offset = Math.floor((end - eventTime(event)) / HOUR_MS);
    if (offset < 0 || offset >= hours) continue;
    const bucket = buckets[hours - 1 - offset];
    if (event.kind === 'host') bucket.hosts += 1;
    else bucket.claims += 1;
    bucket.total += 1;
  }
  return buckets;
}

/**
 * Per-country totals for the visible window.
 *
 * `unmapped` is reported rather than folded into a country: the feed only
 * publishes events it could place, so this is a safety net against a code that
 * reaches the browser from somewhere else.
 */
export function aggregateEvents(events, { end = Date.now(), head = end, hours = WINDOW_HOURS } = {}) {
  const byCode = new Map();
  let total = 0;
  let claims = 0;
  let hosts = 0;
  let unmapped = 0;

  for (const event of eventsInWindow(events, { end, head, hours })) {
    total += 1;
    const isHost = event.kind === 'host';
    if (isHost) hosts += 1;
    else claims += 1;

    const code = String(event.country ?? '').trim().toUpperCase();
    if (!ISO2.test(code)) {
      unmapped += 1;
      continue;
    }

    let entry = byCode.get(code);
    if (!entry) {
      entry = {
        code,
        claims: 0,
        hosts: 0,
        total: 0,
        latest: null,
        latestTime: -Infinity,
        groups: new Map(),
      };
      byCode.set(code, entry);
    }
    entry.total += 1;
    if (isHost) {
      entry.hosts += 1;
    } else {
      entry.claims += 1;
      const group = String(event.group ?? '').trim() || 'Unattributed';
      entry.groups.set(group, (entry.groups.get(group) || 0) + 1);
    }

    const time = eventTime(event);
    if (time !== null && time > entry.latestTime) {
      entry.latestTime = time;
      entry.latest = event.ts;
    }
  }

  const countries = [...byCode.values()]
    .map((entry) => ({
      code: entry.code,
      claims: entry.claims,
      hosts: entry.hosts,
      total: entry.total,
      latest: entry.latest,
      groups: [...entry.groups]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    }))
    .sort((a, b) => b.total - a.total || a.code.localeCompare(b.code));

  return {
    total,
    claims,
    hosts,
    unmapped,
    max: countries.length ? countries[0].total : 0,
    countries,
  };
}

/** Running totals over buckets, so replay only needs an index. */
export function cumulative(buckets) {
  let running = 0;
  return (Array.isArray(buckets) ? buckets : []).map((bucket) => {
    running += Number(bucket?.total) || 0;
    return running;
  });
}

/** IDs in `events` that were not in `seen`, each once. */
export function newEventIds(seen, events) {
  const known = seen instanceof Set ? seen : new Set(Array.isArray(seen) ? seen : []);
  const fresh = [];
  const added = new Set();
  for (const event of Array.isArray(events) ? events : []) {
    const id = event?.id;
    if (typeof id !== 'string' || !id || known.has(id) || added.has(id)) continue;
    added.add(id);
    fresh.push(id);
  }
  return fresh;
}

/**
 * How fresh the feed is, as a state the page can render without arithmetic.
 *
 * The bands scale with the source cadence because a six-hour source is not
 * late at five hours. Thresholds are intentionally generous on the slow side:
 * calling an on-time feed "stale" trains people to ignore the banner.
 */
export function ingestState({ updatedAt, now = Date.now(), cadenceMinutes = 60 } = {}) {
  const time = typeof updatedAt === 'string' ? Date.parse(updatedAt) : NaN;
  if (Number.isNaN(time)) return { state: 'offline', ageMinutes: null };

  const cadence = Number(cadenceMinutes) > 0 ? Number(cadenceMinutes) : 60;
  const ageMinutes = Math.max(0, Math.round((now - time) / MINUTE_MS));
  if (ageMinutes <= cadence * LIVE_FACTOR) return { state: 'live', ageMinutes };
  if (ageMinutes <= cadence * DELAYED_FACTOR) return { state: 'delayed', ageMinutes };
  if (ageMinutes <= cadence * STALE_FACTOR) return { state: 'stale', ageMinutes };
  return { state: 'offline', ageMinutes };
}

/** Pulse radius: sqrt scale so one busy country does not flatten the rest. */
export function pulseRadius(count, max, { min = 3, max: maxRadius = 9 } = {}) {
  const value = Number(count) || 0;
  const peak = Number(max) || 0;
  if (value <= 0 || peak <= 0) return 0;
  const share = Math.min(value / peak, 1);
  return Number((min + (maxRadius - min) * Math.sqrt(share)).toFixed(2));
}

/** How many pulses a country earns: one at the quiet end, four at the busiest. */
export function pulseCount(count, max, { maxPulses = 4 } = {}) {
  const value = Number(count) || 0;
  const peak = Number(max) || 0;
  if (value <= 0 || peak <= 0) return 0;
  return Math.max(1, Math.min(maxPulses, Math.ceil((value / peak) * maxPulses)));
}

/** One line of text for the ticker, in the feed's own vocabulary. */
export function eventLabel(event) {
  if (!event) return '';
  if (event.kind === 'host') {
    return event.host ? `Phishing host · ${event.host}` : 'Phishing host';
  }
  const group = String(event.group ?? '').trim() || 'Unattributed';
  return event.sector ? `${group} claim · ${event.sector}` : `${group} claim`;
}

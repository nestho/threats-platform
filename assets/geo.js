/**
 * Geography helpers for map.html.
 *
 * The map plots ransomware victim claims by the country the leak site claimed,
 * taken from data/ransomware.json. It is deliberately not an IP geolocation
 * product: resolving phishing hosts to coordinates would need a lookup service
 * with a licence that does not fit a commercial site, and would attribute
 * hosting infrastructure rather than victims. Country codes already in the feed
 * are the honest input, and the share of claims that carry one is shown on the
 * page rather than quietly dropped.
 */

const ISO2 = /^[A-Z]{2}$/;

/** Parsed timestamp for ordering, or null when the feed value is unusable. */
function timeValue(value) {
  if (!value) return null;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? null : time;
}

/**
 * Aggregate claims into per-country counts.
 *
 * Claims without a usable ISO 3166-1 alpha-2 code are counted in `unmapped`
 * instead of being assigned to a guessed country, so the page can state its own
 * coverage.
 *
 * @param {object[]} items  ransomware feed items
 * @returns {{total: number, mapped: number, unmapped: number,
 *   max: number, countries: {code: string, count: number, latest: string|null,
 *   groups: {name: string, count: number}[]}[]}}
 */
export function aggregateClaims(items) {
  const byCode = new Map();
  let total = 0;
  let mapped = 0;

  for (const item of Array.isArray(items) ? items : []) {
    total += 1;
    const code = String(item?.country ?? "").trim().toUpperCase();
    if (!ISO2.test(code)) continue;
    mapped += 1;

    let entry = byCode.get(code);
    if (!entry) {
      entry = { code, count: 0, latest: null, latestTime: -Infinity, groups: new Map() };
      byCode.set(code, entry);
    }
    entry.count += 1;

    const group = String(item?.group ?? "").trim() || "Unattributed";
    entry.groups.set(group, (entry.groups.get(group) || 0) + 1);

    const published = item?.published || item?.discovered;
    const time = timeValue(published);
    if (time !== null && time > entry.latestTime) {
      entry.latestTime = time;
      entry.latest = published;
    }
  }

  const countries = [...byCode.values()]
    .map((entry) => ({
      code: entry.code,
      count: entry.count,
      latest: entry.latest,
      groups: [...entry.groups]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));

  return {
    total,
    mapped,
    unmapped: total - mapped,
    max: countries.length ? countries[0].count : 0,
    countries,
  };
}

/**
 * Choropleth intensity for a country, 0 (no claims) to 4 (heaviest).
 *
 * Scaled against the busiest country rather than fixed counts, because the feed
 * window is a rolling set of recent claims and its absolute size drifts. The
 * thresholds are wide so a single-claim country stays visibly coloured instead
 * of vanishing into the background.
 *
 * @param {number} count
 * @param {number} max  count of the busiest country
 */
export function levelFor(count, max) {
  const value = Number(count) || 0;
  const peak = Number(max) || 0;
  if (value <= 0 || peak <= 0) return 0;
  const share = value / peak;
  if (share >= 0.5) return 4;
  if (share >= 0.2) return 3;
  if (share >= 0.08) return 2;
  return 1;
}

/* Intl.DisplayNames is built into every browser the console targets, so country
 * labels need no lookup table in the repository. */
const regions = typeof Intl !== "undefined" && Intl.DisplayNames
  ? new Intl.DisplayNames(["en"], { type: "region" })
  : null;

/** English name for an ISO 3166-1 alpha-2 code, falling back to the code. */
export function countryName(code) {
  const key = String(code ?? "").trim().toUpperCase();
  if (!ISO2.test(key) || !regions) return key || "Unknown";
  try {
    return regions.of(key) || key;
  } catch {
    return key;
  }
}

/** Group claim totals across every country, busiest first. */
export function groupTotals(countries) {
  const totals = new Map();
  for (const country of Array.isArray(countries) ? countries : []) {
    for (const group of country.groups || []) {
      totals.set(group.name, (totals.get(group.name) || 0) + group.count);
    }
  }
  return [...totals]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

/**
 * Subscription windows and status.
 *
 * Dates cross the API and D1 as `YYYY-MM-DDTHH:MM:SSZ`; the arithmetic runs on
 * epoch milliseconds so month-end clamping is the only calendar subtlety.
 */

const DAY_MS = 86_400_000;

function toMs(value) {
  if (value === null || value === undefined || value === "") return 0;
  if (typeof value === "number") return value;
  if (value instanceof Date) return value.getTime();
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export function toIso(value) {
  const date = new Date(toMs(value));
  return date.toISOString().replace(".000Z", "Z");
}

function addMonths(ms, months) {
  const start = new Date(ms);
  const targetMonth = new Date(
    Date.UTC(
      start.getUTCFullYear(),
      start.getUTCMonth() + months,
      1,
      start.getUTCHours(),
      start.getUTCMinutes(),
      start.getUTCSeconds(),
    ),
  );
  const lastDay = new Date(
    Date.UTC(targetMonth.getUTCFullYear(), targetMonth.getUTCMonth() + 1, 0),
  ).getUTCDate();
  targetMonth.setUTCDate(Math.min(start.getUTCDate(), lastDay));
  return targetMonth.getTime();
}

/**
 * Extends from whichever is later: the current paid expiry or now. A lapsed
 * subscription therefore restarts today instead of inheriting lost days.
 */
export function extendExpiry(now, currentExpiry, months) {
  const nowMs = toMs(now);
  const currentMs = Math.max(toMs(currentExpiry), nowMs);
  return toIso(addMonths(currentMs, months));
}

export function subscriptionStatus(expiresAt, now, stored = "active") {
  if (stored === "revoked") return "revoked";
  return toMs(expiresAt) > toMs(now) ? "active" : "expired";
}

export function daysLeft(expiresAt, now) {
  const remaining = toMs(expiresAt) - toMs(now);
  return remaining > 0 ? Math.ceil(remaining / DAY_MS) : 0;
}

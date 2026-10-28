import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  aggregateEvents,
  cumulative,
  eventLabel,
  eventTime,
  eventsInWindow,
  hourlyBuckets,
  ingestState,
  newEventIds,
  pulseCount,
  pulseRadius,
} from './live-map.js';

const NOW = Date.parse('2026-10-28T12:00:00Z');
const HOUR = 3_600_000;

const event = (overrides = {}) => ({
  id: 'rw-1',
  kind: 'claim',
  ts: '2026-10-28T06:00:00Z',
  country: 'US',
  group: 'LockBit',
  sector: 'Manufacturing',
  host: null,
  ...overrides,
});

const hoursAgo = (hours) => new Date(NOW - hours * HOUR).toISOString();

test('eventTime: parses the feed timestamps and rejects junk', () => {
  assert.equal(eventTime(event()), Date.parse('2026-10-28T06:00:00Z'));
  for (const ts of [null, undefined, '', 'not a date', 42]) {
    assert.equal(eventTime({ ts }), null);
  }
});

test('eventsInWindow: keeps events inside the window, inclusive at the head', () => {
  const events = [
    event({ id: 'now', ts: hoursAgo(0) }),
    event({ id: 'edge-start', ts: hoursAgo(72) }),
    event({ id: 'just-inside', ts: new Date(NOW - 72 * HOUR + 1000).toISOString() }),
    event({ id: 'outside', ts: hoursAgo(73) }),
    event({ id: 'future', ts: hoursAgo(-1) }),
  ];
  const kept = eventsInWindow(events, { end: NOW, hours: 72 }).map((item) => item.id);

  assert.deepEqual(kept.sort(), ['just-inside', 'now']);
});

test('eventsInWindow: a replay head changes which events are visible', () => {
  const events = [event({ id: 'a', ts: hoursAgo(10) }), event({ id: 'b', ts: hoursAgo(2) })];
  const replay = eventsInWindow(events, { end: NOW - 5 * HOUR, hours: 72 });
  assert.deepEqual(replay.map((item) => item.id), ['a']);
});

test('eventsInWindow: a head inside a fixed window reveals a prefix', () => {
  const events = [
    event({ id: 'old', ts: hoursAgo(30) }),
    event({ id: 'mid', ts: hoursAgo(10) }),
    event({ id: 'new', ts: hoursAgo(2) }),
  ];
  const replay = eventsInWindow(events, { end: NOW, head: NOW - 5 * HOUR, hours: 72 });
  assert.deepEqual(replay.map((item) => item.id), ['old', 'mid']);
});

test('aggregateEvents: the head filters the aggregate but hourlyBuckets keeps the window', () => {
  const events = [event({ id: 'a', ts: hoursAgo(10) }), event({ id: 'b', ts: hoursAgo(2) })];
  assert.equal(aggregateEvents(events, { end: NOW, head: NOW - 5 * HOUR }).total, 1);
  assert.equal(hourlyBuckets(events, { end: NOW }).reduce((sum, b) => sum + b.total, 0), 2);
});

test('eventsInWindow: tolerates a missing list', () => {
  assert.deepEqual(eventsInWindow(undefined, { end: NOW }), []);
  assert.deepEqual(eventsInWindow([null, event()], { end: NOW }).length, 1);
});

test('hourlyBuckets: one bucket per hour, oldest first', () => {
  const buckets = hourlyBuckets([], { end: NOW, hours: 72 });
  assert.equal(buckets.length, 72);
  assert.equal(buckets[71].start, NOW - HOUR);
  assert.equal(buckets[0].start, NOW - 72 * HOUR);
  assert.deepEqual(
    buckets.map((bucket) => bucket.total),
    Array.from({ length: 72 }, () => 0),
  );
});

test('hourlyBuckets: places events in the right hour and counts kinds apart', () => {
  const buckets = hourlyBuckets([
    event({ kind: 'claim', ts: hoursAgo(0) }),
    event({ kind: 'host', ts: hoursAgo(0) }),
    event({ kind: 'claim', ts: hoursAgo(1.5) }),
    event({ kind: 'claim', ts: hoursAgo(71.5) }),
    event({ kind: 'claim', ts: hoursAgo(80) }),
  ], { end: NOW, hours: 72 });

  assert.deepEqual(buckets[71], { start: NOW - HOUR, claims: 1, hosts: 1, total: 2 });
  assert.deepEqual(buckets[70], { start: NOW - 2 * HOUR, claims: 1, hosts: 0, total: 1 });
  assert.deepEqual(buckets[0], { start: NOW - 72 * HOUR, claims: 1, hosts: 0, total: 1 });
  assert.equal(buckets.reduce((sum, bucket) => sum + bucket.total, 0), 4);
});

test('aggregateEvents: reports claims and hosts per country, busiest first', () => {
  const aggregate = aggregateEvents([
    event({ id: 'a', country: 'US' }),
    event({ id: 'b', country: 'US', group: 'Qilin' }),
    event({ id: 'c', country: 'US' }),
    event({ id: 'd', country: 'DE' }),
    event({ id: 'e', country: 'DE', kind: 'host', group: null, host: 'x.example' }),
    event({ id: 'f', country: 'CA', kind: 'host', group: null, host: 'y.example' }),
  ], { end: NOW });

  assert.equal(aggregate.total, 6);
  assert.equal(aggregate.claims, 4);
  assert.equal(aggregate.hosts, 2);
  assert.equal(aggregate.max, 3);
  assert.deepEqual(
    aggregate.countries.map((entry) => [entry.code, entry.claims, entry.hosts, entry.total]),
    [['US', 3, 0, 3], ['DE', 1, 1, 2], ['CA', 0, 1, 1]],
  );
});

test('aggregateEvents: groups come from claims only, and the latest event is kept', () => {
  const aggregate = aggregateEvents([
    event({ id: 'a', country: 'US', group: 'LockBit', ts: hoursAgo(4) }),
    event({ id: 'b', country: 'US', group: 'LockBit', ts: hoursAgo(2) }),
    event({ id: 'c', country: 'US', group: 'Qilin', ts: hoursAgo(3) }),
    event({ id: 'd', country: 'US', kind: 'host', group: null, host: 'x.example', ts: hoursAgo(1) }),
  ], { end: NOW });

  const us = aggregate.countries[0];
  assert.equal(us.latest, hoursAgo(1));
  assert.deepEqual(us.groups, [{ name: 'LockBit', count: 2 }, { name: 'Qilin', count: 1 }]);
});

test('aggregateEvents: an event without a usable ISO code is counted, not guessed', () => {
  const aggregate = aggregateEvents([
    event({ id: 'a', country: 'usa' }),
    event({ id: 'b', country: null }),
    event({ id: 'c', country: 'US' }),
  ], { end: NOW });

  assert.equal(aggregate.total, 3);
  assert.equal(aggregate.unmapped, 2);
  assert.equal(aggregate.countries.length, 1);
});

test('aggregateEvents: degrades to an empty result', () => {
  const aggregate = aggregateEvents(undefined, { end: NOW });
  assert.deepEqual(aggregate, { total: 0, claims: 0, hosts: 0, unmapped: 0, max: 0, countries: [] });
});

test('cumulative: running totals, so replay only needs a bucket index', () => {
  assert.deepEqual(cumulative([{ total: 1 }, { total: 0 }, { total: 3 }]), [1, 1, 4]);
  assert.deepEqual(cumulative([]), []);
});

test('newEventIds: returns only ids not seen before, once each', () => {
  const events = [event({ id: 'a' }), event({ id: 'b' }), event({ id: 'b' })];
  assert.deepEqual(newEventIds(new Set(['a']), events), ['b']);
  assert.deepEqual(newEventIds([], events), ['a', 'b']);
  assert.deepEqual(newEventIds(new Set(['a', 'b']), events), []);
});

test('ingestState: a recent snapshot is live', () => {
  const state = ingestState({ updatedAt: hoursAgo(0.2), now: NOW });
  assert.equal(state.state, 'live');
  assert.equal(state.ageMinutes, 12);
});

test('ingestState: an hourly feed is not called stale at two hours', () => {
  assert.equal(ingestState({ updatedAt: hoursAgo(2), now: NOW }).state, 'delayed');
  assert.equal(ingestState({ updatedAt: hoursAgo(10), now: NOW }).state, 'stale');
  assert.equal(ingestState({ updatedAt: hoursAgo(30), now: NOW }).state, 'offline');
});

test('ingestState: the thresholds follow the feed cadence', () => {
  assert.equal(ingestState({ updatedAt: hoursAgo(5), now: NOW, cadenceMinutes: 360 }).state, 'live');
  assert.equal(ingestState({ updatedAt: hoursAgo(30), now: NOW, cadenceMinutes: 360 }).state, 'delayed');
});

test('ingestState: a missing or broken timestamp is offline, never live', () => {
  for (const updatedAt of [null, undefined, '', 'garbage']) {
    const state = ingestState({ updatedAt, now: NOW });
    assert.equal(state.state, 'offline', String(updatedAt));
    assert.equal(state.ageMinutes, null);
  }
});

test('pulseRadius: zero stays zero, the busiest country is the largest pulse', () => {
  assert.equal(pulseRadius(0, 10), 0);
  assert.equal(pulseRadius(10, 10), 9);
  assert.equal(pulseRadius(5, 10) > pulseRadius(1, 10), true);
  assert.equal(pulseRadius(3, 0), 0);
});

test('pulseCount: one pulse minimum, four at the busiest country', () => {
  assert.equal(pulseCount(0, 10), 0);
  assert.equal(pulseCount(1, 100), 1);
  assert.equal(pulseCount(100, 100), 4);
  assert.equal(pulseCount(30, 100) >= pulseCount(10, 100), true);
});

test('eventLabel: says what the event is, in the feed\'s own terms', () => {
  assert.equal(eventLabel(event()), 'LockBit claim · Manufacturing');
  assert.equal(eventLabel(event({ sector: null })), 'LockBit claim');
  assert.equal(eventLabel(event({ kind: 'host', group: null, host: 'x.example' })), 'Phishing host · x.example');
});

/**
 * Tests for assets/geo.js
 *
 *     node --test assets/geo.test.mjs
 *
 * The map makes a claim about where ransomware victims are, so the aggregation
 * has to be exact about two things: a claim without a country is never counted
 * as one, and the busiest country is found for the colour scale.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { aggregateClaims, levelFor, countryName, groupTotals } from "./geo.js";

const claim = (code, group, published) => ({
  country: code,
  group,
  published: published || "2026-10-27T00:00:00Z",
});

test("aggregateClaims: counts by country, busiest first", () => {
  const result = aggregateClaims([
    claim("US", "qilin"), claim("US", "qilin"), claim("US", "everest"),
    claim("DE", "qilin"),
    claim("GB", "everest"), claim("GB", "N0n"), claim("GB", "qilin"),
  ]);
  assert.equal(result.total, 7);
  assert.equal(result.mapped, 7);
  assert.equal(result.unmapped, 0);
  assert.equal(result.max, 3);
  assert.deepEqual(result.countries.map((country) => [country.code, country.count]),
    [["GB", 3], ["US", 3], ["DE", 1]]);
});

test("aggregateClaims: a claim without a usable country is unmapped, not guessed", () => {
  const result = aggregateClaims([
    claim(null, "qilin"),
    claim("", "qilin"),
    claim("USA", "qilin"),
    claim("us", "qilin"),
    claim(" us ", "qilin"),
  ]);
  assert.equal(result.total, 5);
  assert.equal(result.mapped, 2, "only two-letter codes count as mapped");
  assert.equal(result.unmapped, 3);
  assert.deepEqual(result.countries.map((country) => country.code), ["US"]);
});

test("aggregateClaims: groups are ordered by count then name", () => {
  const result = aggregateClaims([
    claim("US", "qilin"), claim("US", "qilin"), claim("US", "everest"), claim("US", "N0n"),
  ]);
  assert.deepEqual(result.countries[0].groups,
    [{ name: "qilin", count: 2 }, { name: "everest", count: 1 }, { name: "N0n", count: 1 }]);
});

test("aggregateClaims: a missing group is attributed rather than dropped", () => {
  const result = aggregateClaims([{ country: "US" }]);
  assert.deepEqual(result.countries[0].groups, [{ name: "Unattributed", count: 1 }]);
});

test("aggregateClaims: latest claim is the newest parseable timestamp", () => {
  const result = aggregateClaims([
    claim("US", "qilin", "2026-10-26T10:00:00Z"),
    claim("US", "qilin", "2026-10-28T02:10:42Z"),
    claim("US", "qilin", "not a date"),
    claim("US", "qilin", "2026-10-27T00:00:00Z"),
  ]);
  assert.equal(result.countries[0].latest, "2026-10-28T02:10:42Z");
});

test("aggregateClaims: an unparseable timestamp never wins", () => {
  const result = aggregateClaims([
    claim("DE", "qilin", "garbage"),
    claim("DE", "qilin", "2026-10-25T00:00:00Z"),
  ]);
  assert.equal(result.countries[0].latest, "2026-10-25T00:00:00Z");
});

test("aggregateClaims: empty and malformed input is empty, not an exception", () => {
  for (const input of [[], null, undefined, {}, "items"]) {
    const result = aggregateClaims(input);
    assert.deepEqual(result, { total: 0, mapped: 0, unmapped: 0, max: 0, countries: [] });
  }
});

test("levelFor: empty countries stay at zero and the busiest is heaviest", () => {
  assert.equal(levelFor(0, 38), 0);
  assert.equal(levelFor(1, 0), 0);
  assert.equal(levelFor(38, 38), 4);
  assert.equal(levelFor(8, 38), 3, "21% of the busiest country is band three");
  assert.equal(levelFor(4, 38), 2, "11% is band two");
  assert.equal(levelFor(1, 38), 1, "a single claim is still visible");
});

test("levelFor: never decreases as counts rise", () => {
  let previous = 0;
  for (let count = 0; count <= 40; count += 1) {
    const level = levelFor(count, 40);
    assert.ok(level >= previous, `level dropped at ${count}`);
    assert.ok(level >= 0 && level <= 4);
    previous = level;
  }
});

test("countryName: resolves ISO codes and falls back to the code", () => {
  assert.equal(countryName("US"), "United States");
  assert.equal(countryName("de"), "Germany");
  assert.equal(countryName(""), "Unknown");
  assert.equal(countryName("USA"), "USA", "three letters is not an ISO2 code");
});

test("groupTotals: sums each group across countries", () => {
  const { countries } = aggregateClaims([
    claim("US", "qilin"), claim("US", "everest"), claim("DE", "qilin"), claim("DE", "N0n"),
  ]);
  assert.deepEqual(groupTotals(countries), [
    { name: "qilin", count: 2 },
    { name: "everest", count: 1 },
    { name: "N0n", count: 1 },
  ]);
  assert.deepEqual(groupTotals(null), []);
});

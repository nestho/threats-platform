import { test } from 'node:test';
import assert from 'node:assert/strict';
import { countryRanking, countryFromQuery } from './world-map-view.js';

const country = (code, count) => ({ code, count, latest: null, groups: [] });

test('countryRanking: keeps the order and adds bars relative to the busiest country', () => {
  const aggregate = {
    max: 20,
    countries: [country('US', 20), country('DE', 10), country('IN', 5)],
  };
  const ranked = countryRanking(aggregate);
  assert.deepEqual(ranked.map((entry) => entry.code), ['US', 'DE', 'IN']);
  assert.deepEqual(ranked.map((entry) => entry.bar), [100, 50, 25]);
});

test('countryRanking: defaults to five entries and honours a limit', () => {
  const countries = Array.from({ length: 9 }, (_, i) => country(`C${i}`, 9 - i));
  const aggregate = { max: 9, countries };
  assert.equal(countryRanking(aggregate).length, 5);
  assert.equal(countryRanking(aggregate, 2).length, 2);
  assert.equal(countryRanking(aggregate, 0).length, 0);
});

test('countryRanking: does not mutate the aggregate', () => {
  const aggregate = { max: 4, countries: [country('US', 4)] };
  countryRanking(aggregate);
  assert.deepEqual(aggregate.countries[0], country('US', 4));
});

test('countryRanking: rounds bars to one decimal and never exceeds 100', () => {
  const aggregate = { max: 3, countries: [country('US', 2), country('GB', 3)] };
  const ranked = countryRanking(aggregate);
  assert.equal(ranked[0].bar, 66.7);
  assert.equal(ranked[1].bar, 100);
});

test('countryRanking: degrades to an empty list instead of guessing', () => {
  assert.deepEqual(countryRanking(undefined), []);
  assert.deepEqual(countryRanking({}), []);
  assert.deepEqual(countryRanking({ max: 0, countries: [country('US', 0)] })[0].bar, 0);
});

test('countryFromQuery: accepts a two-letter code in any case', () => {
  assert.equal(countryFromQuery('?country=us'), 'US');
  assert.equal(countryFromQuery('country=de'), 'DE');
});

test('countryFromQuery: rejects anything that is not an ISO alpha-2 code', () => {
  assert.equal(countryFromQuery(''), null);
  assert.equal(countryFromQuery('?country='), null);
  assert.equal(countryFromQuery('?country=USA'), null);
  assert.equal(countryFromQuery('?country=u1'), null);
  assert.equal(countryFromQuery('?country=%20us%20'), 'US');
  assert.equal(countryFromQuery('?group=qilin'), null);
  assert.equal(countryFromQuery('?country=constructor'), null);
});

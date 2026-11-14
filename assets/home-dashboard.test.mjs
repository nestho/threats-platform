import assert from "node:assert/strict";
import test from "node:test";

import { filterActivityEvents } from "./home-dashboard.js";

const events = [
  { category: "vulnerabilities", id: "CVE-1" },
  { category: "phishing", id: "host.example" },
  { category: "vulnerabilities", id: "CVE-2" },
];

test("filterActivityEvents returns the full ordered feed for all", () => {
  assert.deepEqual(filterActivityEvents(events), events);
  assert.deepEqual(filterActivityEvents(events, "all"), events);
});

test("filterActivityEvents returns only events in the selected category", () => {
  assert.deepEqual(
    filterActivityEvents(events, "vulnerabilities"),
    [events[0], events[2]],
  );
  assert.deepEqual(filterActivityEvents(events, "ransomware"), []);
});

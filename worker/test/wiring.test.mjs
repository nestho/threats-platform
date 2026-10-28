/**
 * The default export wires D1 through `createRepo` before passing it to the
 * router. A promise here is not a repository: every handler would fail with
 * "getSettings is not a function" on the first request. The in-memory tests
 * cannot catch that because they inject the fake directly, so this guards the
 * construction boundary.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { createRepo } from "../src/repo.mjs";

test("createRepo returns the adapter synchronously", () => {
  const repo = createRepo({ prepare() { throw new Error("SQL must not run at construction"); } });
  assert.equal(typeof repo.getSettings, "function");
  assert.equal(typeof repo.insertOrder, "function");
  assert.equal(typeof repo.hitRate, "function");
  assert.equal(repo instanceof Promise, false);
});

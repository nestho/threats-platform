/**
 * Tests for the external cron that replaces GitHub's best-effort scheduler.
 *
 *     node --test scheduler
 */
import assert from "node:assert/strict";
import test from "node:test";

import { dispatchUpdate } from "./src/index.mjs";

const REPO = "nestho/threats-platform";
const EXPECTED_URL = `https://api.github.com/repos/${REPO}/actions/workflows/update-data.yml/dispatches`;

function recordingFetch(responses) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const next = responses.length > 1 ? responses.shift() : responses[0];
    return new Response(next.body ?? null, { status: next.status });
  };
  return { calls, fetchImpl };
}

test("dispatches the collector workflow on main with cadence-driven sources", async () => {
  const { calls, fetchImpl } = recordingFetch([{ status: 204 }]);

  const result = await dispatchUpdate({ token: "t0ken", repo: REPO, fetchImpl });

  assert.equal(result.attempts, 1);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, EXPECTED_URL);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.Authorization, "Bearer t0ken");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    ref: "main",
    inputs: { feeds: "auto" },
  });
});

test("retries a server error and succeeds", async () => {
  const { calls, fetchImpl } = recordingFetch([{ status: 502 }, { status: 204 }]);

  const result = await dispatchUpdate({ token: "t0ken", repo: REPO, fetchImpl });

  assert.equal(result.attempts, 2);
  assert.equal(calls.length, 2);
});

test("does not retry a rejected token and reports why", async () => {
  const { calls, fetchImpl } = recordingFetch([
    { status: 401, body: '{"message":"Bad credentials"}' },
  ]);

  await assert.rejects(
    dispatchUpdate({ token: "expired", repo: REPO, fetchImpl }),
    /401.*Bad credentials/s,
  );
  assert.equal(calls.length, 1);
});

test("refuses to run without a token instead of failing silently", async () => {
  const { calls, fetchImpl } = recordingFetch([{ status: 204 }]);

  await assert.rejects(dispatchUpdate({ token: "", repo: REPO, fetchImpl }), /GH_TOKEN/);
  assert.equal(calls.length, 0);
});

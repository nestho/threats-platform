/**
 * Tests for assets/app.js
 *
 *     node --test assets/app.test.mjs
 *
 * esc() is the only thing standing between third-party text and innerHTML on
 * this site, and it had three divergent copies with no tests. These assert the
 * property that actually matters -- that no input can break out of either a text
 * node or a quoted attribute -- rather than testing the implementation.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { esc, timeAgo, timeKey } from "./app.js";

/*
 * These assert on the string esc() returns, not on a parsed DOM.
 *
 * An earlier draft used a fake document.createElement to check that hostile
 * input produced no child elements, which needs a real HTML parser -- jsdom, and
 * a node_modules directory in a project whose defining constraint is zero
 * dependencies. Asserting on the string is not a compromise here: esc() returns
 * a string, and the security property is a property of that string. If it
 * contains no raw < > " ', then no HTML parser -- however forgiving or buggy --
 * can be tricked into producing an element or breaking out of an attribute.
 *
 * The one thing a string check cannot prove is that a future renderer stops
 * passing unescaped data to innerHTML. That is a lint rule, not a unit test.
 */

/** The characters that must never survive esc() as themselves. */
const RAW_METACHARACTERS = /[<>"']/;

function assertNoRawMetacharacters(value) {
  const out = esc(value);
  assert.ok(
    !RAW_METACHARACTERS.test(out),
    `esc() leaked a raw metacharacter for ${JSON.stringify(value)} -> ${JSON.stringify(out)}`,
  );
  return out;
}

test("esc: round-trips ordinary text unchanged", () => {
  for (const value of ["hello", "CVE-2026-1234", "a b & c", "100%", ""]) {
    assert.equal(esc(value), value.replace(/&/g, "&amp;"), `failed for ${JSON.stringify(value)}`);
  }
});

test("esc: neutralises every character that can start a tag", () => {
  const out = esc('<script>alert(1)</script>');
  assert.ok(!out.includes("<"), "must not emit a raw <");
  assert.ok(out.includes("&lt;script&gt;"));
});

test("esc: neutralises an attribute breakout", () => {
  // The bug this exists to prevent: the old esc() escaped < > & but not quotes,
  // so it was unsafe in `attr="${value}"` and programs.html had to hand-roll a
  // second, weaker escape as a workaround.
  const payload = '" onmouseover="alert(1)" x="';
  const out = assertNoRawMetacharacters(payload);
  assert.ok(out.includes("&quot;"), "double quote must become an entity");
});

test("esc: neutralises a single-quote breakout", () => {
  const payload = "' onfocus='alert(1)";
  const out = assertNoRawMetacharacters(payload);
  assert.ok(out.includes("&#39;"), "single quote must become an entity");
});

test("esc: neutralises every known injection payload", () => {
  for (const payload of [
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=//evil.tld>",
    "&lt;script&gt;",
    "<scr<script>ipt>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)//",
    "<style>@import 'evil'</style>",
  ]) {
    assertNoRawMetacharacters(payload);
  }
});

test("esc: ampersands are always emitted as entities, never bare", () => {
  // A bare & followed by something entity-shaped would be re-decoded by the
  // parser, so every & esc() emits must be one it emitted itself.
  const out = esc('&lt;script&gt; & "x" <b>');
  assert.equal(out, "&amp;lt;script&amp;gt; &amp; &quot;x&quot; &lt;b&gt;");
  // Every & is followed by a known entity name and a semicolon.
  for (const match of out.matchAll(/&([^;]*);?/g)) {
    assert.ok(
      ["amp", "lt", "gt", "quot", "#39"].includes(match[1]),
      `unexpected entity ${JSON.stringify(match[0])}`,
    );
  }
});

test("esc: is injective, so two different values never render identically", () => {
  // An earlier draft asserted idempotency (esc(esc(x)) === esc(x)). That is
  // false and asserting it would have been asserting a bug: escaping "&lt;b&gt;"
  // again gives "&amp;lt;b&amp;gt;", because the & is itself escaped. A page
  // that double-escapes shows the user literal entities -- a cosmetic defect,
  // not a security one.
  //
  // The property that actually matters is injectivity: a malicious value and an
  // innocent one must never collapse to the same output, or escaping would lose
  // data and two different feed records could render indistinguishably.
  const samples = [
    "a", "b", "<b>", "&lt;b&gt;", "a&b", "a&amp;b", '"q"', "&quot;q&quot;",
    "<script>", "&lt;script&gt;", "CVE-2026-1", "CVE-2026-2", "", "&", "&amp;",
  ];
  const seen = new Map();
  for (const value of samples) {
    const out = esc(value);
    assert.ok(!seen.has(out), `collision: ${JSON.stringify(value)} and ${JSON.stringify(seen.get(out))} both -> ${JSON.stringify(out)}`);
    seen.set(out, value);
  }
  assert.equal(seen.size, samples.length);
});

test("esc: handles null and undefined without throwing", () => {
  assert.equal(esc(null), "");
  assert.equal(esc(undefined), "");
  assert.equal(esc(0), "0", "0 must not become empty");
  assert.equal(esc(false), "false");
});

test("esc: non-strings are coerced rather than producing [object Object] silently lost", () => {
  assert.equal(esc(42), "42");
  assert.equal(esc(["a", "b"]), "a,b");
});

test("timeAgo: renders recent times and degrades safely", () => {
  const now = Date.now();
  assert.equal(timeAgo(new Date(now - 5_000).toISOString()), "just now");
  assert.equal(timeAgo(new Date(now - 5 * 60_000).toISOString()), "5m ago");
  assert.equal(timeAgo(new Date(now - 3 * 3_600_000).toISOString()), "3h ago");
  assert.equal(timeAgo(new Date(now - 2 * 86_400_000).toISOString()), "2d ago");
});

test("timeAgo: returns an em dash for absent or unparseable input", () => {
  // This is the CERT-EU CEST bug: an RFC-2822 string with a European zone
  // abbreviation parses as Invalid Date in a JS engine, and used to leak through
  // as a broken timestamp instead of degrading.
  assert.equal(timeAgo(null), "—");
  assert.equal(timeAgo(""), "—");
  assert.equal(timeAgo("Tue, 22 Sep 2026 18:52:36 CEST"), "—");
  assert.equal(timeAgo("not a date"), "—");
});

test("timeKey: sorts unparseable timestamps last instead of corrupting order", () => {
  // A NaN comparator makes Array.sort's output engine-defined. timeKey must
  // never return NaN.
  const good1 = "2026-09-24T16:17:22Z";
  const good2 = "2026-09-20T00:00:00Z";
  const bad = "Tue, 22 Sep 2026 18:52:36 CEST";
  const events = [{ t: bad }, { t: good1 }, { t: null }, { t: good2 }];
  events.sort((a, b) => timeKey(b.t) - timeKey(a.t));
  assert.deepEqual(events.map((e) => e.t), [good1, good2, bad, null]);
  for (const value of [null, undefined, "", bad, "nonsense"]) {
    assert.ok(!Number.isNaN(timeKey(value)), `timeKey(${JSON.stringify(value)}) must not be NaN`);
  }
});

/*
 * Guard: no literal control bytes in source.
 *
 * Added after worker/admin.js shipped with a control-character regex written as
 * /[<NUL>-<US><DEL>]/ -- real 0x00/0x1f/0x7f bytes in the file rather than
 * escape sequences. It behaved correctly, but it made git classify the file as
 * binary, so diffs and code review were useless, and the bytes are invisible in
 * every editor.
 *
 * The companion bug was worse: a test payload whose NUL was also literal, so the
 * test passed for a reason its name did not describe ("Acme Admin" with a space
 * in the name and a NUL in the string).
 *
 * A repo-wide lint does not belong in a test file on principle, but it runs in
 * the same `node --test assets worker` invocation as everything else, so the
 * check is actually executed rather than merely written down.
 */
test("repo: no source file contains a literal control byte", async () => {
  const { readdir, readFile } = await import("node:fs/promises");
  const { join, extname } = await import("node:path");

  const ROOT = new URL("../", import.meta.url).pathname;
  const TEXT_EXT = new Set([".js", ".mjs", ".css", ".py", ".html", ".yml", ".toml", ".md", ".json"]);
  const SKIP = new Set([".git", "node_modules", "__pycache__", "data"]);

  const offenders = [];
  async function walk(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (SKIP.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) { await walk(full); continue; }
      if (!TEXT_EXT.has(extname(entry.name))) continue;
      const raw = await readFile(full);
      for (let i = 0; i < raw.length; i += 1) {
        const b = raw[i];
        // Tab (9), LF (10) and CR (13) are legitimate whitespace. Everything else
        // below 32, plus DEL, is a byte someone meant to write as an escape.
        const illegal = b < 9 || (b > 10 && b < 13) || (b > 13 && b < 32) || b === 127;
        if (illegal) {
          const line = raw.subarray(0, i).toString("utf8").split("\n").length;
          offenders.push(`${full.replace(ROOT, "")}:${line} byte 0x${b.toString(16).padStart(2, "0")}`);
          break;
        }
      }
    }
  }
  await walk(ROOT);
  assert.deepEqual(offenders, [], `literal control bytes found:\n${offenders.join("\n")}`);
});

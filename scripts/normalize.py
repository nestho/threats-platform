#!/usr/bin/env python3
"""
Shared normalisation rules for every collector in this repo.

This module exists because the six collectors each grew their own idea of what a
timestamp looks like, and there were four incompatible formats in the published
data. Two of them were actively broken in the browser:

  CERT-EU    "Tue, 22 Sep 2026 18:52:36 CEST"   -> JS Date parses this as Invalid
  Exploit-DB "Fri, 11 Sep 2026 00:00:00 +0000"   -> works, but inconsistent

ECMA-262 only guarantees that a Date constructor understands GMT/UTC plus seven
US zone abbreviations. "CEST" is not one of them, so every CERT-EU item rendered
as an em-dash and poisoned the comparator in the homepage's recent-activity sort
with NaN. Normalising at the collector boundary removes the whole bug class
rather than patching one instance.

WHY NOT JUST parsedate_to_datetime?
-----------------------------------
`email.utils.parsedate_to_datetime` recognises GMT and numeric offsets, but for
an unrecognised zone abbreviation it *silently returns a naive datetime* --
the offset is dropped, not rejected:

    >>> parsedate_to_datetime("Tue, 22 Sep 2026 18:52:36 CEST")
    datetime.datetime(2026, 9, 22, 18, 52, 36)          # no tzinfo!

Emitting that with .isoformat() gives "2026-09-22T18:52:36", which is an
ISO-8601 *local time* form. JavaScript would read it as local time and silently
render it wrong by 1-2 hours for most of the world -- strictly worse than the
loud NaN we have today. So an unrecognised zone is treated as a hard error here
and surfaced by validate_feeds.py, rather than guessed at.
"""
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

__all__ = [
    "UTC",
    "parse_datetime",
    "to_iso_utc",
    "to_iso_date",
    "NormalisationTally",
    "NormalisationTooManyFailures",
    "UnknownTimezone",
    "UnparseableTimestamp",
]

UTC = timezone.utc

# Zone abbreviation -> fixed UTC offset in hours.
#
# The abbreviation always states the offset in effect, so no DST arithmetic is
# needed: if a source says CEST, the offset is +2, full stop. An earlier draft of
# this file modelled CET/CEST as separate zones and then added an hour of summer
# time on top, which turned 18:52:36 CEST into 15:52:36Z -- three hours out.
# Inferring the offset from a DST window is only necessary when a source sends a
# bare local time with no zone at all, and none of ours do.
#
# CET and CEST are the same zone at different times of year, so both appear with
# the offset each name denotes.
_ZONE_OFFSETS = {
    # Names ECMA-262 guarantees a JS Date constructor understands.
    "GMT": 0, "UT": 0, "UTC": 0, "Z": 0,
    "EST": -5, "EDT": -4,
    "CST": -6, "CDT": -5,
    "MST": -7, "MDT": -6,
    "PST": -8, "PDT": -7,
    # European zones. CERT-EU publishes CEST; the rest are here so that a future
    # upstream in this family is validated rather than silently mis-parsed.
    "WET": 0, "WEST": 1,
    "CET": 1, "CEST": 2,
    "EET": 2, "EEST": 3,
    "BST": 1, "IST": 5, "JST": 9,
}


class UnparseableTimestamp(ValueError):
    """The value is not a timestamp format we recognise."""


class UnknownTimezone(ValueError):
    """The timestamp parsed, but carried a zone abbreviation we refuse to guess at."""


def _resolve_zone(abbr: str, naive: datetime) -> timezone:
    """
    Attach a real offset to a naive datetime using an explicit zone table.

    Raises UnknownTimezone rather than assuming UTC, because assuming UTC is how
    a visible bug becomes an invisible one.
    """
    abbr = abbr.upper()
    if abbr in _ZONE_OFFSETS:
        return timezone(timedelta(hours=_ZONE_OFFSETS[abbr]))
    raise UnknownTimezone(
        f"timezone abbreviation {abbr!r} is not in the accepted table "
        f"({', '.join(sorted(_ZONE_OFFSETS))}) -- refusing to guess"
    )


_TZ_ABBR = re.compile(r"\s([A-Z]{2,5})$")


def parse_datetime(value: str, *, assume_tz: str = "UTC", field: str = "timestamp") -> datetime:
    """
    Parse any timestamp shape an upstream might emit into a tz-aware UTC datetime.

    Handles, in order of preference:
      * ISO-8601 with an explicit offset or Z          -> used as-is
      * ISO-8601 naive ("2026-09-24T16:17:22.157")     -> `assume_tz` applied
      * "YYYY-MM-DD HH:MM:SS" naive                    -> `assume_tz` applied
      * RFC-2822 with numeric offset ("+0000")         -> used as-is
      * RFC-2822 with a known zone abbreviation        -> resolved via the table
      * RFC-2822 with an unknown zone abbreviation     -> UnknownTimezone

    `assume_tz` is the zone to attribute to a *naive* value. NVD and abuse.ch both
    publish UTC without saying so, so their collectors pass the default; nothing
    passes a non-UTC value, because no upstream here does.
    """
    if not isinstance(value, str) or not value.strip():
        raise UnparseableTimestamp(f"{field}: expected a non-empty string, got {value!r}")

    raw = value.strip()
    assume = _ZONE_OFFSETS[assume_tz.upper()] if assume_tz.upper() in _ZONE_OFFSETS else 0
    assume_tzinfo = timezone(timedelta(hours=assume))

    # 1. ISO-8601, which is what we want every upstream to end up producing.
    iso_candidate = raw.replace(" ", "T", 1) if " " in raw and "T" not in raw else raw
    try:
        dt = datetime.fromisoformat(iso_candidate.replace("Z", "+00:00"))
        return dt.replace(tzinfo=assume_tzinfo) if dt.tzinfo is None else dt.astimezone(UTC)
    except ValueError:
        pass

    # 1b. ISO-8601 carrying a named zone ("2026-01-15T10:00:00 CET").
    # fromisoformat rejects named zones, so peel the abbreviation off and resolve
    # it through the table. No current feed sends this, but handling it here is
    # cheaper than discovering later that the module only worked by luck.
    named = re.match(r"^(.*\d)\s+([A-Za-z]{2,5})$", iso_candidate)
    if named:
        try:
            dt = datetime.fromisoformat(named.group(1))
        except ValueError:
            pass
        else:
            return dt.replace(tzinfo=_resolve_zone(named.group(2), dt)).astimezone(UTC)

    # 2. RFC-2822. parsedate_to_datetime handles numeric offsets itself and
    #    returns naive only when it met a zone name it does not know.
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError) as exc:
        raise UnparseableTimestamp(f"{field}: cannot parse {raw!r} ({exc})") from exc

    if dt.tzinfo is not None:
        return dt.astimezone(UTC)

    match = _TZ_ABBR.search(raw)
    if not match:
        # No zone at all and not parseable as ISO -- treat as the assumed zone.
        return dt.replace(tzinfo=assume_tzinfo).astimezone(UTC)

    return dt.replace(tzinfo=_resolve_zone(match.group(1), dt)).astimezone(UTC)


def to_iso_utc(value: str, *, assume_tz: str = "UTC", field: str = "timestamp") -> str:
    """
    Normalise any accepted timestamp shape to ISO-8601 UTC with an explicit Z.

    The trailing Z is not cosmetic: an ISO string *without* an offset is defined
    as local time, so omitting it is what made the original CERT-EU data
    dangerous to consume.
    """
    return parse_datetime(value, assume_tz=assume_tz, field=field).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_iso_date(value: str, *, field: str = "date") -> str:
    """
    Normalise to a bare YYYY-MM-DD, preserving date-only precision.

    CISA KEV publishes date-only and there is no time to recover. A bare
    YYYY-MM-DD *is* unambiguous to a JS Date constructor (UTC midnight), so this
    stays parseable and does not need to be widened to a fake midnight.
    """
    if not isinstance(value, str) or not value.strip():
        raise UnparseableTimestamp(f"{field}: expected a non-empty string, got {value!r}")
    raw = value.strip()
    try:
        return datetime.strptime(raw[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError as exc:
        raise UnparseableTimestamp(f"{field}: cannot parse date {raw!r} ({exc})") from exc


class NormalisationTally:
    """
    Collects per-item normalisation failures instead of letting one bad row
    destroy an entire feed.

    The tension: a timestamp we cannot parse should never be guessed at, but
    neither should a single malformed advisory date cost us the other 99 good
    ones. Raising on the first failure makes an upstream format change look
    identical to one weird row, and either way the operator learns nothing.

    So: tolerate a small number of bad rows, publish the rest, and fail loudly
    once the failure count indicates something systematic. That distinguishes
    "one odd CVE" from "upstream changed the format", which is the distinction
    that actually matters at 3am.

    Failures are also recorded in the feed output so validate_feeds.py can see
    them -- tolerating them silently is how a systematic break sneaks through.
    """

    def __init__(self, source, *, tolerance=0.05, absolute_floor=3):
        self.source = source
        self.tolerance = tolerance
        self.absolute_floor = absolute_floor
        self.failures = []
        self.seen = 0

    def _record(self, exc, field, value):
        self.failures.append({"field": field, "value": str(value)[:80], "error": str(exc)[:160]})

    def iso(self, value, *, field="timestamp", assume_tz="UTC"):
        """Normalise to ISO-8601 UTC, or return None and tally the failure."""
        self.seen += 1
        try:
            return to_iso_utc(value, assume_tz=assume_tz, field=field)
        except (UnparseableTimestamp, UnknownTimezone) as exc:
            self._record(exc, field, value)
            return None

    def date(self, value, *, field="date"):
        """Normalise to YYYY-MM-DD, or return None and tally the failure."""
        self.seen += 1
        try:
            return to_iso_date(value, field=field)
        except UnparseableTimestamp as exc:
            self._record(exc, field, value)
            return None

    @property
    def failed(self):
        return len(self.failures)

    def exceeded(self):
        """True when the failure count looks systematic rather than incidental."""
        if not self.failures:
            return False
        allowed = max(self.absolute_floor, int(self.seen * self.tolerance))
        return self.failed > allowed

    def raise_if_exceeded(self):
        if not self.exceeded():
            return
        allowed = max(self.absolute_floor, int(self.seen * self.tolerance))
        sample = "; ".join(f"{f['field']}={f['value']!r}" for f in self.failures[:3])
        raise NormalisationTooManyFailures(
            f"{self.source}: {self.failed} of {self.seen} timestamps could not be "
            f"normalised (tolerance {allowed}). Upstream format probably changed. "
            f"First failures: {sample}"
        )


class NormalisationTooManyFailures(RuntimeError):
    """Too many records failed normalisation to publish the feed."""


if __name__ == "__main__":
    # Cheap self-check so the module is verifiable without a test runner.
    cases = [
        ("Tue, 22 Sep 2026 18:52:36 CEST", "2026-09-22T16:52:36Z"),
        ("Fri, 11 Sep 2026 00:00:00 +0000", "2026-09-11T00:00:00Z"),
        ("Mon, 01 Sep 2026 09:00:00 GMT", "2026-09-01T09:00:00Z"),
        ("2026-09-24T16:17:22.157", "2026-09-24T16:17:22Z"),
        ("2026-09-26T15:31:27Z", "2026-09-26T15:31:27Z"),
        ("2026-09-27 02:20:17", "2026-09-27T02:20:17Z"),
    ]
    failures = 0
    for raw, expected in cases:
        got = to_iso_utc(raw)
        ok = got == expected
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {raw!r:42s} -> {got}")
    for raw in ("Wed, 04 Feb 2026 10:00:00 XYZ",):
        try:
            to_iso_utc(raw)
            print(f"  FAIL {raw!r} should have raised UnknownTimezone")
            failures += 1
        except UnknownTimezone:
            print(f"  ok   {raw!r:42s} -> refused (unknown zone)")
    raise SystemExit(1 if failures else 0)

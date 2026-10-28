/*
 * Shared helpers for threats.top
 *
 * Every page had its own copy of esc(), showToast(), copyText() and timeAgo().
 * Three copies of an escaping function is three chances to ship an XSS, and the
 * copies had already drifted -- programs.html hand-rolled a second, weaker
 * escape for an attribute (see DOM attribute helpers below).
 */

/**
 * Escape a string for interpolation into HTML.
 *
 * Handles BOTH text and quoted-attribute context. The previous version used
 * `div.textContent = s; return div.innerHTML`, which escapes < > & but NOT quotes
 * -- correct in a text node, wrong inside `attr="${value}"`. That is why
 * programs.html had a separate `"`-only escape: the shared one could not be used
 * in an attribute. One correct escaper, used everywhere, removes the temptation.
 *
 * @param {unknown} value
 * @returns {string} safe to interpolate into HTML text or a quoted attribute
 */
export function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Compact relative time. Returns an em dash for absent or unparseable input. */
export function timeAgo(value) {
  if (!value) return '—';
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return '—';
  const seconds = (Date.now() - t) / 1000;
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Sort key for a mixed-format timestamp.
 *
 * The previous sort was `new Date(b.time || 0) - new Date(a.time || 0)`. When
 * any timestamp was unparseable that comparator returned NaN, and Array.sort with
 * a NaN comparator leaves ordering engine-defined rather than chronological.
 * The collectors now emit ISO-8601 UTC everywhere, but a null or malformed value
 * must not be able to corrupt ordering, so unparseable values sort last.
 */
export function timeKey(value) {
  if (!value) return -Infinity;
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? -Infinity : t;
}

let toastTimer;

/** Show a transient message in the page's toast, announced to screen readers. */
export function showToast(message) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 1600);
}

/** Copy text, reporting the outcome in the toast rather than failing silently. */
export async function copyText(text, okMessage = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(okMessage);
    return true;
  } catch {
    showToast('Copy failed');
    return false;
  }
}

/**
 * Copy an absolute URL for a data endpoint.
 *
 * Uses location.origin so the same code works on a custom domain, on a preview
 * deployment, and on localhost, without hardcoding threats.top.
 */
export function copyEndpointUrl(path, okMessage = 'Copied endpoint') {
  return copyText(location.origin + path, okMessage);
}

/**
 * Fetch JSON, returning null on any failure rather than throwing.
 *
 * Every page used Promise.allSettled and then re-checked .status, which is fine
 * but easy to get subtly wrong. This keeps the call sites to one line while
 * preserving the "one dead feed must not blank the page" behaviour.
 */
export async function fetchJson(path) {
  try {
    const response = await fetch(path);
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Fetch several JSON files at once, keyed by name.
 *
 * Never rejects and never throws: a feed that fails to load comes back as null so
 * the page can degrade to "unavailable" for that section only.
 */
export async function fetchAll(map) {
  const names = Object.keys(map);
  const values = await Promise.all(names.map((name) => fetchJson(map[name])));
  return Object.fromEntries(names.map((name, i) => [name, values[i]]));
}

/**
 * Recompute source freshness against the reader's clock.
 *
 * status.json records `stale` when it is generated, but the file is only
 * rewritten when a collector publishes. A missed schedule slot leaves the file
 * claiming "current" while its timestamps age, and the UI would trust a verdict
 * that quietly stopped being true. Cadence and last_success are enough to
 * re-derive it, using the same rules as scripts/status.py: stale past twice the
 * cadence, outage when a critical source is stale, degraded on any error.
 *
 * @param {{sources?: object[], overall?: string}} status
 * @param {number} now  epoch milliseconds, injectable for tests
 */
export function recomputeHealth(status, now = Date.now()) {
  const sources = (status.sources || []).map((source) => {
    const cadence = Number(source.cadence_minutes) || 1440;
    const last = source.last_success ? new Date(source.last_success).getTime() : NaN;
    const ageMinutes = Number.isNaN(last)
      ? Infinity
      : Math.floor(Math.max(0, now - last) / 60000);
    return {
      ...source,
      age_minutes: Number.isFinite(ageMinutes) ? ageMinutes : null,
      stale: Boolean(source.stale) || ageMinutes > cadence * 2,
    };
  });
  const critical = sources.some((source) => source.critical && source.stale);
  const degraded = sources.some((source) => source.stale || source.error);
  return { ...status, sources, overall: critical ? 'outage' : degraded ? 'degraded' : 'ok' };
}

/**
 * Reveal a warning note when any of the given sources is stale or failing.
 *
 * Pages otherwise show only their own feed's `updated_at`, which cannot tell a
 * reader whether that timestamp is on schedule. status.json records cadence and
 * last_success, so consult it rather than duplicating cadence rules per page.
 *
 * @param {string} elementId  id of a hidden .note element
 * @param {string[]} sourceIds  status.json source ids used by this page
 */
export async function showStaleNote(elementId, sourceIds) {
  const element = document.getElementById(elementId);
  if (!element) return;
  const file = await fetchJson('/data/status.json');
  if (!file) return;
  const status = recomputeHealth(file);
  const affected = status.sources.filter(
    (source) => sourceIds.includes(source.id) && (source.stale || source.error),
  );
  if (!affected.length) return;
  element.hidden = false;
  element.className = 'note warn';
  element.innerHTML =
    'Stale or failing source' + (affected.length === 1 ? '' : 's') + ': '
    + affected.map((source) => esc(source.label)).join(', ')
    + '. The data below may be older than its cadence. '
    + '<a href="/status.html">See source status →</a>';
}

/**
 * Wire up a tab group with correct ARIA and keyboard behaviour.
 *
 * The previous markup was a row of <button>s with an .active class: no
 * role="tablist", no aria-selected, and arrow keys did nothing. This makes them
 * behave like the tabs they look like.
 *
 * @param {string} selector  container holding the tab buttons
 * @param {(id: string) => void} onChange
 */
export function initTabs(selector, onChange) {
  const root = document.querySelector(selector);
  if (!root) return;
  const tabs = [...root.querySelectorAll('[role="tab"]')];

  const select = (tab, focus = false) => {
    for (const other of tabs) {
      other.setAttribute('aria-selected', String(other === tab));
      other.tabIndex = other === tab ? 0 : -1;
    }
    onChange(tab.dataset.view);
    if (focus) tab.focus();
  };

  for (const tab of tabs) {
    tab.tabIndex = tab.getAttribute('aria-selected') === 'true' ? 0 : -1;
    tab.addEventListener('click', () => select(tab));
    tab.addEventListener('keydown', (event) => {
      const index = tabs.indexOf(tab);
      let next = null;
      if (event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
      else if (event.key === 'ArrowLeft') next = tabs[(index - 1 + tabs.length) % tabs.length];
      else if (event.key === 'Home') next = tabs[0];
      else if (event.key === 'End') next = tabs[tabs.length - 1];
      if (next) {
        event.preventDefault();
        select(next, true);
      }
    });
  }
}

/**
 * Update a result-count element and announce it.
 *
 * A count that changes silently on every keystroke is invisible to a screen
 * reader user; without this the search box appears to do nothing.
 */
export function setResultCount(element, count, noun = 'result') {
  if (!element) return;
  const text = `${count} ${noun}${count === 1 ? '' : 's'}`;
  element.textContent = text;
}

/**
 * Bring the console shell to life: current-page marking, UTC clock, and the
 * live source-health chip in the rail and top bar.
 *
 * Every page ships the shell as static HTML so it works without JavaScript;
 * this only upgrades it. Health is read from status.json, the same file the
 * status page uses, so the chip cannot drift from the source of truth.
 */
export function initConsoleShell() {
  const current = document.querySelector('.rail-nav a[aria-current="page"]');
  if (!current) {
    const here = location.pathname.replace(/index\.html$/, '/');
    for (const link of document.querySelectorAll('.rail-nav a')) {
      if (new URL(link.getAttribute('href'), location.origin).pathname === here) {
        link.setAttribute('aria-current', 'page');
        break;
      }
    }
  }

  const clock = document.getElementById('shell-clock');
  const stamp = () => {
    const now = new Date();
    if (clock) {
      clock.textContent = now.toISOString().slice(11, 16) + 'Z';
      clock.dateTime = now.toISOString();
    }
    for (const element of document.querySelectorAll('[data-shell-date]')) {
      element.textContent = now
        .toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' })
        .toUpperCase();
    }
  };
  stamp();
  setInterval(stamp, 30000);

  const dot = document.getElementById('rail-dot');
  const label = document.getElementById('rail-health-text');
  const meta = document.getElementById('rail-health-meta');
  const chip = document.getElementById('live-chip');
  const chipText = document.getElementById('live-text');

  const paintHealth = (file) => {
    if (!file) {
      if (label) label.textContent = 'status unavailable';
      if (meta) meta.textContent = 'status.json unreachable';
      return;
    }
    const status = recomputeHealth(file);
    const { sources, overall } = status;
    const text = overall === 'ok' ? 'all sources current' : overall === 'outage' ? 'critical outage' : 'degraded';
    if (dot) dot.className = `dot ${overall}`;
    if (label) label.textContent = text;
    if (meta) {
      const checked = status.generated_at
        ? status.generated_at.slice(11, 16) + 'Z'
        : 'schedule unknown';
      meta.textContent = `${sources.length} sources · ${checked}`;
    }
    if (chip) chip.className = `live-chip ${overall}`;
    if (chipText) chipText.textContent = text;
  };

  // fetchJson resolves to null instead of rejecting, but an explicit second
  // handler keeps the chain complete if that ever changes.
  fetchJson('/data/status.json').then(paintHealth, () => paintHealth(null));
}

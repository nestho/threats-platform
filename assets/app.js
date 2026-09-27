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

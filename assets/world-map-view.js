import { WORLD_PATHS, WORLD_VIEWBOX } from './world-map.js';
import { countryName, levelFor } from './geo.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Read a country code from a query string.
 *
 * The overview links to /map.html?country=XX. Anything that is not two ASCII
 * letters is ignored rather than passed on, so a hand-edited or hostile link
 * cannot select an arbitrary key in the geometry table.
 */
export function countryFromQuery(search) {
  const value = new URLSearchParams(search).get('country');
  if (!value) return null;
  const code = value.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : null;
}

function barShare(count, peak) {
  const value = Number(count) || 0;
  const top = Number(peak) || 0;
  if (value <= 0 || top <= 0) return 0;
  return Math.min(100, Math.round((value / top) * 1000) / 10);
}

export function claimWord(count) {
  return count === 1 ? 'claim' : 'claims';
}

/**
 * The busiest countries, with a bar width relative to the busiest one.
 *
 * The aggregate is already ordered by count; taking a prefix keeps the ranking
 * honest about ties instead of re-sorting and inventing an order.
 */
export function countryRanking(aggregate, limit = 5) {
  const countries = Array.isArray(aggregate?.countries) ? aggregate.countries : [];
  const peak = Number(aggregate?.max) || 0;
  return countries.slice(0, Math.max(0, limit)).map((entry) => ({
    ...entry,
    bar: barShare(entry.count, peak),
  }));
}

/**
 * Draw the world once and repaint its classes on later calls.
 *
 * Both the overview teaser and the full geography page use this. Re-creating
 * 175 paths per filter change would be the only expensive work on either page.
 *
 * focusable is fixed per surface: on the geography page coloured countries are
 * buttons, while the overview keeps the drawing out of the tab order and lets
 * the ranked country links carry keyboard access.
 */
export function createWorldView(svg, { focusable = false } = {}) {
  svg.setAttribute('viewBox', WORLD_VIEWBOX);

  const shapes = new Map();
  for (const [code, path] of Object.entries(WORLD_PATHS)) {
    const shape = document.createElementNS(SVG_NS, 'path');
    shape.setAttribute('d', path);
    shape.setAttribute('class', 'country');
    shape.dataset.code = code;
    svg.append(shape);
    shapes.set(code, shape);
  }

  function paint(countries, { max = 0, selected = null } = {}) {
    const present = new Map(countries.map((entry) => [entry.code, entry]));
    for (const [code, shape] of shapes) {
      const country = present.get(code);
      const classes = ['country'];
      if (country) {
        classes.push('has-claims');
        const level = levelFor(country.count, max);
        if (level) classes.push(`lvl-${level}`);
      }
      if (code === selected) classes.push('selected');
      shape.setAttribute('class', classes.join(' '));

      if (!country) {
        for (const name of ['tabindex', 'role', 'aria-label', 'aria-pressed']) {
          shape.removeAttribute(name);
        }
        shape.replaceChildren();
        continue;
      }

      const label = `${countryName(code)}, ${country.count} ${claimWord(country.count)}`;
      if (focusable) {
        shape.setAttribute('tabindex', '0');
        shape.setAttribute('role', 'button');
        shape.setAttribute('aria-pressed', String(code === selected));
        shape.setAttribute('aria-label', label);
      }
      shape.replaceChildren();
      const title = document.createElementNS(SVG_NS, 'title');
      title.textContent = `${countryName(code)} · ${country.count} ${claimWord(country.count)}`;
      shape.append(title);
    }
    return { drawn: shapes.size, shown: present.size };
  }

  return { shapes, paint };
}

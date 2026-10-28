#!/usr/bin/env python3
"""
Build the offline world outline used by map.html.

The site has no build step and no runtime dependencies, so the map cannot
download TopoJSON or run a projection library in the browser. Instead this
script projects Natural Earth's 1:110m country geometry once and commits the
result as an ES module of SVG path strings keyed by ISO 3166-1 alpha-2.

Natural Earth is public domain, which keeps the map usable commercially -- the
reason the map is built from the ransomware feed's own ISO country codes rather
than from an IP geolocation service with a non-commercial licence.

Regenerate with:

    python3 scripts/build_world_map.py

The upstream file is pinned to a commit SHA rather than `master`, so a
regeneration reproduces the committed asset byte for byte.
"""
import json
import urllib.request
from pathlib import Path

SOURCE = (
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/"
    "9380cca83db5f9aef52d5e762765100745f84b27/geojson/ne_110m_admin_0_countries.geojson"
)

OUTPUT = Path(__file__).resolve().parent.parent / "assets" / "world-map.js"

# Equirectangular crop: Antarctica and the empty Arctic are dropped so the
# populated latitudes get the page width instead of a band of ice.
MIN_LAT, MAX_LAT = -58.0, 84.0
WIDTH = 1000
HEIGHT = round(WIDTH * (MAX_LAT - MIN_LAT) / 360)

# One decimal on a 1000px canvas is ~0.4px; more precision is invisible and
# multiplies the committed file size.
PRECISION = 1


def project(lon, lat):
    x = (lon + 180.0) / 360.0 * WIDTH
    y = (MAX_LAT - lat) / (MAX_LAT - MIN_LAT) * HEIGHT
    return round(x, PRECISION), round(y, PRECISION)


def ring_path(ring):
    points = []
    for lon, lat in ring:
        point = project(lon, lat)
        if not points or points[-1] != point:
            points.append(point)
    if len(points) < 3:
        return ""
    head, *tail = points
    body = " ".join(f"{x:g} {y:g}" for x, y in tail)
    return f"M{head[0]:g} {head[1]:g} {body}Z"


def geometry_polygons(geometry):
    kind = geometry.get("type")
    if kind == "Polygon":
        return [geometry["coordinates"]]
    if kind == "MultiPolygon":
        return geometry["coordinates"]
    return []


def geometry_paths(geometry):
    return "".join(
        ring_path(ring) for polygon in geometry_polygons(geometry) for ring in polygon
    )


def ring_area(ring):
    """Signed shoelace area; the sign only tells winding direction."""
    total = 0.0
    for index, (x1, y1) in enumerate(ring):
        x2, y2 = ring[(index + 1) % len(ring)]
        total += x1 * y2 - x2 * y1
    return total / 2.0


def largest_ring(polygons):
    """
    Outer ring of the biggest polygon.

    A country's outline is a list of polygons, each starting with its outer ring
    and followed by holes. France is mainland plus French Guiana, so the
    mainland has to win or its marker drifts into the Atlantic.
    """
    best = None
    best_area = 0.0
    for polygon in polygons or []:
        ring = polygon[0] if polygon else []
        if len(ring) < 3:
            continue
        area = abs(ring_area(ring))
        if area > best_area:
            best, best_area = ring, area
    return best


def ring_centroid(ring):
    """Area-weighted centroid; may fall outside a concave ring."""
    area = ring_area(ring)
    if not area:
        return (0.0, 0.0)
    x_sum = 0.0
    y_sum = 0.0
    for index, (x1, y1) in enumerate(ring):
        x2, y2 = ring[(index + 1) % len(ring)]
        cross = x1 * y2 - x2 * y1
        x_sum += (x1 + x2) * cross
        y_sum += (y1 + y2) * cross
    return (x_sum / (6.0 * area), y_sum / (6.0 * area))


def point_in_ring(point, ring):
    x, y = point
    inside = False
    for index, (x1, y1) in enumerate(ring):
        x2, y2 = ring[(index + 1) % len(ring)]
        if (y1 > y) != (y2 > y):
            cross = x1 + (y - y1) * (x2 - x1) / (y2 - y1)
            if cross > x:
                inside = not inside
    return inside


def _edge_distance(point, segment):
    """Distance from a point to a segment, used to find the roomiest spot."""
    px, py = point
    (x1, y1), (x2, y2) = segment
    dx, dy = x2 - x1, y2 - y1
    if dx == 0 and dy == 0:
        return ((px - x1) ** 2 + (py - y1) ** 2) ** 0.5
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
    nearest = (x1 + t * dx, y1 + t * dy)
    return ((px - nearest[0]) ** 2 + (py - nearest[1]) ** 2) ** 0.5


def interior_point(ring, steps=16):
    """
    A point that is inside `ring`.

    Concave countries (Norway, Croatia, the United States with Alaska) put their
    centroid in the water, which would place their pulse offshore. When that
    happens, sample a grid and keep the inside point furthest from any edge —
    the same idea as a pole of inaccessibility, small enough to run per country
    at build time.
    """
    if len(ring) < 3:
        return None
    centroid = ring_centroid(ring)
    if point_in_ring(centroid, ring):
        return centroid

    xs = [x for x, _ in ring]
    ys = [y for _, y in ring]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    segments = [(ring[i], ring[(i + 1) % len(ring)]) for i in range(len(ring))]

    best = None
    best_clearance = 0.0
    for row in range(1, steps):
        y = min_y + (max_y - min_y) * row / steps
        for column in range(1, steps):
            x = min_x + (max_x - min_x) * column / steps
            if not point_in_ring((x, y), ring):
                continue
            clearance = min(_edge_distance((x, y), segment) for segment in segments)
            if clearance > best_clearance:
                best, best_clearance = (x, y), clearance
    return best


def project_polygons(polygons):
    """Project lon/lat polygons into the same space as the SVG paths."""
    return [[[project(lon, lat) for lon, lat in ring] for ring in polygon] for polygon in polygons]


def centroid_table(features):
    """Country code -> [x, y] in the same projected space as the SVG paths."""
    table = {}
    for feature in features:
        ring = largest_ring(feature.get("polygons"))
        point = interior_point(ring) if ring else None
        if point is None:
            continue
        table[feature["code"]] = [round(point[0], PRECISION), round(point[1], PRECISION)]
    return table


def iso_code(properties):
    for key in ("ISO_A2_EH", "ISO_A2"):
        value = (properties.get(key) or "").strip()
        if len(value) == 2 and value.isalpha():
            return value.upper()
    return ""


def main():
    with urllib.request.urlopen(SOURCE, timeout=120) as response:
        document = json.loads(response.read().decode("utf-8"))

    paths = {}
    polygons = {}
    skipped = []
    for feature in document["features"]:
        code = iso_code(feature["properties"])
        geometry = feature.get("geometry") or {}
        path = geometry_paths(geometry) if geometry else ""
        if not code or not path:
            skipped.append(feature["properties"].get("NAME", "?"))
            continue
        if code in paths:
            # Natural Earth splits a few countries into multiple features.
            paths[code] += path
            polygons[code].extend(geometry_polygons(geometry))
        else:
            paths[code] = path
            polygons[code] = geometry_polygons(geometry)

    centroids = centroid_table(
        [{"code": code, "polygons": project_polygons(polygons[code])} for code in sorted(polygons)]
    )

    lines = [
        "// Generated by scripts/build_world_map.py -- do not edit by hand.",
        "// Natural Earth 1:110m Admin 0 Countries, public domain.",
        f"// Equirectangular, {MIN_LAT:g} to {MAX_LAT:g} latitude, {WIDTH}x{HEIGHT}.",
        "export const WORLD_VIEWBOX = "
        f"\"0 0 {WIDTH} {HEIGHT}\";",
        "export const WORLD_PATHS = Object.freeze({",
    ]
    for code in sorted(paths):
        lines.append(f"  {code}: {json.dumps(paths[code])},")
    lines.append("});")
    lines.append("")
    # Marker anchors, in the same projected space: the interior point of each
    # country's largest polygon, so a pulse never lands in the sea.
    lines.append("export const WORLD_CENTROIDS = Object.freeze({")
    for code in sorted(centroids):
        x, y = centroids[code]
        lines.append(f"  {code}: [{x:g}, {y:g}],")
    lines.append("});")
    lines.append("")

    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    size = OUTPUT.stat().st_size
    print(f"wrote {OUTPUT} ({size / 1024:.1f} KiB, {len(paths)} countries)")
    if skipped:
        print(f"skipped without ISO code or geometry: {', '.join(sorted(skipped))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

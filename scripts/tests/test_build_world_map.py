"""Tests for the offline world outline's marker geometry.

Pulses on the live map are placed at these points, so a centroid that lands in
the sea (France with French Guiana, Norway's coast) would draw a wave of events
in the wrong place. The builder therefore has to return a point that is inside
the country, not merely near its middle.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import build_world_map as world


SQUARE = [[(0, 0), (10, 0), (10, 10), (0, 10)]]
# A C shape: its shoelace centroid sits in the open mouth at roughly (5, 5).
C_SHAPE = [[(0, 0), (10, 0), (10, 2), (2, 2), (2, 8), (10, 8), (10, 10), (0, 10)]]


def inside(point, ring):
    """Ray-casting containment test, independent of the implementation."""
    x, y = point
    hit = False
    for index, (x1, y1) in enumerate(ring):
        x2, y2 = ring[(index + 1) % len(ring)]
        if (y1 > y) != (y2 > y):
            cross = x1 + (y - y1) * (x2 - x1) / (y2 - y1)
            if cross > x:
                hit = not hit
    return hit


class LargestPolygonTest(unittest.TestCase):
    def test_picks_the_polygon_with_the_most_area(self):
        mainland = SQUARE
        island = [[(20, 20), (21, 20), (21, 21), (20, 21)]]
        self.assertEqual(world.largest_ring([mainland, island]), SQUARE[0])

    def test_ignores_degenerate_rings(self):
        self.assertIsNone(world.largest_ring([[[(0, 0), (1, 1)]]]))

    def test_uses_the_outer_ring_and_ignores_holes(self):
        polygon = [SQUARE[0], [(1, 1), (2, 1), (2, 2)]]
        self.assertEqual(world.largest_ring([polygon]), SQUARE[0])


class InteriorPointTest(unittest.TestCase):
    def test_square_centroid_is_the_middle(self):
        x, y = world.interior_point(SQUARE[0])
        self.assertAlmostEqual(x, 5, places=6)
        self.assertAlmostEqual(y, 5, places=6)

    def test_c_shape_centroid_would_fall_in_the_notch(self):
        # Guard the fixture itself: the naive centroid must be outside for this
        # test to prove anything.
        centroid = world.ring_centroid(C_SHAPE[0])
        self.assertFalse(inside(centroid, C_SHAPE[0]))

    def test_c_shape_returns_a_point_inside_the_land(self):
        x, y = world.interior_point(C_SHAPE[0])
        self.assertTrue(inside((x, y), C_SHAPE[0]), f"({x}, {y}) is not inside the C")

    def test_degenerate_ring_has_no_interior_point(self):
        self.assertIsNone(world.interior_point([(0, 0), (1, 1)]))


class CentroidTableTest(unittest.TestCase):
    def test_centroids_are_rounded_to_one_decimal(self):
        table = world.centroid_table([
            {"code": "SQ", "polygons": [SQUARE]},
        ])
        self.assertEqual(table["SQ"], [5, 5])

    def test_countries_without_geometry_are_omitted(self):
        table = world.centroid_table([{"code": "XX", "polygons": []}])
        self.assertEqual(table, {})


if __name__ == "__main__":
    unittest.main()

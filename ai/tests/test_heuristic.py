import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nameforge.heuristic import (
    heuristic_suggest,
    is_valid_identifier,
    make_name,
    split_words,
    usable_words,
)
from nameforge.provider import validate_suggestions


class TestHeuristic(unittest.TestCase):
    def test_split_words(self):
        self.assertEqual(split_words("PlayerSpeed"), ["player", "speed"])
        self.assertEqual(split_words("player-speed"), ["player", "speed"])
        self.assertEqual(split_words("getHTTPResponse"), ["get", "http", "response"])

    def test_make_name_styles(self):
        style = {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64}
        self.assertEqual(make_name(style, ["player", "speed"]), "player_speed")
        style["case"] = "camelCase"
        self.assertEqual(make_name(style, ["player", "speed"]), "playerSpeed")
        style["case"] = "PascalCase"
        self.assertEqual(make_name(style, ["player", "speed"]), "PlayerSpeed")

    def test_heuristic_uses_strings(self):
        ctx = {
            "address": 0x1000,
            "size": 0x40,
            "current_name": None,
            "state": "detected",
            "instructions": [{"address": 0x1000, "text": "nop"}] * 3,
            "instructions_truncated": False,
            "callers": [],
            "callees": [],
            "strings": [{"address": 0x2000, "value": "player_speed"}],
            "constants": [],
            "style": {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64,
                      "inferred_case": None, "examples": []},
        }
        style = {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64}
        res = heuristic_suggest(ctx, style)
        self.assertTrue(res)
        self.assertEqual(res[0]["name"], "player_speed")

    def test_heuristic_no_evidence(self):
        ctx = {"instructions": [], "strings": [], "callees": []}
        style = {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64}
        self.assertEqual(heuristic_suggest(ctx, style), [])

    def test_usable_words_rejects_paths(self):
        self.assertIsNone(usable_words("/usr/bin"))
        self.assertIsNone(usable_words("https://example.com"))
        self.assertIsNotNone(usable_words("player speed"))

    def test_is_valid_identifier(self):
        self.assertTrue(is_valid_identifier("player_speed", 64))
        self.assertFalse(is_valid_identifier("1player", 64))

    def test_validate_suggestions(self):
        style = {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64}
        suggestions = [
            {"name": "good_name", "confidence": 0.8, "reason": "cadena cercana"},
            {"name": "bad-name", "confidence": 0.9, "reason": "x"},
            {"name": "nan", "confidence": float("nan"), "reason": "x"},
            {"name": "no_reason", "confidence": 0.5, "reason": " "},
        ]
        valid = validate_suggestions(suggestions, style)
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0]["name"], "good_name")


if __name__ == "__main__":
    unittest.main()
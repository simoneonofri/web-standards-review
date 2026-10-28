from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from whatwg_miner import (  # noqa: E402
    anchor_exists,
    evidence_class,
    matched_categories,
    parse_index,
    parse_spec,
)


class MinerTests(unittest.TestCase):
    def test_index_parser_ignores_social_link_text(self) -> None:
        source = b'''<dl><dt><a href="https://one.spec.whatwg.org/">One</a> (<a href="https://example.test/">@one</a>)</dt><dd><p>First standard.</p></dd><dt><a href="https://two.spec.whatwg.org/">Two API</a></dt><dd>Second standard.</dd></dl>'''
        inventory = parse_index(source)
        self.assertEqual(inventory["standard_count"], 2)
        self.assertEqual([item["title"] for item in inventory["standards"]], ["One", "Two API"])

    def test_spec_parser_handles_optional_paragraph_end_tags(self) -> None:
        source = b'''<h2 id="guard">Guard</h2><p>Permission is denied by default.<p id="failure">Return a network error when authorization fails.'''
        blocks = parse_spec(source)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0].anchor, "guard")
        self.assertEqual(blocks[1].anchor, "failure")

    def test_classifier_separates_privacy_only_and_security(self) -> None:
        self.assertEqual(evidence_class("This limits fingerprinting and tracking.", "Privacy"), "privacy_only")
        self.assertEqual(evidence_class("This permission prevents an attacker from reading data.", "Guard"), "security_control")

    def test_category_matching(self) -> None:
        categories = matched_categories("A cross-origin request requires transient activation and permission.")
        self.assertIn("origin-and-isolation", categories)
        self.assertIn("user-intent-and-visibility", categories)
        self.assertIn("authority-and-permission", categories)

    def test_anchor_check(self) -> None:
        self.assertTrue(anchor_exists(b'<h2 id="a-(b)">Title</h2>', "a-(b)"))
        self.assertFalse(anchor_exists(b'<h2 id="other">Title</h2>', "missing"))


if __name__ == "__main__":
    unittest.main()

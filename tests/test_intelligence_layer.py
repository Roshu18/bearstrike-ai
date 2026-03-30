import time
import unittest
from unittest.mock import patch

from core.control_plane import (
    add_hunter_note,
    ensure_db,
    get_high_value_targets,
    get_hunter_notes,
    score_endpoint,
)
from core.reporting import build_target_report_markdown
from core.strategist import analyze_target_surface, build_strategy_bundle
from core.strike_engine import (
    get_autonomous_hunt_state,
    start_autonomous_hunt,
    stop_autonomous_hunt,
)


class IntelligenceLayerTests(unittest.TestCase):
    def setUp(self) -> None:
        ensure_db()

    def tearDown(self) -> None:
        stop_autonomous_hunt()
        time.sleep(0.2)

    def test_hunter_note_roundtrip(self) -> None:
        note = add_hunter_note("example.com", "Potential IDOR on account endpoint", 0.72)
        self.assertEqual(note["target"], "example.com")
        self.assertGreater(note["id"], 0)

        notes = get_hunter_notes("example.com", limit=20)
        messages = [str(item.get("message") or "") for item in notes]
        self.assertTrue(any("Potential IDOR" in message for message in messages))

    def test_get_high_value_targets_filters(self) -> None:
        score_endpoint(target="example.com", endpoint="/api/user?id=9", method="GET", context="hackerone")
        score_endpoint(target="example.com", endpoint="/status", method="GET", context="")

        high = get_high_value_targets(target="example.com", limit=20, min_score=8)
        self.assertTrue(high)
        self.assertTrue(all(int(item.get("score") or 0) >= 8 for item in high))

    def test_strategist_and_report_markdown(self) -> None:
        score_endpoint(target="example.com", endpoint="/api/auth/login", method="POST", context="hackerone")
        add_hunter_note("example.com", "Auth edge-case around pre-verification state", 0.66)

        bundle = build_strategy_bundle("example.com", limit=10)
        self.assertEqual(bundle.get("target"), "example.com")
        self.assertIn("risk_posture", bundle)

        analysis = analyze_target_surface("example.com", limit=10)
        self.assertIn("Recommended Focus", analysis)

        report = build_target_report_markdown("example.com")
        self.assertIn("BearStrike Target Report", report)
        self.assertIn("example.com", report)

    @patch(
        "core.strike_engine.run_tool",
        return_value=(
            "critical high severity vulnerability found: "
            "sql injection, ssrf, idor, broken access control, remote code execution"
        ),
    )
    @patch("core.strike_engine.check_tool_installed", return_value=True)
    def test_autonomous_hunt_stops_on_high_confidence_signal(self, _mock_installed, _mock_run) -> None:
        message = start_autonomous_hunt("example.com", mode="low_noise", max_duration_seconds=120)
        self.assertIn("started", message.lower())

        deadline = time.time() + 6.0
        while time.time() < deadline:
            state = get_autonomous_hunt_state()
            if not bool(state.get("running", False)) and str(state.get("stop_reason") or ""):
                break
            time.sleep(0.1)

        final_state = get_autonomous_hunt_state()
        if bool(final_state.get("running", False)):
            time.sleep(0.5)
            final_state = get_autonomous_hunt_state()
        self.assertFalse(bool(final_state.get("running", False)))
        self.assertEqual(str(final_state.get("stop_reason") or ""), "high-confidence-hit")


if __name__ == "__main__":
    unittest.main()

import json, os, random, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cna.analyze import analyze, analyze_session, percentile, load_trace
from cna.synth import generate, make_session
from cna.cli import main


class EndToEnd(unittest.TestCase):
    def test_exact_match_against_ground_truth(self):
        events, truth = generate(seed=7)
        r = analyze(events)
        self.assertEqual(r["attempts"], truth["attempts"])
        self.assertEqual(r["outcomes"]["SUCCESS"], truth["success"])
        self.assertEqual(r["outcomes"]["REJECTED"], truth["rejected"])
        self.assertEqual(r["outcomes"]["INCOMPLETE"], truth["incomplete"])
        self.assertEqual(r["outcomes"]["OUT_OF_ORDER"], truth["out_of_order"])
        self.assertEqual(r["reject_causes"], truth["reject_causes"])

    def test_other_seeds_still_match(self):
        for seed in (1, 2, 99):
            events, truth = generate(seed=seed)
            r = analyze(events)
            self.assertEqual(r["outcomes"]["SUCCESS"], truth["success"], seed)
            self.assertEqual(r["reject_causes"], truth["reject_causes"], seed)

    def test_expected_alarms(self):
        events, _ = generate(seed=7)
        r = analyze(events)
        text = " ".join(r["alarms"])
        self.assertIn("ATTACH_SUCCESS_LOW", text)
        # 4 slow HSS answers out of ~200 sessions is about 2%, so p95 stays low but the maximum shows them
        self.assertNotIn("HSS_LATENCY_HIGH", text)
        self.assertGreater(r["latency"]["HSS authentication (AIR->AIA)"]["max_ms"], 500)
        self.assertIn("CREATE_SESSION_FAILURES", text)
        self.assertIn("STALLED_SESSIONS: 6", text)
        self.assertIn("OUT_OF_ORDER_SIGNALLING: 2", text)

    def test_clean_network_has_no_alarms(self):
        events, truth = generate(seed=3, counts={"ok": 100})
        r = analyze(events)
        self.assertEqual(r["attach_success_pct"], 100.0)
        self.assertEqual(r["alarms"], [])
        self.assertLess(r["latency"]["HSS authentication (AIR->AIA)"]["p95_ms"], 100)

    def test_slow_hss_sessions_succeed_but_raise_latency(self):
        events, _ = generate(seed=3, counts={"ok": 50, "slow_hss": 10})
        r = analyze(events)
        self.assertEqual(r["outcomes"], {"SUCCESS": 60})
        self.assertGreater(r["latency"]["HSS authentication (AIR->AIA)"]["p95_ms"], 500)


class Sessions(unittest.TestCase):
    def one(self, scen):
        return analyze_session(make_session("s", "001010000000001", scen, 0.0, random.Random(1)))

    def test_root_causes(self):
        self.assertIn("5001", self.one("user_unknown")["root_cause"])
        self.assertIn("5004", self.one("roaming_not_allowed")["root_cause"])
        self.assertIn("73", self.one("no_resources")["root_cause"])
        self.assertIn("78", self.one("unknown_apn")["root_cause"])
        self.assertEqual(self.one("auth_failure")["root_cause"], "authentication failure")

    def test_incomplete_points_at_missing_step(self):
        self.assertEqual(self.one("hss_timeout")["detail"], "no 'Authentication-Information-Answer'")
        self.assertEqual(self.one("stalled_context")["detail"], "no 'Initial Context Setup Response'")

    def test_out_of_order_names_the_step(self):
        r = self.one("out_of_order")
        self.assertEqual(r["outcome"], "OUT_OF_ORDER")
        self.assertIn("expected 'Security Mode Command'", r["detail"])

    def test_session_without_attach_request_is_not_a_success(self):
        evs = make_session("s", "001010000000001", "ok", 0.0, random.Random(1))[1:]
        r = analyze_session(evs)
        self.assertEqual(r["outcome"], "OUT_OF_ORDER")
        self.assertIn("expected 'Attach Request'", r["detail"])

    def test_empty_session_list(self):
        r = analyze([])
        self.assertEqual(r["attempts"], 0)
        self.assertEqual(r["alarms"], [])


class Helpers(unittest.TestCase):
    def test_percentile_nearest_rank(self):
        v = list(range(1, 101))
        self.assertEqual(percentile(v, 50), 50)
        self.assertEqual(percentile(v, 95), 95)
        self.assertIsNone(percentile([], 50))

    def test_bad_trace_line_reports_line_number(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"ts": 1, "session": "a", "iface": "NAS", "msg": "x"}\n{"ts": 2}\n')
        with self.assertRaises(ValueError) as c:
            load_trace(f.name)
        self.assertIn("line 2", str(c.exception))
        os.unlink(f.name)

    def test_cli_round_trip_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.jsonl")
            self.assertEqual(main(["generate", p]), 0)
            self.assertEqual(main(["analyze", p]), 0)
            self.assertEqual(main(["analyze", p, "--fail-on-alarm"]), 2)


if __name__ == "__main__":
    unittest.main()

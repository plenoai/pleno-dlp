import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location("performance", Path(__file__).with_name("run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class PerformanceContract(unittest.TestCase):
    def test_timeout_terminates_the_wrapped_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "survived"
            child = "import sys,time; from pathlib import Path; time.sleep(1); Path(sys.argv[1]).write_text('alive')"
            wrapper = "import subprocess,sys,time; subprocess.Popen(sys.argv[1:]); print('ready', flush=True); time.sleep(30)"
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                run.run_process([sys.executable, "-c", wrapper, sys.executable, "-c", child, str(marker)], timeout=0.5)
            self.assertIn(b"ready", caught.exception.output)
            time.sleep(1)
            self.assertFalse(marker.exists(), "scanner survived its timed-out wrapper")

    def test_both_metrics_and_every_competitor_are_required(self):
        samples = {name: [{"seconds": 1, "rss_bytes": 100}]
                   for name in ("pleno-dlp", *run.COMPETITORS)}
        self.assertTrue(run.evaluate(samples, 1)["pass"])
        samples["pleno-dlp"][0]["rss_bytes"] = 121
        self.assertFalse(run.evaluate(samples, 1)["pass"])
        samples["pleno-dlp"][0]["rss_bytes"] = 100
        samples["betterleaks"][0]["seconds"] = 0.5
        result = run.evaluate(samples, 1)
        self.assertEqual(result["metrics"]["seconds"]["competitor"], "betterleaks")
        self.assertFalse(result["pass"])
        del samples["betterleaks"]
        self.assertFalse(run.evaluate(samples, 1)["pass"])

    def test_coverage_failure_and_missing_samples_cannot_pass(self):
        samples = {name: [{"seconds": 1, "rss_bytes": 100}]
                   for name in ("pleno-dlp", *run.COMPETITORS)}
        samples["pleno-dlp"][0]["error"] = "canary mismatch"
        result = run.evaluate(samples, 1)
        self.assertFalse(result["pass"])
        self.assertTrue(result["metrics"]["seconds"]["pass"])
        del samples["pleno-dlp"][0]["error"]
        self.assertFalse(run.evaluate(samples, 2)["pass"])

    def test_empty_output_still_has_a_baseline_signature(self):
        self.assertEqual(run.observations("pleno-dlp", "[]", set())[1], run.digest(b""))

    def test_baseline_signature_includes_offsets_and_severity(self):
        record = {"detector": "Other", "start": 10, "end": 20, "severity": "high"}
        signature = run.observations("pleno-dlp", json.dumps([record]), set())[1]
        for key, value in (("start", 11), ("severity", "low")):
            changed = {**record, key: value}
            self.assertNotEqual(run.observations("pleno-dlp", json.dumps([changed]), set())[1], signature)

    def test_betterleaks_null_report_and_malformed_json(self):
        self.assertEqual(run.observations("betterleaks", "null", set()), (0, None))
        for data in ("{}", "false", "[5]", "null"):
            with self.assertRaises(ValueError):
                run.observations("pleno-dlp", data, set())

    def test_missing_or_extra_canary_is_a_failure(self):
        token = "ghp_" + "a" * 36
        expected = {run.digest(token.encode())}
        record = {"RuleID": "github-pat", "Secret": token}
        self.assertEqual(run.observations("gitleaks", json.dumps([record]), expected)[0], 1)
        with self.assertRaises(ValueError):
            run.observations("gitleaks", "[]", expected)
        with self.assertRaises(ValueError):
            run.observations("gitleaks", json.dumps([record]), set())

    def test_budget_uses_best_competitor_and_median(self):
        samples = {name: [{"seconds": value} for value in values] for name, values in {
            "pleno-dlp": [1.21, 1.21, 0.1], "before": [2, 2, 2],
            "gitleaks": [1, 1, 99], "trufflehog": [3, 3, 3]}.items()}
        result = run.summarize(samples, "seconds")
        self.assertEqual(result["competitor"], "gitleaks")
        self.assertEqual(result["before_ratio"], 2)
        self.assertFalse(result["pass"])
        samples["pleno-dlp"] = [{"seconds": 1.2}]
        self.assertTrue(run.summarize(samples, "seconds")["pass"])


if __name__ == "__main__":
    unittest.main()

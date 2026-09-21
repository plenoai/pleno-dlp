import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("performance", Path(__file__).with_name("run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class PerformanceContract(unittest.TestCase):
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

"""Run with python3 -m unittest discover -s bench/oss-study."""
from pathlib import Path
import unittest

from accuracy import DATA, score
from study import command, competing_work, safe_path
from report import summarize


class StudyTest(unittest.TestCase):
    def test_scoring_deduplicates_and_does_not_invent_labels(self):
        labels = {
            ("a", 1): [{"GroundTruth": "T", "Category": "Token"}],
            ("a", 2): [{"GroundTruth": "F", "Category": "Token"}],
            ("a", 3): [{"GroundTruth": "X", "Category": "Token"}],
            ("a", 4): [{"GroundTruth": "T", "Category": "Token"}],
            ("a", 5): [{"GroundTruth": x, "Category": "Token"} for x in ("T", "F")],
        }
        records = [{"path": str(DATA / "a"), "line": n} for n in (1, 1, 2, 5, 9)]
        result = score(labels, records)
        self.assertEqual([result[k] for k in ("tp", "fp", "tn", "fn")], [1, 1, 1, 1])
        self.assertEqual(result["unlabelled_predicted_lines"], 1)
        self.assertEqual(result["ambiguous_lines_excluded"], 1)
        self.assertEqual(result["f1_on_labelled_lines"], 0.5)

    def test_paths_and_offline_commands(self):
        for name in ("../escape", "/absolute/file", "root/../../escape", "root"):
            with self.assertRaises(ValueError):
                safe_path(name)
        self.assertEqual(safe_path("root/.github/test.yml"), Path(".github/test.yml"))
        self.assertIn("--no-verify", command("pleno-dlp", "scanner", Path("input")))
        self.assertIn("--no-verification", command("trufflehog", "scanner", Path("input")))

    def test_aggregate_uses_medians_and_cpu_sum(self):
        values = [{"seconds": n, "user_seconds": 2 * n, "system_seconds": n,
                   "rss_bytes": n * 1024, "findings": 1, "canary_found": True,
                   "locations_sha256": "same"} for n in (1, 100, 2)]
        results = {"runs": 3, "tools": {"pleno-dlp": {}, "trufflehog": {}},
                   "repositories": {"repo": {"pleno-dlp": values, "trufflehog": values}}}
        got = summarize([{"repo": "repo", "files": 1, "bytes": 1048576}], results)
        self.assertEqual(got["totals"]["pleno-dlp"]["seconds"], 2)
        self.assertEqual(got["totals"]["pleno-dlp"]["cpu_seconds"], 6)
        self.assertEqual(got["aggregate_speedup"], 1)
        self.assertEqual(got["pleno_faster_repositories"], 0)

    def test_competing_work_ignores_this_study(self):
        self.assertFalse(competing_work("2 1 time time -l scanner\n3 2 trufflehog scanner input", 1))
        self.assertTrue(competing_work("2 0 go /usr/bin/go test ./...", 1))
        self.assertTrue(competing_work("3 0 pkg.test /tmp/pkg.test", 1))
        self.assertTrue(competing_work("4 0 trufflehog scanner input", 1))
        self.assertFalse(competing_work("5 0 sh sh -c 'go test ./...'", 1))
        self.assertFalse(competing_work("6 0 go /usr/bin/go version -m /tmp/go-build/file", 1))


if __name__ == "__main__":
    unittest.main()

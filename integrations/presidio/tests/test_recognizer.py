"""Tests runnable with stdlib only (no presidio install needed):
    python -m unittest discover -s tests

The presidio-dependent path is exercised only when presidio-analyzer
is importable.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pleno_dlp_presidio.recognizer import (  # noqa: E402
    DEFAULT_ENTITY_MAP,
    VERDICT_SCORES,
    _byte_to_char_offsets,
    _normalize_entity,
)

# Fake pleno-dlp: reads stdin, locates the first "SECRET-" run, and
# emits pleno-dlp's JSON finding shape with correct byte offsets.
FAKE_BIN = """#!/usr/bin/env python3
import json, re, sys
data = sys.stdin.buffer.read()
m = re.search(rb"SECRET-[A-Za-z0-9]+", data)
if m:
    print(json.dumps([{
        "detector": "FakeProvider", "verdict": "verified",
        "start": m.start(), "end": m.end(),
    }]))
else:
    print("[]")
"""


class TestHelpers(unittest.TestCase):
    def test_byte_to_char_offsets_multibyte(self):
        text = "日本語 SECRET-123 tail"
        start = text.encode().index(b"SECRET")
        end = start + len("SECRET-123")
        cs, ce = _byte_to_char_offsets(text, start, end)
        self.assertEqual(text[cs:ce], "SECRET-123")

    def test_byte_to_char_offsets_rejects_bad_range(self):
        self.assertIsNone(_byte_to_char_offsets("abc", 2, 99))

    def test_normalize_entity(self):
        self.assertEqual(_normalize_entity("AzureDevOps"), "AZUREDEVOPS")
        self.assertEqual(_normalize_entity("a"), "A")

    def test_verdict_scores_covered(self):
        for v in ("verified", "unverified", "indeterminate"):
            self.assertIn(v, VERDICT_SCORES)
        self.assertIn("OpenAI", DEFAULT_ENTITY_MAP)


class TestRecognizerAgainstFakeBinary(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        path = os.path.join(self.dir, "pleno-dlp")
        with open(path, "w") as f:
            f.write(FAKE_BIN)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        self.bin = path

    def _recognizer(self):
        from pleno_dlp_presidio.recognizer import PlenoDLPRecognizer

        return PlenoDLPRecognizer(binary=self.bin, verify=False)

    def test_finds_secret_with_char_offsets(self):
        r = self._recognizer()
        text = "前置き SECRET-AB12 後置き"
        results = r.analyze(text, None)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(text[res.start:res.end], "SECRET-AB12")
        self.assertEqual(res.score, 1.0)

    def test_no_findings(self):
        r = self._recognizer()
        self.assertEqual(r.analyze("nothing here", None), [])

    def test_missing_binary_returns_empty(self):
        from pleno_dlp_presidio.recognizer import PlenoDLPRecognizer

        r = PlenoDLPRecognizer(binary="definitely-not-on-path-xyz", verify=False)
        self.assertEqual(r.analyze("SECRET-1", None), [])


if __name__ == "__main__":
    unittest.main()

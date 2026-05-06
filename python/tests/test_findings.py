"""Finding redaction + factory behaviour."""

from __future__ import annotations

from pleno_secret_scanner.findings import Finding, _redact


def test_redact_keeps_first_four_last_two() -> None:
    assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA" + "*" * 14 + "LE"


def test_redact_short_strings_fully_masked() -> None:
    assert _redact("abc") == "***"
    assert _redact("123456") == "******"


def test_make_default_redacts_raw() -> None:
    f = Finding.make(
        rule_id="aws",
        backend="native",
        raw="AKIAIOSFODNN7EXAMPLE",
        source_id="x",
        source_kind="test",
        path="/p",
    )
    assert f.redacted == "AKIA" + "*" * 14 + "LE"
    assert f.verified is False


def test_make_honours_explicit_redacted() -> None:
    f = Finding.make(
        rule_id="aws",
        backend="trufflehog",
        raw="AKIAIOSFODNN7EXAMPLE",
        redacted="AKIA****",
        source_id="x",
        source_kind="test",
        path="/p",
    )
    assert f.redacted == "AKIA****"

"""Registry-driven detector instantiation + output factory error paths."""

from __future__ import annotations

import pytest

from pleno_dlp import output, registry


def test_detector_factory_known_names() -> None:
    for name in ("native", "trufflehog", "gitleaks"):
        det = registry.create(name)
        assert det.name == name


def test_detector_factory_pii_takes_kwargs() -> None:
    det = registry.create("pii", base_url="http://example.test", language="en")
    assert det.name == "pii"


def test_detector_factory_unknown_raises() -> None:
    with pytest.raises(KeyError, match="Unknown connector"):
        registry.create("does-not-exist")


def test_detector_factory_secret_rejects_unknown_kwargs() -> None:
    """Detectors with no extra kwargs reject unknowns loud — a typo'd flag
    must surface, not be silently dropped."""
    with pytest.raises(TypeError, match="unexpected kwargs"):
        registry.create("native", base_url="http://nope")


def test_output_factory_known_formats() -> None:
    for fmt in ("json", "sarif", "table"):
        s = output.make(fmt)
        assert s is not None


def test_output_factory_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        output.make("xml")

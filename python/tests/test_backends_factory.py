"""Backend factory + output factory error paths."""

from __future__ import annotations

import pytest

from pleno_dlp import backends, output


def test_backend_factory_known_names() -> None:
    for name in ("native", "trufflehog", "gitleaks"):
        b = backends.make(name)
        assert b.name == name


def test_backend_factory_pii_takes_kwargs() -> None:
    b = backends.make("pii", base_url="http://example.test", language="en")
    assert b.name == "pii"


def test_backend_factory_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown backend"):
        backends.make("does-not-exist")


def test_backend_factory_secret_rejects_kwargs() -> None:
    """Secret backends take no kwargs — a typo'd flag must surface, not be
    silently dropped."""
    with pytest.raises(TypeError, match="takes no kwargs"):
        backends.make("native", base_url="http://nope")


def test_output_factory_known_formats() -> None:
    for fmt in ("json", "sarif", "table"):
        s = output.make(fmt)
        assert s is not None


def test_output_factory_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        output.make("xml")

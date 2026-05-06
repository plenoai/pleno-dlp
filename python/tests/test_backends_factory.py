"""Backend factory + output factory error paths."""

from __future__ import annotations

import pytest

from pleno_secret_scanner import backends, output


def test_backend_factory_known_names() -> None:
    for name in ("native", "trufflehog", "gitleaks"):
        b = backends.make(name)
        assert b.name == name


def test_backend_factory_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown backend"):
        backends.make("does-not-exist")


def test_output_factory_known_formats() -> None:
    for fmt in ("json", "sarif", "table"):
        s = output.make(fmt)
        assert s is not None


def test_output_factory_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        output.make("xml")

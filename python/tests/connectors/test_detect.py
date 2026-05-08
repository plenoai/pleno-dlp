"""Per-connector detection — every shipped connector exposes ``detect()``
and routes through a configurable engine."""

from __future__ import annotations

import pytest

from pleno_dlp import Capability, Document, DocumentRef, registry
from pleno_dlp.engines import ENGINE_NAMES, NativeEngine

_SAAS_CONNECTORS = ("github", "gitlab", "bitbucket", "slack", "notion", "confluence", "jira")


@pytest.mark.parametrize("name", _SAAS_CONNECTORS)
def test_every_connector_advertises_detect_capability(name: str) -> None:
    """Every shipped SaaS connector includes Capability.DETECT in its spec."""
    spec = registry.spec(name)
    assert Capability.DETECT in spec.capabilities


@pytest.mark.parametrize("name", _SAAS_CONNECTORS)
def test_every_connector_accepts_engine_kwarg(name: str) -> None:
    """The `engine` kwarg is declared on every connector's option sheet."""
    spec = registry.spec(name)
    opt = spec.option("engine")
    assert opt is not None
    assert opt.default == "native"
    assert set(opt.choices) == set(ENGINE_NAMES)


async def test_github_detect_uses_internal_engine() -> None:
    """Construct github with no auth, hand it a Document with a known
    secret, and expect the bundled native engine to fire."""
    from pleno_dlp.connectors.github import GitHubConnector

    connector = GitHubConnector(owner=None)  # verify-style construction (no scan)
    try:
        doc = Document(
            ref=DocumentRef(source_id="t", source_kind="github", path="/x.txt"),
            text="leaked AKIAIOSFODNN7EXAMPLE in this file",
        )
        findings = [f async for f in connector.detect(doc)]
        assert any(f.rule_id == "aws-access-key-id" for f in findings)
    finally:
        await connector.close()


def test_unknown_engine_rejected_at_construction() -> None:
    """A typo'd engine name fails at __init__, not at first scan."""
    from pleno_dlp.connectors.github import GitHubConnector

    with pytest.raises(ValueError, match="unknown engine"):
        GitHubConnector(owner=None, engine="bogus")


async def test_engine_substitution_via_kwarg_takes_effect() -> None:
    """Constructing with engine='native' wires up NativeEngine internally."""
    from pleno_dlp.connectors.github import GitHubConnector

    connector = GitHubConnector(owner=None, engine="native")
    try:
        assert isinstance(connector._engine, NativeEngine)
    finally:
        await connector.close()

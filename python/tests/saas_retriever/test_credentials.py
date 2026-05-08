"""Credential bundle: shape + redaction-on-repr."""

from __future__ import annotations

from datetime import UTC, datetime

from saas_retriever import (
    Credential,
    CredentialError,
    CredentialMisconfiguredError,
    CredentialNotFoundError,
)


def test_credential_holds_provider_payload() -> None:
    cred = Credential(
        kind="github",
        payload={"token": "ghp_secret"},
        source="env",
    )
    assert cred.kind == "github"
    assert cred.payload["token"] == "ghp_secret"
    assert cred.source == "env"


def test_secret_keys_masked_in_repr() -> None:
    cred = Credential(
        kind="aws",
        payload={
            "access_key_id": "AKIA1234",  # public id — kept
            "secret_access_key": "deadbeef",  # secret — masked
            "region": "us-east-1",  # not secret — kept
        },
    )
    rendered = repr(cred)
    assert "AKIA1234" in rendered
    assert "us-east-1" in rendered
    assert "deadbeef" not in rendered
    assert "***" in rendered


def test_password_token_session_pem_all_masked() -> None:
    # Use distinctive values longer than the keys themselves so substring
    # matches in `repr` reflect the real value, not the field label.
    payload = {
        "password": "PASSWORDXX",
        "token": "TOKENXXXXXXX",
        "session_token": "SESSIONXXXXX",
        "private_key": "PRIVATEXXXXX",
        "ca_pem": "PEMVALUEXXXX",
        "credential_id": "CREDIDXXXXX",
    }
    rendered = repr(Credential(kind="x", payload=payload))
    for v in payload.values():
        assert v not in rendered, f"value {v!r} leaked: {rendered}"


def test_str_matches_repr() -> None:
    cred = Credential(kind="x", payload={"token": "t"})
    assert str(cred) == repr(cred)


def test_expires_at_optional() -> None:
    expires = datetime(2026, 5, 7, tzinfo=UTC)
    cred = Credential(kind="x", payload={"token": "t"}, expires_at=expires)
    assert cred.expires_at == expires
    # repr renders the datetime via its native ``__repr__`` (not isoformat),
    # so check for an unambiguous fragment.
    assert "2026, 5, 7" in repr(cred)


def test_error_hierarchy() -> None:
    assert issubclass(CredentialNotFoundError, CredentialError)
    assert issubclass(CredentialMisconfiguredError, CredentialError)

from __future__ import annotations

import logging

import pytest

from signet.config import DownstreamConfig, Settings
from signet.credential_broker import (
    CredentialError,
    MemorySecretStore,
    SecretReference,
    TokenRegistry,
)


def test_configuration_accepts_references_not_secret_values() -> None:
    with pytest.raises(ValueError, match="keychain"):
        DownstreamConfig(transport="http", url="https://example.test", credential_ref="secret")
    settings = Settings()
    dump = repr(settings.safe_dump())
    assert "keychain://" not in dump
    assert "<secret-reference>" in dump


def test_secrets_are_redacted_from_repr_str_and_errors(caplog: pytest.LogCaptureFixture) -> None:
    marker = "never-log-this-secret"
    store = MemorySecretStore({("Signet", "test"): marker})
    secret = store.get(SecretReference.parse("keychain://Signet/test"))
    caplog.set_level(logging.INFO)
    logging.info("secret=%r store=%r", secret, store)
    assert marker not in repr(secret)
    assert marker not in str(secret)
    assert marker not in repr(store)
    assert marker not in caplog.text


def test_profile_namespace_is_shared_across_alias_tokens_but_alias_is_enforced() -> None:
    registry = TokenRegistry()
    fastmail = registry.issue("profile:email", {"fastmail", "approvals"})
    approvals = registry.issue("profile:email", {"approvals"})
    other = registry.issue("profile:other", {"approvals"})

    enqueuer = registry.authenticate(f"Bearer {fastmail.token}", alias="fastmail")
    status_reader = registry.authenticate(f"Bearer {approvals.token}", alias="approvals")
    stranger = registry.authenticate(f"Bearer {other.token}", alias="approvals")
    assert enqueuer.namespace == status_reader.namespace == "profile:email"
    assert stranger.namespace != enqueuer.namespace
    with pytest.raises(CredentialError, match="invalid"):
        registry.authenticate(f"Bearer {approvals.token}", alias="fastmail")


def test_raw_tokens_are_never_exported_or_represented() -> None:
    registry = TokenRegistry()
    issued = registry.issue("profile:test", {"approvals"})
    exported = repr(registry.export_records())
    assert issued.token not in repr(issued)
    assert issued.token not in str(issued)
    assert issued.token not in exported
    assert issued.token.startswith("sgt_")


def test_revoked_and_missing_tokens_fail_closed() -> None:
    registry = TokenRegistry()
    issued = registry.issue("profile:test", {"approvals"})
    registry.revoke(issued.token_id)
    with pytest.raises(CredentialError, match="invalid"):
        registry.authenticate(f"Bearer {issued.token}", alias="approvals")
    with pytest.raises(CredentialError, match="required"):
        registry.authenticate(None, alias="approvals")

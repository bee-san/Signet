from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

from signet.config import DownstreamConfig, Settings
from signet.credential_broker import (
    CredentialError,
    MemorySecretStore,
    SecretReference,
    TokenRecord,
    TokenRegistry,
)


def test_configuration_accepts_references_not_secret_values() -> None:
    with pytest.raises(ValueError, match="credential_identity_digest"):
        DownstreamConfig(
            transport="http",
            url="https://example.test",
            credential_ref="keychain://Signet/example",
        )
    with pytest.raises(ValueError, match="keychain"):
        DownstreamConfig(
            transport="http",
            url="https://example.test",
            credential_ref="secret",
            credential_identity_digest="c" * 64,
        )
    with pytest.raises(ValueError, match="credential identity"):
        DownstreamConfig(
            transport="http",
            url="https://example.test",
            credential_ref="keychain://Signet/example",
            credential_identity_digest="generation-1",
        )
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
    assert registry.export_records()[0].verifier.startswith("sha256$")
    assert "$argon2" not in registry.export_records()[0].verifier


def test_revoked_and_missing_tokens_fail_closed() -> None:
    registry = TokenRegistry()
    issued = registry.issue("profile:test", {"approvals"})
    registry.revoke(issued.token_id)
    with pytest.raises(CredentialError, match="invalid"):
        registry.authenticate(f"Bearer {issued.token}", alias="approvals")
    with pytest.raises(CredentialError, match="required"):
        registry.authenticate(None, alias="approvals")


def test_machine_token_authentication_has_bounded_parallel_cost() -> None:
    registry = TokenRegistry()
    issued = registry.issue("profile:test", {"approvals"})
    token_id = issued.token.removeprefix("sgt_").split(".", 1)[0]
    wrong = f"sgt_{token_id}.{'A' * 43}"

    def reject(_: int) -> bool:
        try:
            registry.authenticate(f"Bearer {wrong}", alias="approvals")
        except CredentialError:
            return True
        return False

    with ThreadPoolExecutor(max_workers=64) as executor:
        assert all(executor.map(reject, range(2_048)))
    assert (
        registry.authenticate(f"Bearer {issued.token}", alias="approvals").namespace
        == "profile:test"
    )


@pytest.mark.parametrize(
    "token",
    [
        "sgt_short.secret",
        f"sgt_{'a' * 16}.{'b' * 42}",
        f"sgt_{'a' * 16}.{'b' * 44}",
        f"sgt_{'a' * 15}!.{'b' * 43}",
        f"sgt_{'a' * 16}.{'b' * 42}!",
    ],
)
def test_machine_token_format_is_exact(token: str) -> None:
    registry = TokenRegistry()
    with pytest.raises(CredentialError, match="invalid"):
        registry.authenticate(f"Bearer {token}", alias="approvals")


def test_legacy_password_hash_token_records_fail_closed_without_verification() -> None:
    registry = TokenRegistry(
        [
            TokenRecord(
                token_id="abcdefghijklmnop",
                namespace="profile:test",
                allowed_aliases=frozenset({"approvals"}),
                verifier="$argon2id$v=19$m=1073741824,t=99,p=99$invalid$invalid",
            )
        ]
    )
    token = f"sgt_abcdefghijklmnop.{'A' * 43}"
    with pytest.raises(CredentialError, match="invalid"):
        registry.authenticate(f"Bearer {token}", alias="approvals")

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import encode_cbor

from signet.auth import ActionBinding, ProofCapability
from signet.webauthn import (
    FakeAssertion,
    FakeWebAuthnProvider,
    InMemoryWebAuthnRepository,
    InvalidWebAuthnAssertion,
    OfficialWebAuthnProvider,
    VerifiedWebAuthn,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnChallengeRateLimited,
    WebAuthnChallengeUnavailable,
    WebAuthnCredential,
    WebAuthnCredentialUnavailable,
    WebAuthnError,
)

ORIGIN = "https://approval.example.test"
RP_ID = "approval.example.test"
SESSION_ID = "test-preauth-session"
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
RAW_CREDENTIAL_ID = b"explicit-fake-credential"
CREDENTIAL_ID = base64.urlsafe_b64encode(RAW_CREDENTIAL_ID).rstrip(b"=").decode()
TEST_CAPABILITIES = ProofCapability(b"test-only-proof-capability-key-0001")


def credential(**changes: object) -> WebAuthnCredential:
    values: dict[str, object] = {
        "credential_id": CREDENTIAL_ID,
        "user_id": "human",
        "user_handle": b"fake-user-handle",
        "public_key": b"explicit-fake-public-key",
        "sign_count": 7,
        "device_type": "single_device",
        "backed_up": False,
    }
    values.update(changes)
    return WebAuthnCredential(**values)  # type: ignore[arg-type]


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def signed_es256_assertion(
    challenge: bytes,
    *,
    sign_count: int,
) -> tuple[bytes, dict[str, Any]]:
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    cose_public_key = encode_cbor(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    )
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": base64url(challenge),
            "origin": ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    authenticator_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + b"\x05"  # User present and user verified.
        + sign_count.to_bytes(4, "big")
    )
    signature = private_key.sign(
        authenticator_data + hashlib.sha256(client_data).digest(),
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
    )
    return cose_public_key, {
        "id": CREDENTIAL_ID,
        "rawId": CREDENTIAL_ID,
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url(client_data),
            "authenticatorData": base64url(authenticator_data),
            "signature": base64url(signature),
            "userHandle": base64url(b"fake-user-handle"),
        },
    }


def issue_fixture(
    *,
    binding: ActionBinding | None = None,
) -> tuple[
    InMemoryWebAuthnRepository,
    ActionBinding,
    str,
    FakeAssertion,
]:
    selected_binding = binding or ActionBinding("approve", "request-a", 1, HASH_A)
    repository = InMemoryWebAuthnRepository((credential(),))
    issued = WebAuthnChallengeIssuer(repository, rp_id=RP_ID).issue(
        "human",
        selected_binding,
        session_id=SESSION_ID,
        http_method="POST",
        now=1_000,
    )
    challenge = repository.find_challenge(issued.challenge_id)
    assert challenge is not None
    assertion = FakeAssertion(
        credential_id=CREDENTIAL_ID,
        user_handle=b"fake-user-handle",
        challenge=challenge.challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
        new_sign_count=8,
    )
    return repository, selected_binding, issued.challenge_id, assertion


def verifier(repository: InMemoryWebAuthnRepository) -> WebAuthnAssertionVerifier:
    return WebAuthnAssertionVerifier(
        repository,
        rp_id=RP_ID,
        origin=ORIGIN,
        capabilities=TEST_CAPABILITIES,
        provider=FakeWebAuthnProvider(),
        allow_test_provider=True,
    )


def verify_assertion(
    repository: InMemoryWebAuthnRepository,
    assertion: FakeAssertion,
    *,
    challenge_id: str,
    user_id: str,
    binding: ActionBinding,
    now: int,
    session_id: str = SESSION_ID,
    http_method: str = "POST",
) -> VerifiedWebAuthn:
    return verifier(repository).verify(
        assertion,
        challenge_id=challenge_id,
        user_id=user_id,
        binding=binding,
        session_id=session_id,
        http_method=http_method,
        now=now,
    )


def test_challenge_options_require_uv_and_bind_allowed_credentials() -> None:
    repository = InMemoryWebAuthnRepository((credential(),))
    binding = ActionBinding("approve", "request-a", 1, HASH_A)
    issued = WebAuthnChallengeIssuer(repository, rp_id=RP_ID).issue(
        "human",
        binding,
        session_id=SESSION_ID,
        http_method="POST",
        now=1_000,
    )
    options = json.loads(issued.options_json)
    challenge = repository.find_challenge(issued.challenge_id)
    assert challenge is not None

    assert options["rpId"] == RP_ID
    assert options["userVerification"] == "required"
    assert options["allowCredentials"] == [{"id": CREDENTIAL_ID, "type": "public-key"}]
    assert issued.binding == binding
    assert issued.challenge_id not in repr(issued)
    assert repr(challenge.challenge) not in repr(challenge)
    assert options["challenge"] not in repr(issued)
    assert CREDENTIAL_ID not in repr(credential())


def test_valid_fake_assertion_exposes_values_for_atomic_cas_without_consuming() -> None:
    repository, binding, challenge_id, assertion = issue_fixture()
    verified = verify_assertion(
        repository,
        assertion,
        challenge_id=challenge_id,
        user_id="human",
        binding=binding,
        now=1_001,
    )

    assert verified.credential_id == CREDENTIAL_ID
    assert verified.expected_counter == 7
    assert verified.new_counter == 8
    assert verified.expected_backup_eligible is False
    assert verified.new_backup_eligible is False
    assert verified.previous_backed_up is False
    assert verified.new_backed_up is False
    assert verified.challenge_id == challenge_id
    assert len(verified.use_id) == 64
    assert repository.find_challenge(challenge_id).consumed_at is None  # type: ignore[union-attr]


def test_counter_proof_supports_one_compare_and_swap_winner() -> None:
    repository, binding, challenge_id, assertion = issue_fixture()
    proof = verify_assertion(
        repository,
        assertion,
        challenge_id=challenge_id,
        user_id="human",
        binding=binding,
        now=1_001,
    )

    assert repository.update_credential(
        proof.credential_id,
        expected_sign_count=proof.expected_counter,
        new_sign_count=proof.new_counter,
        backed_up=proof.new_backed_up,
    )
    assert not repository.update_credential(
        proof.credential_id,
        expected_sign_count=proof.expected_counter,
        new_sign_count=proof.new_counter,
        backed_up=proof.new_backed_up,
    )


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("outer_type", "not-public-key"),
        ("client_type", "webauthn.create"),
        ("cross_origin", True),
        ("origin", "https://wrong.example.test"),
        ("rp_id", "wrong.example.test"),
        ("user_handle", b"wrong-user"),
        ("user_present", False),
        ("user_verified", False),
        ("new_sign_count", 7),
        ("signature_valid", False),
        ("device_type", "multi_device"),
        ("backed_up", True),
    ],
)
def test_strict_assertion_fields_fail_closed(change: str, value: Any) -> None:
    repository, binding, challenge_id, assertion = issue_fixture()
    hostile = replace(assertion, **{change: value})

    with pytest.raises(WebAuthnError):
        verify_assertion(
            repository,
            hostile,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_001,
        )


@pytest.mark.parametrize(
    "wrong_binding",
    [
        ActionBinding("deny", "request-a", 1, HASH_A),
        ActionBinding("approve", "request-b", 1, HASH_A),
        ActionBinding("approve", "request-a", 2, HASH_A),
        ActionBinding("approve", "request-a", 1, HASH_B),
        ActionBinding("edit", "request-a", 1, HASH_A, HASH_B),
    ],
)
def test_action_version_and_hash_mismatches_reject_before_verification(
    wrong_binding: ActionBinding,
) -> None:
    repository, _, challenge_id, assertion = issue_fixture()

    with pytest.raises(WebAuthnChallengeUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=wrong_binding,
            now=1_001,
        )


@pytest.mark.parametrize(
    "wrong_binding",
    [
        ActionBinding("edit", "request-a", 1, HASH_C, HASH_B),
        ActionBinding("edit", "request-a", 1, HASH_A, HASH_C),
    ],
)
def test_edit_assertion_binds_both_current_and_prospective_hashes(
    wrong_binding: ActionBinding,
) -> None:
    edit_binding = ActionBinding("edit", "request-a", 1, HASH_A, HASH_B)
    repository, _, challenge_id, assertion = issue_fixture(binding=edit_binding)
    with pytest.raises(WebAuthnChallengeUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=wrong_binding,
            now=1_001,
        )


def test_replayed_expired_invalidated_and_wrong_user_challenges_are_rejected() -> None:
    repository, binding, challenge_id, assertion = issue_fixture()
    challenge = repository.find_challenge(challenge_id)
    assert challenge is not None

    assert repository.consume_challenge(challenge_id, now=1_001)
    with pytest.raises(WebAuthnChallengeUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_002,
        )

    repository.replace_challenge(replace(challenge, expires_at=1_001))
    with pytest.raises(WebAuthnChallengeUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_001,
        )

    repository.replace_challenge(replace(challenge, invalidated_at=1_001))
    with pytest.raises(WebAuthnChallengeUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_002,
        )

    repository.replace_challenge(challenge)
    with pytest.raises(WebAuthnChallengeUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="other-user",
            binding=binding,
            now=1_001,
        )


def test_wrong_owner_unknown_and_revoked_credentials_are_rejected() -> None:
    repository, binding, challenge_id, assertion = issue_fixture()
    repository.replace_credential(credential(user_id="other-user"))
    with pytest.raises(WebAuthnCredentialUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_001,
        )

    unknown = replace(assertion, credential_id=base64.urlsafe_b64encode(b"unknown").decode())
    with pytest.raises(InvalidWebAuthnAssertion):
        verify_assertion(
            repository,
            unknown,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_001,
        )

    repository.replace_credential(credential(disabled=True))
    with pytest.raises(WebAuthnCredentialUnavailable):
        verify_assertion(
            repository,
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_001,
        )


def test_backup_eligibility_and_state_rollback_are_rejected() -> None:
    repository, binding, challenge_id, assertion = issue_fixture()
    repository.replace_credential(credential(device_type="multi_device", backed_up=True))
    rollback = replace(assertion, device_type="multi_device", backed_up=False)
    with pytest.raises(InvalidWebAuthnAssertion):
        verify_assertion(
            repository,
            rollback,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            now=1_001,
        )


def test_challenge_flooding_is_bounded_per_user() -> None:
    repository = InMemoryWebAuthnRepository((credential(),))
    issuer = WebAuthnChallengeIssuer(repository, rp_id=RP_ID, max_active_per_user=2)
    binding = ActionBinding("login")
    issuer.issue("human", binding, session_id=SESSION_ID, http_method="POST", now=1_000)
    issuer.issue("human", binding, session_id=SESSION_ID, http_method="POST", now=1_000)
    with pytest.raises(WebAuthnChallengeRateLimited):
        issuer.issue("human", binding, session_id=SESSION_ID, http_method="POST", now=1_000)


def test_fake_provider_requires_opt_in_and_official_provider_rejects_fake_assertions() -> None:
    repository, binding, challenge_id, assertion = issue_fixture()
    with pytest.raises(ValueError, match="explicit test opt-in"):
        WebAuthnAssertionVerifier(
            repository,
            rp_id=RP_ID,
            origin=ORIGIN,
            capabilities=TEST_CAPABILITIES,
            provider=FakeWebAuthnProvider(),
        )

    production = WebAuthnAssertionVerifier(
        repository,
        rp_id=RP_ID,
        origin=ORIGIN,
        capabilities=TEST_CAPABILITIES,
        provider=OfficialWebAuthnProvider(),
    )
    with pytest.raises(InvalidWebAuthnAssertion):
        production.verify(
            assertion,
            challenge_id=challenge_id,
            user_id="human",
            binding=binding,
            session_id=SESSION_ID,
            http_method="POST",
            now=1_001,
        )


def test_webauthn_verifier_requires_explicit_capabilities() -> None:
    with pytest.raises(TypeError):
        WebAuthnAssertionVerifier(  # type: ignore[call-arg]
            InMemoryWebAuthnRepository((credential(),)),
            rp_id=RP_ID,
            origin=ORIGIN,
        )


def test_official_provider_verifies_real_es256_assertion_and_rejects_tampering() -> None:
    public_key, _ = signed_es256_assertion(b"fixture-challenge" * 2, sign_count=8)
    repository = InMemoryWebAuthnRepository((credential(public_key=public_key),))
    binding = ActionBinding("approve", "request-a", 1, HASH_A)
    issued = WebAuthnChallengeIssuer(repository, rp_id=RP_ID).issue(
        "human",
        binding,
        session_id=SESSION_ID,
        http_method="POST",
        now=1_000,
    )
    challenge = repository.find_challenge(issued.challenge_id)
    assert challenge is not None
    matching_public_key, assertion = signed_es256_assertion(
        challenge.challenge,
        sign_count=8,
    )
    assert matching_public_key == public_key
    production = WebAuthnAssertionVerifier(
        repository,
        rp_id=RP_ID,
        origin=ORIGIN,
        capabilities=TEST_CAPABILITIES,
    )

    verified = production.verify(
        assertion,
        challenge_id=issued.challenge_id,
        user_id="human",
        binding=binding,
        session_id=SESSION_ID,
        http_method="POST",
        now=1_001,
    )
    assert verified.credential_id == CREDENTIAL_ID
    assert verified.expected_counter == 7
    assert verified.new_counter == 8

    encoded_signature = assertion["response"]["signature"]
    signature = bytearray(
        base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
    )
    signature[-1] ^= 1
    tampered = {
        **assertion,
        "response": {
            **assertion["response"],
            "signature": base64url(bytes(signature)),
        },
    }
    with pytest.raises(InvalidWebAuthnAssertion):
        production.verify(
            tampered,
            challenge_id=issued.challenge_id,
            user_id="human",
            binding=binding,
            session_id=SESSION_ID,
            http_method="POST",
            now=1_001,
        )


def test_origin_and_rp_configuration_must_be_exact_https_scope() -> None:
    repository = InMemoryWebAuthnRepository((credential(),))
    with pytest.raises(ValueError, match="HTTPS"):
        WebAuthnAssertionVerifier(
            repository,
            rp_id=RP_ID,
            origin="http://example.test",
            capabilities=TEST_CAPABILITIES,
        )
    with pytest.raises(ValueError, match="exactly match"):
        WebAuthnAssertionVerifier(
            repository,
            rp_id="other.test",
            origin=ORIGIN,
            capabilities=TEST_CAPABILITIES,
        )
    with pytest.raises(ValueError, match="exactly match"):
        WebAuthnAssertionVerifier(
            repository,
            rp_id=RP_ID,
            origin=f"https://subdomain.{RP_ID}",
            capabilities=TEST_CAPABILITIES,
        )
    with pytest.raises(ValueError, match="HTTPS"):
        WebAuthnAssertionVerifier(
            repository,
            rp_id=RP_ID,
            origin=f"{ORIGIN}/",
            capabilities=TEST_CAPABILITIES,
        )
    with pytest.raises(ValueError, match="canonical hostname"):
        WebAuthnAssertionVerifier(
            repository,
            rp_id="EXAMPLE.TEST",
            origin=ORIGIN,
            capabilities=TEST_CAPABILITIES,
        )


def test_invalid_credential_shape_is_rejected() -> None:
    with pytest.raises(ValueError, match="canonical base64url"):
        credential(credential_id="not+padded=")
    with pytest.raises(ValueError, match="single-device"):
        credential(backed_up=True)

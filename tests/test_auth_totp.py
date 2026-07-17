from __future__ import annotations

from dataclasses import dataclass

import pytest

from signet.auth import (
    ActionBinding,
    AuthenticationRateLimited,
    InMemoryAttemptLimiter,
    ProofCapability,
    totp_rate_limit_key,
)
from signet.credential_broker import MemorySecretStore, Secret
from signet.totp import (
    FakeTotpProvider,
    InvalidTotp,
    PyotpTotpProvider,
    TotpCredential,
    TotpNotEnrolled,
    TotpUnavailable,
    TotpVerifier,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
TEST_CAPABILITIES = ProofCapability(b"test-only-proof-capability-key-0001")


@dataclass
class TotpRepository:
    credentials: dict[str, TotpCredential | tuple[TotpCredential, ...]]

    def active_totps(self, user_id: str) -> tuple[TotpCredential, ...]:
        credentials = self.credentials.get(user_id)
        if credentials is None:
            return ()
        if isinstance(credentials, TotpCredential):
            return (credentials,)
        return credentials


def repository() -> TotpRepository:
    return TotpRepository(
        {
            "human": TotpCredential(
                credential_id="totp-main",
                user_id="human",
                secret_reference="keychain://Signet/test-totp",
            )
        }
    )


def secret_store() -> MemorySecretStore:
    return MemorySecretStore({("Signet", "test-totp"): "fake-secret-material"})


def verifier(
    limiter: InMemoryAttemptLimiter | None = None,
    *,
    proof: str = "fake:accepted",
) -> TotpVerifier:
    return TotpVerifier(
        repository(),
        secret_store(),
        limiter or InMemoryAttemptLimiter(),
        capabilities=TEST_CAPABILITIES,
        provider=FakeTotpProvider(proof, step=77),
        allow_test_provider=True,
    )


def test_fake_totp_requires_explicit_opt_in() -> None:
    with pytest.raises(ValueError, match="explicit test opt-in"):
        TotpVerifier(
            repository(),
            secret_store(),
            InMemoryAttemptLimiter(),
            capabilities=TEST_CAPABILITIES,
            provider=FakeTotpProvider(),
        )


def test_totp_verifier_requires_explicit_capabilities() -> None:
    with pytest.raises(TypeError):
        TotpVerifier(  # type: ignore[call-arg]
            repository(),
            secret_store(),
            InMemoryAttemptLimiter(),
        )


def test_fake_totp_returns_an_action_bound_opaque_use_id() -> None:
    selected = verifier()
    binding_a = ActionBinding("approve", "request-a", 1, HASH_A)
    binding_b = ActionBinding("approve", "request-b", 2, HASH_B)

    first = selected.verify("human", "fake:accepted", binding=binding_a, now=1_000)
    second = selected.verify("human", "fake:accepted", binding=binding_b, now=1_000)

    assert first.binding == binding_a
    assert second.binding == binding_b
    assert first.use_id == second.use_id
    assert "fake:accepted" not in first.use_id
    assert len(first.use_id) == 64


def test_valid_proof_clears_failures_only_after_atomic_consumption() -> None:
    limiter = InMemoryAttemptLimiter(lock_schedule=((3, 10),))
    selected = verifier(limiter)
    binding = ActionBinding("approve", "request-a", 1, HASH_A)
    with pytest.raises(InvalidTotp):
        selected.verify("human", "fake:wrong", binding=binding, now=1_000)

    proof = selected.verify("human", "fake:accepted", binding=binding, now=1_001)
    key = totp_rate_limit_key("human")
    assert limiter.state(key).failures == 2
    selected.record_consumed_success(proof, now=1_001)
    assert limiter.state(key).failures == 0


def test_totp_rate_limit_is_shared_between_web_and_mcp_verifiers() -> None:
    limiter = InMemoryAttemptLimiter(lock_schedule=((2, 10),))
    web = verifier(limiter)
    mcp = verifier(limiter)
    binding = ActionBinding("approve", "request-a", 1, HASH_A)

    with pytest.raises(InvalidTotp):
        web.verify("human", "fake:wrong", binding=binding, now=1_000)
    with pytest.raises(InvalidTotp):
        mcp.verify("human", "fake:wrong", binding=binding, now=1_001)
    with pytest.raises(AuthenticationRateLimited):
        web.verify("human", "fake:accepted", binding=binding, now=1_002)


def test_totp_unenrolled_and_unavailable_are_distinct_from_invalid() -> None:
    binding = ActionBinding("approve", "request-a", 1, HASH_A)
    unenrolled = TotpVerifier(
        TotpRepository({}),
        secret_store(),
        InMemoryAttemptLimiter(),
        capabilities=TEST_CAPABILITIES,
        provider=FakeTotpProvider(),
        allow_test_provider=True,
    )
    with pytest.raises(TotpNotEnrolled, match="authenticated web app"):
        unenrolled.verify("human", "fake:any", binding=binding, now=1_000)

    unavailable = TotpVerifier(
        repository(),
        MemorySecretStore({}),
        InMemoryAttemptLimiter(),
        capabilities=TEST_CAPABILITIES,
        provider=FakeTotpProvider(),
        allow_test_provider=True,
    )
    with pytest.raises(TotpUnavailable, match="unavailable"):
        unavailable.verify("human", "fake:any", binding=binding, now=1_000)

    wrong_owner = TotpVerifier(
        TotpRepository(
            {
                "human": TotpCredential(
                    credential_id="totp-other",
                    user_id="other",
                    secret_reference="keychain://Signet/test-totp",
                )
            }
        ),
        secret_store(),
        InMemoryAttemptLimiter(),
        capabilities=TEST_CAPABILITIES,
        provider=FakeTotpProvider(),
        allow_test_provider=True,
    )
    with pytest.raises(TotpNotEnrolled):
        wrong_owner.verify("human", "fake:any", binding=binding, now=1_000)


def test_totp_verifier_accepts_any_active_factor_and_skips_unavailable_factors() -> None:
    class PerSecretProvider:
        test_only = True

        def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None:
            del now
            if secret.reveal() == "second-secret" and proof == "fake:second":
                return 81
            return None

    credentials = (
        TotpCredential("totp-first", "human", "keychain://Signet/missing-totp"),
        TotpCredential("totp-second", "human", "keychain://Signet/second-totp"),
    )
    selected = TotpVerifier(
        TotpRepository({"human": credentials}),
        MemorySecretStore({("Signet", "second-totp"): "second-secret"}),
        InMemoryAttemptLimiter(),
        capabilities=TEST_CAPABILITIES,
        provider=PerSecretProvider(),
        allow_test_provider=True,
    )

    proof = selected.verify(
        "human",
        "fake:second",
        binding=ActionBinding("approve", "request-a", 1, HASH_A),
        now=1_000,
    )

    assert proof.credential_id == "totp-second"


def test_production_provider_rejects_non_authenticator_shaped_proof() -> None:
    provider = PyotpTotpProvider()
    assert (
        provider.verify_step(Secret("not-authenticator-material"), "fake:proof", now=1_000) is None
    )


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ],
)
def test_production_provider_matches_rfc6238_sha1_vectors(
    timestamp: int,
    expected: str,
) -> None:
    provider = PyotpTotpProvider(digits=8, valid_window=0)
    secret = Secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

    assert provider.verify_step(secret, expected, now=timestamp) == timestamp // 30


def test_totp_objects_redact_secret_locations_and_fake_proofs() -> None:
    credential = repository().credentials["human"]
    assert "test-totp" not in repr(credential)
    assert "fake:accepted" not in repr(FakeTotpProvider("fake:accepted"))

    proof = verifier().verify(
        "human",
        "fake:accepted",
        binding=ActionBinding("approve", "request-a", 1, HASH_A),
        now=1_000,
    )
    rendered = repr(proof)
    assert proof.use_id not in rendered
    assert proof.credential_id not in rendered
    assert proof.attempt_reservation.attempt_id not in rendered

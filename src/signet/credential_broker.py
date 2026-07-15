"""Secret references, macOS Keychain access, and profile-scoped agent tokens."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

import keyring


class CredentialError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class Secret:
    _value: str

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class SecretReference:
    service: str
    account: str

    @classmethod
    def parse(cls, reference: str) -> SecretReference:
        parsed = urlparse(reference)
        if parsed.scheme != "keychain" or not parsed.netloc:
            raise CredentialError("secret reference must use keychain://service/account")
        account = parsed.path.removeprefix("/")
        if not account or "/" in account or parsed.params or parsed.query or parsed.fragment:
            raise CredentialError("invalid keychain secret reference")
        return cls(service=parsed.netloc, account=account)


class SecretStore(Protocol):
    def get(self, reference: SecretReference) -> Secret: ...


class KeychainSecretStore:
    """Use the platform keyring; on macOS its backend is the login Keychain."""

    def get(self, reference: SecretReference) -> Secret:
        try:
            value = keyring.get_password(reference.service, reference.account)
        except Exception as exc:  # keyring backends intentionally vary by platform
            raise CredentialError("the configured Keychain secret is unavailable") from exc
        if value is None:
            raise CredentialError("the configured Keychain secret is unavailable")
        return Secret(value)


class MemorySecretStore:
    """Test-only store. Values remain redacted in all representations."""

    def __init__(self, values: dict[tuple[str, str], str]) -> None:
        self._values = dict(values)

    def get(self, reference: SecretReference) -> Secret:
        try:
            return Secret(self._values[(reference.service, reference.account)])
        except KeyError as exc:
            raise CredentialError("the configured Keychain secret is unavailable") from exc

    def __repr__(self) -> str:
        return f"MemorySecretStore(entries={len(self._values)}, values=<redacted>)"


@dataclass(frozen=True, slots=True)
class CallerPrincipal:
    """One profile-level namespace shared by that profile's alias tokens."""

    namespace: str
    allowed_aliases: frozenset[str]
    token_id: str


@dataclass(frozen=True, slots=True, repr=False)
class IssuedToken:
    token_id: str
    token: str

    def __repr__(self) -> str:
        return f"IssuedToken(token_id={self.token_id!r}, token=<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class TokenRecord:
    token_id: str
    namespace: str
    allowed_aliases: frozenset[str]
    verifier: str
    revoked: bool = False


class TokenRegistry:
    """Registry for high-entropy machine tokens returned only once."""

    def __init__(self, records: Iterable[TokenRecord] = ()) -> None:
        self._records = {record.token_id: record for record in records}

    def issue(self, namespace: str, allowed_aliases: Iterable[str]) -> IssuedToken:
        aliases = frozenset(allowed_aliases)
        if not namespace or not aliases or any(not alias for alias in aliases):
            raise CredentialError("namespace and at least one alias are required")
        token_id = secrets.token_urlsafe(12)
        while token_id in self._records:
            token_id = secrets.token_urlsafe(12)
        raw_secret = secrets.token_urlsafe(32)
        raw_token = f"sgt_{token_id}.{raw_secret}"
        self._records[token_id] = TokenRecord(
            token_id=token_id,
            namespace=namespace,
            allowed_aliases=aliases,
            verifier=_encode_machine_token_verifier(raw_token),
        )
        return IssuedToken(token_id=token_id, token=raw_token)

    def export_records(self) -> tuple[TokenRecord, ...]:
        return tuple(self._records.values())

    def authenticate(self, authorization: str | None, *, alias: str) -> CallerPrincipal:
        if not authorization or not authorization.startswith("Bearer "):
            raise CredentialError("bearer authentication is required")
        raw_token = authorization.removeprefix("Bearer ")
        match = _MACHINE_TOKEN_PATTERN.fullmatch(raw_token)
        if match is None:
            raise CredentialError("invalid bearer token")
        token_id = match.group("token_id")
        record = self._records.get(token_id)
        actual = hashlib.sha256(raw_token.encode("ascii")).digest()
        expected = _decode_machine_token_verifier(record.verifier if record is not None else "")
        secret_matches = hmac.compare_digest(actual, expected)
        if (
            record is None
            or record.revoked
            or alias not in record.allowed_aliases
            or not secret_matches
        ):
            raise CredentialError("invalid bearer token")
        return CallerPrincipal(
            namespace=record.namespace,
            allowed_aliases=record.allowed_aliases,
            token_id=record.token_id,
        )

    def revoke(self, token_id: str) -> None:
        record = self._records.get(token_id)
        if record is None:
            return
        self._records[token_id] = TokenRecord(
            token_id=record.token_id,
            namespace=record.namespace,
            allowed_aliases=record.allowed_aliases,
            verifier=record.verifier,
            revoked=True,
        )


_MACHINE_TOKEN_PATTERN = re.compile(r"^sgt_(?P<token_id>[A-Za-z0-9_-]{16})\.[A-Za-z0-9_-]{43}$")
_MACHINE_TOKEN_VERIFIER_PREFIX = "sha256$"


def _encode_machine_token_verifier(raw_token: str) -> str:
    return _MACHINE_TOKEN_VERIFIER_PREFIX + hashlib.sha256(raw_token.encode("ascii")).hexdigest()


def _decode_machine_token_verifier(verifier: str) -> bytes:
    if not verifier.startswith(_MACHINE_TOKEN_VERIFIER_PREFIX):
        return bytes(hashlib.sha256().digest_size)
    encoded = verifier.removeprefix(_MACHINE_TOKEN_VERIFIER_PREFIX)
    if len(encoded) != hashlib.sha256().digest_size * 2:
        return bytes(hashlib.sha256().digest_size)
    try:
        return bytes.fromhex(encoded)
    except ValueError:
        return bytes(hashlib.sha256().digest_size)

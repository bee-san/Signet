"""Secret references, macOS Keychain access, and profile-scoped agent tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Iterable
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol
from urllib.parse import urlparse

import keyring

from signet.db import Database, IntegrityError


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


@dataclass(frozen=True, slots=True, repr=False)
class TokenRecord:
    token_id: str
    namespace: str
    allowed_aliases: frozenset[str]
    verifier: str
    revoked: bool = False

    def __repr__(self) -> str:
        return (
            "TokenRecord("
            f"token_id={self.token_id!r}, namespace={self.namespace!r}, "
            f"allowed_aliases={self.allowed_aliases!r}, verifier=<redacted>, "
            f"revoked={self.revoked!r})"
        )


@dataclass(frozen=True, slots=True)
class StoredTokenMetadata:
    """Non-secret operator metadata for one durable MCP caller token."""

    token_id: str
    namespace: str
    allowed_aliases: tuple[str, ...]
    created_at: int
    revoked_at: int | None
    rotation_of_token_id: str | None


class TokenRegistry:
    """Registry for high-entropy machine tokens returned only once."""

    def __init__(self, records: Iterable[TokenRecord] = ()) -> None:
        self._records = {record.token_id: record for record in records}

    def issue(self, namespace: str, allowed_aliases: Iterable[str]) -> IssuedToken:
        aliases = frozenset(allowed_aliases)
        if not namespace or not aliases or any(not alias for alias in aliases):
            raise CredentialError("namespace and at least one alias are required")
        token_id = _new_token_id()
        while token_id in self._records:
            token_id = _new_token_id()
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


class SQLiteTokenRegistry(TokenRegistry):
    """Durable caller tokens whose revocation is checked on every authentication."""

    def __init__(
        self,
        database: Database,
        *,
        allowed_principals: MappingABC[str, Iterable[str]] | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        super().__init__()
        self._database = database
        self._clock = clock or (lambda: int(time.time()))
        if allowed_principals is None:
            self._allowed_principals: MappingABC[str, frozenset[str]] | None = None
        else:
            principals: dict[str, frozenset[str]] = {}
            for namespace, aliases in allowed_principals.items():
                selected_namespace = _validate_machine_namespace(namespace)
                selected_aliases = _validate_machine_aliases(aliases)
                if selected_namespace in principals:
                    raise CredentialError("caller namespaces must be unique")
                principals[selected_namespace] = selected_aliases
            self._allowed_principals = MappingProxyType(principals)

    def issue(self, namespace: str, allowed_aliases: Iterable[str]) -> IssuedToken:
        selected_namespace = _validate_machine_namespace(namespace)
        aliases = _validate_machine_aliases(allowed_aliases)
        self._require_configured_principal(selected_namespace, aliases)
        now = self._now()
        for _ in range(8):
            issued = _new_machine_token()
            try:
                with self._database.transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO mcp_caller_tokens(
                            token_id, origin_namespace, verifier,
                            allowed_aliases_json, created_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            issued.token_id,
                            selected_namespace,
                            _encode_machine_token_verifier(issued.token),
                            _aliases_json(aliases),
                            now,
                        ),
                    )
                return issued
            except IntegrityError:
                continue
        raise CredentialError("could not allocate a unique caller token ID")

    def authenticate(self, authorization: str | None, *, alias: str) -> CallerPrincipal:
        raw_token, token_id = _parse_machine_authorization(authorization)
        row: Any | None = None
        if token_id is not None:
            with self._database.read() as connection:
                row = connection.execute(
                    """
                    SELECT token_id, origin_namespace, verifier, allowed_aliases_json,
                           revoked_at
                    FROM mcp_caller_tokens
                    WHERE token_id = ?
                    """,
                    (token_id,),
                ).fetchone()
        record = _stored_token_record(row)
        if record is not None and self._allowed_principals is not None:
            configured = self._allowed_principals.get(record.namespace)
            if configured != record.allowed_aliases:
                record = None
        registry = TokenRegistry(() if record is None else (record,))
        principal = registry.authenticate(
            None if raw_token is None else f"Bearer {raw_token}",
            alias=alias,
        )
        with self._database.read() as connection:
            current_row = connection.execute(
                """
                SELECT token_id, origin_namespace, verifier, allowed_aliases_json,
                       revoked_at
                FROM mcp_caller_tokens
                WHERE token_id = ?
                """,
                (principal.token_id,),
            ).fetchone()
        if _stored_token_record(current_row) != record:
            raise CredentialError("invalid bearer token")
        return principal

    def export_records(self) -> tuple[TokenRecord, ...]:
        raise CredentialError("durable caller token verifiers are not exportable")

    def list_metadata(self) -> tuple[StoredTokenMetadata, ...]:
        with self._database.read() as connection:
            rows = connection.execute(
                """
                SELECT token_id, origin_namespace, allowed_aliases_json, created_at,
                       revoked_at, rotation_of_token_id
                FROM mcp_caller_tokens
                ORDER BY created_at, token_id
                """
            ).fetchall()
        return tuple(_stored_token_metadata(row) for row in rows)

    def revoke(self, token_id: str) -> None:
        _validate_token_id(token_id)
        now = self._now()
        with self._database.transaction() as connection:
            connection.execute(
                """
                UPDATE mcp_caller_tokens
                SET revoked_at = COALESCE(revoked_at, max(created_at, ?))
                WHERE token_id = ?
                """,
                (now, token_id),
            )

    def rotate(self, token_id: str) -> IssuedToken:
        _validate_token_id(token_id)
        now = self._now()
        for _ in range(8):
            replacement = _new_machine_token()
            try:
                with self._database.transaction() as connection:
                    row = connection.execute(
                        """
                        SELECT origin_namespace, allowed_aliases_json, created_at, revoked_at
                        FROM mcp_caller_tokens
                        WHERE token_id = ?
                        """,
                        (token_id,),
                    ).fetchone()
                    if row is None:
                        raise CredentialError("caller token ID does not exist")
                    if row["revoked_at"] is not None:
                        raise CredentialError("caller token is already revoked")
                    pending = connection.execute(
                        """
                        SELECT 1 FROM mcp_caller_tokens
                        WHERE rotation_of_token_id = ? AND revoked_at IS NULL
                        """,
                        (token_id,),
                    ).fetchone()
                    if pending is not None:
                        raise CredentialError(
                            "caller token already has an active replacement; "
                            "install it or revoke it before retrying"
                        )
                    namespace = _validate_machine_namespace(str(row["origin_namespace"]))
                    aliases = _decode_machine_aliases(str(row["allowed_aliases_json"]))
                    self._require_configured_principal(namespace, aliases)
                    transition_time = max(now, int(row["created_at"]))
                    connection.execute(
                        """
                        INSERT INTO mcp_caller_tokens(
                            token_id, origin_namespace, verifier,
                            allowed_aliases_json, created_at, rotation_of_token_id
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            replacement.token_id,
                            namespace,
                            _encode_machine_token_verifier(replacement.token),
                            _aliases_json(aliases),
                            transition_time,
                            token_id,
                        ),
                    )
                return replacement
            except IntegrityError:
                continue
        raise CredentialError("could not allocate a unique caller token ID")

    def metadata(self, token_id: str) -> StoredTokenMetadata | None:
        _validate_token_id(token_id)
        with self._database.read() as connection:
            row = connection.execute(
                """
                SELECT token_id, origin_namespace, allowed_aliases_json, created_at,
                       revoked_at, rotation_of_token_id
                FROM mcp_caller_tokens
                WHERE token_id = ?
                """,
                (token_id,),
            ).fetchone()
        return None if row is None else _stored_token_metadata(row)

    def _require_configured_principal(self, namespace: str, aliases: frozenset[str]) -> None:
        if self._allowed_principals is None:
            return
        if self._allowed_principals.get(namespace) != aliases:
            raise CredentialError("namespace and aliases do not match the deployment config")

    def _now(self) -> int:
        value = self._clock()
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CredentialError("the caller token clock is invalid")
        return value


_MACHINE_TOKEN_PATTERN = re.compile(r"^sgt_(?P<token_id>[A-Za-z0-9_-]{16})\.[A-Za-z0-9_-]{43}$")
_MACHINE_TOKEN_VERIFIER_PREFIX = "sha256$"
_MACHINE_TOKEN_VERIFIER_PATTERN = re.compile(r"^sha256\$[0-9a-f]{64}$")
_MACHINE_ALIAS_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MACHINE_NAMESPACE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


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


def _new_machine_token() -> IssuedToken:
    token_id = _new_token_id()
    raw_secret = secrets.token_urlsafe(32)
    return IssuedToken(token_id=token_id, token=f"sgt_{token_id}.{raw_secret}")


def _new_token_id() -> str:
    # A leading '-' is ambiguous to command-line parsers when operators rotate it.
    first = secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    return first + secrets.token_urlsafe(12)[1:]


def _parse_machine_authorization(
    authorization: str | None,
) -> tuple[str | None, str | None]:
    if not authorization or not authorization.startswith("Bearer "):
        return None, None
    raw_token = authorization.removeprefix("Bearer ")
    match = _MACHINE_TOKEN_PATTERN.fullmatch(raw_token)
    return raw_token, (match.group("token_id") if match is not None else None)


def _validate_machine_namespace(namespace: str) -> str:
    if _MACHINE_NAMESPACE_PATTERN.fullmatch(namespace) is None:
        raise CredentialError("invalid caller namespace")
    return namespace


def _validate_machine_aliases(aliases: Iterable[str]) -> frozenset[str]:
    values = tuple(aliases)
    selected = frozenset(values)
    if (
        not values
        or len(values) != len(selected)
        or len(values) > 16
        or any(_MACHINE_ALIAS_PATTERN.fullmatch(alias) is None for alias in values)
    ):
        raise CredentialError("invalid or duplicate caller aliases")
    return selected


def _validate_token_id(token_id: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]{16}", token_id) is None:
        raise CredentialError("invalid caller token ID")
    return token_id


def _aliases_json(aliases: Iterable[str]) -> str:
    selected = _validate_machine_aliases(aliases)
    return json.dumps(sorted(selected), separators=(",", ":"))


def _decode_machine_aliases(encoded: str) -> frozenset[str]:
    try:
        value = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeError):
        raise CredentialError("stored caller token aliases are invalid") from None
    if not isinstance(value, list) or any(not isinstance(alias, str) for alias in value):
        raise CredentialError("stored caller token aliases are invalid")
    return _validate_machine_aliases(value)


def _stored_token_record(row: Any | None) -> TokenRecord | None:
    if row is None:
        return None
    try:
        token_id = _validate_token_id(str(row["token_id"]))
        namespace = _validate_machine_namespace(str(row["origin_namespace"]))
        aliases = _decode_machine_aliases(str(row["allowed_aliases_json"]))
        verifier = str(row["verifier"])
        if _MACHINE_TOKEN_VERIFIER_PATTERN.fullmatch(verifier) is None:
            raise CredentialError("stored caller token verifier is invalid")
        return TokenRecord(
            token_id=token_id,
            namespace=namespace,
            allowed_aliases=aliases,
            verifier=verifier,
            revoked=row["revoked_at"] is not None,
        )
    except (CredentialError, KeyError, TypeError, ValueError):
        return None


def _stored_token_metadata(row: Any) -> StoredTokenMetadata:
    try:
        token_id = _validate_token_id(str(row["token_id"]))
        namespace = _validate_machine_namespace(str(row["origin_namespace"]))
        aliases = tuple(sorted(_decode_machine_aliases(str(row["allowed_aliases_json"]))))
        created_at = int(row["created_at"])
        revoked_at = None if row["revoked_at"] is None else int(row["revoked_at"])
        rotation_of = row["rotation_of_token_id"]
        rotation_of_id = None if rotation_of is None else _validate_token_id(str(rotation_of))
        if created_at < 0:
            raise ValueError
    except (CredentialError, KeyError, TypeError, ValueError):
        raise CredentialError("stored caller token metadata is invalid") from None
    return StoredTokenMetadata(
        token_id=token_id,
        namespace=namespace,
        allowed_aliases=aliases,
        created_at=created_at,
        revoked_at=revoked_at,
        rotation_of_token_id=rotation_of_id,
    )

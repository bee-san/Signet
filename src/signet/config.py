"""Non-secret runtime configuration."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from signet.auth import canonical_user_id
from signet.credential_broker import CredentialError, SecretReference
from signet.private_paths import PrivatePathError, ensure_private_directory


class DownstreamConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: Literal["http", "stdio"]
    credential_ref: str
    credential_identity_digest: str
    url: str | None = None
    command: tuple[str, ...] = ()
    working_directory: Path | None = None
    executable_sha256: str | None = None
    execution_snapshot_root: Path | None = None
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    output_limit_bytes: int = Field(default=1_048_576, gt=0, le=16_777_216)

    @field_validator("credential_ref")
    @classmethod
    def credential_is_reference_only(cls, value: str) -> str:
        if not value.startswith("keychain://"):
            raise ValueError("downstream credentials must use keychain:// references")
        return value

    @field_validator("credential_identity_digest")
    @classmethod
    def credential_identity_is_inventory_generation(cls, value: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("credential identity must be a lowercase SHA-256 inventory digest")
        return value

    @field_validator("executable_sha256")
    @classmethod
    def executable_digest_is_exact(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("stdio executable digest must be a lowercase SHA-256")
        return value


class Settings(BaseSettings):
    """Configuration is intentionally unable to carry secret values."""

    model_config = SettingsConfigDict(
        env_prefix="SIGNET_",
        extra="forbid",
        case_sensitive=False,
    )

    data_dir: Path = Path("~/.hermes/services/signet/data").expanduser()
    policy_path: Path = Path("~/.hermes/services/signet/config/policy.yaml").expanduser()
    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8789, ge=1024, le=65535)
    web_host: str = "127.0.0.1"
    web_port: int = Field(default=8790, ge=1024, le=65535)
    public_origin: str = "https://signet.invalid"
    rp_id: str = "signet.invalid"
    allowed_hosts: tuple[str, ...] = ("signet.invalid", "127.0.0.1", "localhost")
    session_secret_ref: str = "keychain://Signet/web-session"
    payload_key_ref: str = "keychain://Signet/payload-encryption"
    totp_secret_ref: str = "keychain://Signet/totp"
    vapid_private_key_ref: str = "keychain://Signet/vapid-private"
    vapid_public_key: str = ""
    pending_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=300, le=30 * 24 * 3600)
    queue_limit: int = Field(default=1000, ge=1, le=100_000)
    minimum_free_bytes: int = Field(default=100 * 1024 * 1024, ge=0)
    development_fake_providers: bool = False

    @field_validator(
        "session_secret_ref", "payload_key_ref", "totp_secret_ref", "vapid_private_key_ref"
    )
    @classmethod
    def secret_fields_are_references(cls, value: str) -> str:
        if not value.startswith("keychain://"):
            raise ValueError("secret configuration must contain a keychain:// reference")
        return value

    @field_validator("public_origin")
    @classmethod
    def origin_requires_https(cls, value: str) -> str:
        if not value.startswith("https://") or value.endswith("/"):
            raise ValueError("public_origin must be an HTTPS origin without a trailing slash")
        return value

    def prepare_directories(self) -> None:
        try:
            ensure_private_directory(self.data_dir)
        except PrivatePathError as exc:
            raise ValueError("data_dir must be an owned mode-0700 directory") from exc

    def safe_dump(self) -> dict[str, object]:
        data = self.model_dump(mode="json")
        for field in (
            "session_secret_ref",
            "payload_key_ref",
            "totp_secret_ref",
            "vapid_private_key_ref",
        ):
            data[field] = "<secret-reference>"
        data["vapid_public_key"] = "<configured>" if self.vapid_public_key else "<unset>"
        return data


class ProductionStorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data_dir: Path
    backup_dir: Path
    restore_dir: Path

    @field_validator("data_dir", "backup_dir", "restore_dir", mode="before")
    @classmethod
    def paths_are_absolute_and_lexical(cls, value: Any) -> Any:
        if isinstance(value, str):
            path = Path(value)
            if not path.is_absolute() or "\x00" in value or ".." in path.parts:
                raise ValueError("production storage paths must be absolute lexical paths")
        return value

    @model_validator(mode="after")
    def paths_are_distinct(self) -> Self:
        paths = (self.data_dir, self.backup_dir, self.restore_dir)
        if any(not path.is_absolute() or ".." in path.parts for path in paths):
            raise ValueError("production storage paths must be absolute lexical paths")
        if len(set(paths)) != len(paths):
            raise ValueError("production storage paths must be distinct")
        if any(
            left.is_relative_to(right) or right.is_relative_to(left)
            for index, left in enumerate(paths)
            for right in paths[index + 1 :]
        ):
            raise ValueError("production storage paths must not overlap")
        return self

    def prepare_directories(self) -> None:
        for path in (self.data_dir, self.backup_dir, self.restore_dir):
            try:
                ensure_private_directory(path)
            except PrivatePathError as exc:
                raise ValueError(
                    "production storage paths must be owned mode-0700 directories"
                ) from exc

    @property
    def database_path(self) -> Path:
        return self.data_dir / "signet.db"


class ProductionSecretsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_secret_ref: str
    csrf_secret_ref: str
    capability_key_ref: str
    payload_key_ref: str
    totp_secret_ref: str | None = None
    vapid_private_key_ref: str | None = None

    @field_validator(
        "session_secret_ref",
        "csrf_secret_ref",
        "capability_key_ref",
        "payload_key_ref",
        "totp_secret_ref",
        "vapid_private_key_ref",
    )
    @classmethod
    def secret_fields_are_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            SecretReference.parse(value)
        except CredentialError as exc:
            raise ValueError("secret configuration must contain a keychain:// reference") from exc
        return value


class ProductionCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    storage_ready: bool
    secret_broker_ready: bool
    mcp_ready: bool
    web_ready: bool
    workers_ready: bool
    policy_ready: bool
    live_providers_ready: bool

    @model_validator(mode="after")
    def live_provider_cutover_is_not_available(self) -> Self:
        if self.live_providers_ready:
            raise ValueError("live provider cutover is not implemented by this production slice")
        return self

    @property
    def ready(self) -> bool:
        return all(
            (
                self.storage_ready,
                self.secret_broker_ready,
                self.mcp_ready,
                self.web_ready,
                self.workers_ready,
                self.policy_ready,
                self.live_providers_ready,
            )
        )

    @property
    def missing_prerequisites(self) -> tuple[str, ...]:
        return tuple(
            field
            for field, value in (
                ("storage_ready", self.storage_ready),
                ("secret_broker_ready", self.secret_broker_ready),
                ("mcp_ready", self.mcp_ready),
                ("web_ready", self.web_ready),
                ("workers_ready", self.workers_ready),
                ("policy_ready", self.policy_ready),
                ("live_providers_ready", self.live_providers_ready),
            )
            if not value
        )


class ProductionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    mode: Literal["production"] = "production"
    owner_user_id: str
    public_origin: str
    rp_id: str
    allowed_hosts: tuple[str, ...]
    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8789, ge=1024, le=65535)
    web_host: str = "127.0.0.1"
    web_port: int = Field(default=8790, ge=1024, le=65535)
    policy_path: Path
    storage: ProductionStorageConfig
    secrets: ProductionSecretsConfig
    capabilities: ProductionCapabilities
    connectors: dict[str, DownstreamConfig] = Field(default_factory=dict)

    @field_validator("owner_user_id")
    @classmethod
    def owner_is_canonical(cls, value: str) -> str:
        if canonical_user_id(value) != value:
            raise ValueError("owner_user_id must be a canonical user id")
        return value

    @field_validator("public_origin")
    @classmethod
    def origin_requires_https(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or value.endswith("/")
        ):
            raise ValueError("public_origin must be an HTTPS origin without a trailing slash")
        return value

    @field_validator("mcp_host", "web_host")
    @classmethod
    def hosts_are_loopback_only(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("production listeners must use numeric loopback addresses") from exc
        if not address.is_loopback:
            raise ValueError("production listeners must remain loopback-only")
        return address.compressed

    @field_validator("allowed_hosts")
    @classmethod
    def allowed_hosts_are_bounded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not value
            or len(value) > 32
            or len(set(value)) != len(value)
            or any(
                not host or len(host) > 253 or "\x00" in host or "*" in host or "/" in host
                for host in value
            )
        ):
            raise ValueError("allowed_hosts must contain non-empty host labels")
        return value

    @field_validator("policy_path", mode="before")
    @classmethod
    def policy_path_is_absolute_and_lexical(cls, value: Any) -> Any:
        if isinstance(value, str):
            path = Path(value)
            if not path.is_absolute() or "\x00" in value or ".." in path.parts:
                raise ValueError("policy_path must be an absolute lexical path")
        return value

    @field_validator("connectors")
    @classmethod
    def connectors_are_strict(
        cls,
        value: dict[str, DownstreamConfig],
    ) -> dict[str, DownstreamConfig]:
        alias_pattern = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
        for alias, connector in value.items():
            if alias_pattern.fullmatch(alias) is None or alias == "gateway":
                raise ValueError("production connector aliases are invalid or reserved")
            if connector.transport == "http":
                endpoint = urlsplit(connector.url or "")
                try:
                    endpoint_port = endpoint.port
                except ValueError as exc:
                    raise ValueError("production HTTP connector endpoint is invalid") from exc
                if (
                    endpoint.scheme != "https"
                    or not endpoint.hostname
                    or endpoint.username is not None
                    or endpoint.password is not None
                    or endpoint.query
                    or endpoint.fragment
                    or endpoint_port is not None
                    and not 1 <= endpoint_port <= 65535
                    or connector.command
                    or connector.working_directory is not None
                    or connector.executable_sha256 is not None
                    or connector.execution_snapshot_root is not None
                ):
                    raise ValueError("production HTTP connector fields are incomplete or mixed")
            else:
                command_path = Path(connector.command[0]) if connector.command else Path()
                working_directory = connector.working_directory
                snapshot_root = connector.execution_snapshot_root
                if (
                    connector.url is not None
                    or not connector.command
                    or working_directory is None
                    or connector.executable_sha256 is None
                    or snapshot_root is None
                    or not command_path.is_absolute()
                    or ".." in command_path.parts
                    or not working_directory.is_absolute()
                    or ".." in working_directory.parts
                    or not snapshot_root.is_absolute()
                    or ".." in snapshot_root.parts
                    or any("\x00" in argument for argument in connector.command)
                ):
                    raise ValueError("production stdio connector fields are incomplete or mixed")
        return value

    @model_validator(mode="after")
    def production_shape_is_consistent(self) -> Self:
        if not self.policy_path.is_absolute() or ".." in self.policy_path.parts:
            raise ValueError("policy_path must be an absolute lexical path")
        if self.mcp_port == self.web_port:
            raise ValueError("production MCP and web ports must differ")
        origin_host = urlsplit(self.public_origin).hostname
        if self.rp_id != origin_host:
            raise ValueError("rp_id must equal the public origin host")
        if origin_host not in self.allowed_hosts:
            raise ValueError("allowed_hosts must include the public origin host")
        references = [
            reference for reference in self.secrets.model_dump().values() if reference is not None
        ]
        if len(references) != len(set(references)):
            raise ValueError("production secret purposes must use distinct references")
        return self

    def prepare_directories(self) -> None:
        self.storage.prepare_directories()

    def safe_dump(self) -> dict[str, object]:
        data = self.model_dump(mode="json")
        data["secrets"] = {
            key: ("<secret-reference>" if value is not None else None)
            for key, value in data["secrets"].items()
        }
        data["connectors"] = {
            alias: {
                **connector,
                "credential_ref": "<secret-reference>",
            }
            for alias, connector in data["connectors"].items()
        }
        return data

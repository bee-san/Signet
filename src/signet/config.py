"""Non-secret runtime configuration."""

from __future__ import annotations

import hashlib
import hmac
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


def production_instance_identity(root: Path) -> str:
    """Return the public, deterministic identity used by local health probes."""

    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("production root must be an absolute lexical path")
    material = b"signet-health-instance-v1\0" + str(root).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def production_health_proof(
    secret: str,
    *,
    identity: str,
    component: Literal["mcp", "web"],
    challenge: str,
) -> str:
    """Authenticate one fresh component-specific local health challenge."""

    if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise ValueError("health identity must be one lowercase SHA-256 digest")
    if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", challenge) is None:
        raise ValueError("health challenge must be one URL-safe random value")
    key = secret.encode("utf-8")
    if not 32 <= len(key) <= 4_096:
        raise ValueError("health proof secret must be 32 to 4096 UTF-8 bytes")
    material = b"signet-health-proof-v1\0" + identity.encode("ascii")
    material += b"\0" + component.encode("ascii") + b"\0" + challenge.encode("ascii")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def is_valid_allowed_host(host: str) -> bool:
    if (
        not host
        or len(host) > 253
        or host.endswith(".")
        or any(character in host for character in ("\x00", "*", "/", "%"))
    ):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        return all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label)
            and label.isascii()
            for label in labels
        )
    return True


def validate_public_origin(value: str) -> str:
    """Validate one canonical HTTPS origin and its allowed-host representation."""

    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("public_origin must use canonical HTTPS serialization") from None
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
    try:
        numeric_address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError(f"numeric IPv{numeric_address.version} public origins are not supported")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("public_origin hostname is invalid") from None
    if not is_valid_allowed_host(hostname):
        raise ValueError("public_origin hostname is not a valid allowed host")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("public_origin port is invalid")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    canonical = f"https://{authority}"
    if port is not None and port != 443:
        canonical = f"{canonical}:{port}"
    if value != canonical:
        raise ValueError("public_origin must use canonical HTTPS serialization")
    return value


class DownstreamConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: Literal["http", "stdio"]
    credential_ref: str
    credential_identity_digest: str
    server_identity_digest: str | None = None
    url: str | None = None
    tls_server_certificate: Path | None = None
    tls_server_certificate_sha256: str | None = None
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
    def credential_identity_is_reviewed_material(cls, value: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("credential identity must be a lowercase SHA-256 material digest")
        return value

    @field_validator("server_identity_digest")
    @classmethod
    def server_identity_is_exact(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("server identity must be a lowercase SHA-256 digest")
        return value

    @field_validator("tls_server_certificate_sha256")
    @classmethod
    def tls_server_certificate_digest_is_exact(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("TLS server certificate digest must be a lowercase SHA-256")
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
    attachment_staging_dir: Path | None = None
    attachment_source_roots: tuple[Path, ...] = ()

    @field_validator(
        "data_dir",
        "backup_dir",
        "restore_dir",
        "attachment_staging_dir",
        mode="before",
    )
    @classmethod
    def paths_are_absolute_and_lexical(cls, value: Any) -> Any:
        if isinstance(value, str):
            path = Path(value)
            if not path.is_absolute() or "\x00" in value or ".." in path.parts:
                raise ValueError("production storage paths must be absolute lexical paths")
        return value

    @model_validator(mode="after")
    def paths_are_distinct(self) -> Self:
        paths = tuple(
            path
            for path in (
                self.data_dir,
                self.backup_dir,
                self.restore_dir,
                self.attachment_staging_dir,
            )
            if path is not None
        )
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

    @field_validator("attachment_source_roots", mode="before")
    @classmethod
    def attachment_roots_are_absolute_and_lexical(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            for candidate in value:
                if not isinstance(candidate, (str, Path)):
                    continue
                path = Path(candidate)
                if not path.is_absolute() or "\x00" in str(candidate) or ".." in path.parts:
                    raise ValueError("attachment source roots must be absolute lexical paths")
        return value

    def prepare_directories(self) -> None:
        paths: tuple[Path, ...] = (self.data_dir, self.backup_dir, self.restore_dir)
        if self.attachment_staging_dir is not None:
            paths += (self.attachment_staging_dir,)
        for path in paths:
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
    attachment_key_ref: str | None = None
    totp_secret_ref: str | None = None
    vapid_private_key_ref: str | None = None

    @field_validator(
        "session_secret_ref",
        "csrf_secret_ref",
        "capability_key_ref",
        "payload_key_ref",
        "attachment_key_ref",
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


class ProductionWacliConfig(BaseModel):
    """Non-secret runtime boundary for the owned WhatsApp subprocess."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    account: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    )
    linked_jid: str = Field(
        min_length=22,
        max_length=48,
        pattern=r"^[1-9][0-9]{6,31}@s\.whatsapp\.net$",
    )
    home: Path
    store: Path
    expected_version: str
    cli_timeout: str = "15s"
    max_output_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)

    @field_validator("home", "store", mode="before")
    @classmethod
    def runtime_paths_are_absolute_and_lexical(cls, value: Any) -> Any:
        if isinstance(value, str):
            path = Path(value)
            if not path.is_absolute() or "\x00" in value or ".." in path.parts:
                raise ValueError("wacli runtime paths must be absolute lexical paths")
        return value

    @field_validator("expected_version")
    @classmethod
    def version_is_exact(cls, value: str) -> str:
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None:
            raise ValueError("wacli expected version must be exact")
        return value

    @field_validator("cli_timeout")
    @classmethod
    def cli_timeout_is_bounded(cls, value: str) -> str:
        if re.fullmatch(r"[1-9][0-9]{0,2}s", value) is None:
            raise ValueError("wacli CLI timeout must be bounded")
        return value

    @model_validator(mode="after")
    def runtime_paths_are_isolated(self) -> Self:
        if (
            not self.home.is_absolute()
            or not self.store.is_absolute()
            or self.home == self.store
            or self.home.parent != self.store.parent
        ):
            raise ValueError("wacli home and store must be isolated siblings")
        return self


class ProductionProviderRollout(BaseModel):
    """Explicit two-state cutover record; omission always means disabled."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: Literal["disabled", "enabled"] = "disabled"
    wacli: ProductionWacliConfig | None = None


class ProductionCallerPrincipal(BaseModel):
    """One reviewed Hermes profile allowed to use fixed production MCP routes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str
    allowed_aliases: tuple[
        Literal["approvals", "fastmail", "whatsapp"],
        ...,
    ] = ("approvals",)

    @field_validator("namespace")
    @classmethod
    def namespace_is_profile_scoped(cls, value: str) -> str:
        if re.fullmatch(r"profile:[a-z][a-z0-9-]{0,63}", value) is None:
            raise ValueError("production caller namespace must identify one Hermes profile")
        return value

    @field_validator("allowed_aliases")
    @classmethod
    def aliases_are_fixed_production_routes(
        cls,
        value: tuple[Literal["approvals", "fastmail", "whatsapp"], ...],
    ) -> tuple[Literal["approvals", "fastmail", "whatsapp"], ...]:
        if "approvals" not in value or len(value) != len(set(value)):
            raise ValueError(
                "production callers require approvals and unique fixed provider aliases"
            )
        return value


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
    caller_principals: tuple[ProductionCallerPrincipal, ...] = ()
    connectors: dict[str, DownstreamConfig] = Field(default_factory=dict)
    provider_rollout: ProductionProviderRollout = Field(default_factory=ProductionProviderRollout)

    @field_validator("owner_user_id")
    @classmethod
    def owner_is_canonical(cls, value: str) -> str:
        if canonical_user_id(value) != value:
            raise ValueError("owner_user_id must be a canonical user id")
        return value

    @field_validator("public_origin")
    @classmethod
    def origin_requires_https(cls, value: str) -> str:
        return validate_public_origin(value)

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
            or len({host.lower() for host in value}) != len(value)
            or any(not is_valid_allowed_host(host) for host in value)
        ):
            raise ValueError("allowed_hosts must contain valid unique host labels")
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
                    or (connector.tls_server_certificate is None)
                    != (connector.tls_server_certificate_sha256 is None)
                    or connector.tls_server_certificate is not None
                    and (
                        not connector.tls_server_certificate.is_absolute()
                        or ".." in connector.tls_server_certificate.parts
                    )
                ):
                    raise ValueError("production HTTP connector fields are incomplete or mixed")
            else:
                command_path = Path(connector.command[0]) if connector.command else Path()
                working_directory = connector.working_directory
                snapshot_root = connector.execution_snapshot_root
                if (
                    connector.url is not None
                    or connector.tls_server_certificate is not None
                    or connector.tls_server_certificate_sha256 is not None
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
        namespaces = tuple(principal.namespace for principal in self.caller_principals)
        if len(namespaces) != len(set(namespaces)):
            raise ValueError("production caller namespaces must be unique")
        references = [
            reference for reference in self.secrets.model_dump().values() if reference is not None
        ]
        if len(references) != len(set(references)):
            raise ValueError("production secret purposes must use distinct references")
        rollout_enabled = self.provider_rollout.state == "enabled"
        if rollout_enabled and not self.capabilities.live_providers_ready:
            raise ValueError("live provider readiness must be recorded before cutover")
        if self.capabilities.live_providers_ready and not rollout_enabled:
            raise ValueError("live provider cutover must be explicitly enabled")
        if rollout_enabled and (
            self.storage.attachment_staging_dir is None
            or not self.storage.attachment_source_roots
            or self.secrets.attachment_key_ref is None
        ):
            raise ValueError("live provider attachment staging must be configured")
        if rollout_enabled and set(self.connectors) - {"fastmail", "whatsapp"}:
            raise ValueError("live provider rollout supports only Fastmail and WhatsApp")
        if (
            rollout_enabled
            and "fastmail" in self.connectors
            and (
                self.connectors["fastmail"].tls_server_certificate is None
                or self.connectors["fastmail"].tls_server_certificate_sha256 is None
            )
        ):
            raise ValueError("live Fastmail rollout requires a reviewed TLS server certificate")
        if rollout_enabled and (
            ("whatsapp" in self.connectors) != (self.provider_rollout.wacli is not None)
        ):
            raise ValueError("WhatsApp rollout requires exactly one owned wacli boundary")
        return self

    @property
    def allowed_principals(self) -> dict[str, tuple[str, ...]]:
        return {
            principal.namespace: tuple(principal.allowed_aliases)
            for principal in self.caller_principals
        }

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

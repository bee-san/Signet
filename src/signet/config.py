"""Non-secret runtime configuration."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DownstreamConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: Literal["http", "stdio"]
    credential_ref: str
    url: str | None = None
    command: tuple[str, ...] = ()
    working_directory: Path | None = None
    executable_sha256: str | None = None
    execution_snapshot_root: Path | None = None
    test_only_allow_script: bool = False
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    output_limit_bytes: int = Field(default=1_048_576, gt=0, le=16_777_216)

    @field_validator("credential_ref")
    @classmethod
    def credential_is_reference_only(cls, value: str) -> str:
        if not value.startswith("keychain://"):
            raise ValueError("downstream credentials must use keychain:// references")
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
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.data_dir, 0o700)

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

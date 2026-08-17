from __future__ import annotations

from pathlib import Path

import pytest

from signet.adapters.base import staging_account_scope
from signet.adapters.fastmail import FastmailAdapter
from signet.adapters.whatsapp import WhatsAppFileAdapter
from signet.gateway import LocalInvocation
from signet.mcp_mirror import InvocationIdentity
from signet.policy import load_policy
from signet.production_staging_handlers import (
    ProductionStagingHandlerError,
    build_production_staging_handlers,
)
from tests.attachment_fixtures import staging_store as make_staging_store


def _policy(tmp_path: Path, *, fastmail_stage_account: str = "account:fastmail"):
    path = tmp_path / "policy.yaml"
    path.write_text(
        f"""
version: 1
default_mode: deny
downstreams:
  fastmail:
    transport: http
    url: https://mail.example.test/mcp
    credential_ref: keychain://signet/mail
    account_ref: account:fastmail
    tools:
      upload_attachment:
        mode: virtualize_local
        adapter: fastmail.stage_attachment
        account_ref: {fastmail_stage_account}
        schema_digest: {"a" * 64}
      send_email:
        mode: approval
        adapter: fastmail.send
        communication_send: true
        account_ref: account:fastmail
        schema_digest: {"b" * 64}
  whatsapp:
    transport: stdio
    command_ref: connector:whatsapp
    credential_ref: keychain://signet/whatsapp
    account_ref: account:whatsapp
    tools:
      upload_media:
        mode: virtualize_local
        adapter: whatsapp.stage_media
        account_ref: account:whatsapp
        schema_digest: {"c" * 64}
      send_file:
        mode: approval
        adapter: whatsapp.send_file
        communication_send: true
        account_ref: account:whatsapp
        schema_digest: {"d" * 64}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return load_policy(path)


def _invocation(alias: str, tool: str) -> LocalInvocation:
    return LocalInvocation(
        namespace="session:test",
        alias=alias,
        tool=tool,
        identity=InvocationIdentity("e" * 64, "explicit"),
    )


def test_production_staging_handlers_create_account_scoped_references(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    store = make_staging_store(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    adapters = {
        ("fastmail", "send_email"): FastmailAdapter(
            staging_store=store,
            account="account:fastmail",
            reviewed_dispatch_enabled=True,
        ),
        ("whatsapp", "send_file"): WhatsAppFileAdapter(
            staging_store=store,
            account="account:whatsapp",
            reviewed_dispatch_enabled=True,
        ),
    }
    handlers = build_production_staging_handlers(_policy(tmp_path), adapters)
    source = source_root / "report.txt"
    source.write_text("reviewed staging bytes", encoding="utf-8")
    arguments = {
        "source_path": str(source),
        "filename": "report.txt",
        "mime_type": "text/plain",
    }

    attachment = handlers["fastmail.stage_attachment"](
        arguments,
        _invocation("fastmail", "upload_attachment"),
    )
    media = handlers["whatsapp.stage_media"](
        arguments,
        _invocation("whatsapp", "upload_media"),
    )

    assert (
        store.resolve(
            attachment["staged_id"],
            adapter="fastmail",
            account=staging_account_scope("account:fastmail", "session:test"),
        ).sha256
        == attachment["sha256"]
    )
    assert (
        store.resolve(
            media["staged_id"],
            adapter="whatsapp",
            account=staging_account_scope("account:whatsapp", "session:test"),
        ).sha256
        == media["sha256"]
    )
    with pytest.raises(Exception, match="scope"):
        adapters[("fastmail", "send_email")].freeze_attachments(
            {
                "to": ["recipient@example.test"],
                "cc": [],
                "bcc": [],
                "subject": "subject",
                "text_body": "body",
                "attachments": [attachment],
            },
            caller_namespace="session:other",
        )


def test_production_staging_handlers_reject_cross_account_routes(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    store = make_staging_store(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    adapters = {
        ("fastmail", "send_email"): FastmailAdapter(
            staging_store=store,
            account="account:fastmail",
        )
    }

    with pytest.raises(ProductionStagingHandlerError, match="account scope"):
        build_production_staging_handlers(
            _policy(tmp_path, fastmail_stage_account="account:other"),
            adapters,
        )

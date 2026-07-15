from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError
from starlette.testclient import TestClient

import signet.demo as demo_module
from signet.app import main
from signet.backup import BackupError
from signet.credential_broker import CredentialError
from signet.demo import (
    DEMO_ACTION_PROOF,
    DEMO_GRACEFUL_SHUTDOWN_SECONDS,
    DEMO_LOGIN_PROOF,
    DEMO_NAMESPACE,
    DemoAssembly,
    DemoError,
    backup_demo,
    build_demo,
    credential_value,
    hermes_config,
    initialize_demo,
    live_smoke,
    offline_smoke,
    restore_demo,
)
from signet.retention import BackupPins

FASTMAIL_ARGUMENTS = {
    "from": "fake-sender@demo.invalid",
    "to": ["fake-recipient@demo.invalid"],
    "cc": [],
    "bcc": [],
    "subject": "Signet fake-only demo",
    "body": "This is a fake-only approval test.",
    "attachments": [],
}
WHATSAPP_ARGUMENTS = {
    "to": "15555550123@s.whatsapp.net",
    "message": "This is a fake-only approval test.",
}


def new_demo(tmp_path: Path, name: str = "demo") -> Path:
    root = tmp_path / name
    initialize_demo(root, now=1_800_000_000)
    return root


@asynccontextmanager
async def mcp_client(assembly: DemoAssembly) -> AsyncIterator[httpx.AsyncClient]:
    token = credential_value(assembly.root, "mcp-token")
    async with (
        assembly.mcp.app.router.lifespan_context(assembly.mcp.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=assembly.mcp.app),
            base_url="http://localhost:8789",
            headers={"Authorization": f"Bearer {token}"},
        ) as client,
    ):
        yield client


@asynccontextmanager
async def mcp_session(
    client: httpx.AsyncClient,
    alias: str,
) -> AsyncIterator[ClientSession]:
    async with (
        streamable_http_client(
            f"http://localhost:8789/mcp/{alias}",
            http_client=client,
        ) as (read_stream, write_stream, _get_session_id),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


async def enqueue(
    client: httpx.AsyncClient,
    alias: str,
    tool: str,
    arguments: dict[str, Any],
) -> str:
    async with mcp_session(client, alias) as session:
        result = await session.call_tool(tool, arguments)
    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["status"] == "pending_approval"
    return str(result.structuredContent["request_id"])


def exhausted_fake_unknown(root: Path) -> tuple[DemoAssembly, str, str]:
    assembly = build_demo(root)

    async def create_request() -> str:
        async with mcp_client(assembly) as client:
            return await enqueue(client, "fastmail", "send_email", FASTMAIL_ARGUMENTS)

    request_id = asyncio.run(create_request())
    request = assembly.state_machine.get_request(request_id)
    payload_hash = str(request["current_payload_hash"])
    with assembly.database.transaction() as connection:
        connection.execute(
            """
            UPDATE approval_requests
            SET state = 'outcome_unknown', safe_outcome_json = ?
            WHERE request_id = ?
            """,
            ('{"provider_candidate":"fake:private"}', request_id),
        )
        connection.execute(
            """
            INSERT INTO execution_attempts(
                attempt_id, request_id, version, payload_hash, fencing_token,
                worker_id, worker_generation, phase, claimed_at,
                dispatch_started_at, reconciliation_attempt_count,
                reconciliation_resolution, reconciliation_exhausted_at,
                reconciliation_notification_required, safe_completion_json,
                outcome_classification
            ) VALUES (?, ?, 1, ?, ?, 'fake:worker', 1, 'outcome_unknown', ?,
                      ?, 2, 'exhausted', ?, 1, ?, 'outcome_unknown')
            """,
            (
                f"attempt:{request_id}",
                request_id,
                payload_hash,
                f"fence:{request_id}",
                int(request["created_at"]),
                int(request["created_at"]) + 1,
                int(request["created_at"]) + 2,
                '{"provider_candidate":"fake:private"}',
            ),
        )
    return assembly, request_id, payload_hash


def hidden_values(document: str, name: str) -> list[str]:
    return re.findall(rf'name="{re.escape(name)}" value="([^"]+)"', document)


async def web_action(
    assembly: DemoAssembly,
    request_id: str,
    action: str,
) -> httpx.Response:
    origin = "http://127.0.0.1:8790"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=assembly.web),
        base_url=origin,
        follow_redirects=False,
    ) as client:
        login = await client.get("/login")
        assert login.status_code == 200
        assert "Fake-only demo" in login.text
        assert "Fake demo credentials" in login.text
        assert ">Fake user<" in login.text
        assert ">Fake password<" in login.text
        assert ">Fake login proof<" in login.text
        assert "Enter fake demo" in login.text
        assert 'id="password" name="password" type="text"' in login.text
        assert 'inputmode="text" autocomplete="off"' in login.text
        assert '<details class="fallback-login" open>' in login.text
        assert "data-passkey-login" not in login.text
        assert "Use passkey" not in login.text
        login_csrf = hidden_values(login.text, "csrf_token")[-1]
        authenticated = await client.post(
            "/login/password",
            data={
                "user_id": credential_value(assembly.root, "web-user"),
                "password": credential_value(assembly.root, "web-password"),
                "totp_proof": DEMO_LOGIN_PROOF,
                "csrf_token": login_csrf,
            },
            headers={"Origin": origin},
        )
        assert authenticated.status_code == 303

        detail = await client.get(f"/requests/{request_id}")
        assert detail.status_code == 200
        assert "Fake-only demo" in detail.text
        assert "Use fake action proof" in detail.text
        assert ">Fake action proof<" in detail.text
        assert 'inputmode="text" autocomplete="off"' in detail.text
        assert '<details class="authenticator-fallback" open>' in detail.text
        assert 'class="totp-action"' in detail.text
        assert "data-passkey-action" not in detail.text
        assert "Use passkey" not in detail.text
        assert "Always allow" not in detail.text
        response = await client.post(
            f"/requests/{request_id}/actions/totp",
            data={
                "action": action,
                "expected_version": hidden_values(detail.text, "expected_version")[-1],
                "expected_payload_hash": hidden_values(detail.text, "expected_payload_hash")[-1],
                "totp_proof": DEMO_ACTION_PROOF,
                "csrf_token": hidden_values(detail.text, "csrf_token")[-1],
            },
            headers={"Origin": origin},
        )
    return response


def request_state(assembly: DemoAssembly, request_id: str) -> str:
    return str(assembly.state_machine.get_request(request_id)["state"])


def test_cli_initializes_private_state_and_prints_only_selected_credentials(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "missing" / "demo"
    main(["demo", "init", "--data-dir", str(root)])
    assert "fake-only" in capsys.readouterr().out
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for name in ("demo-state.json", "demo-secrets.json", "policy.yaml", "approvals.sqlite3"):
        assert stat.S_IMODE((root / name).stat().st_mode) == 0o600

    main(
        [
            "demo",
            "credentials",
            "--data-dir",
            str(root),
            "--field",
            "web-login-proof",
        ]
    )
    captured = capsys.readouterr()
    assert captured.out == "fake:login\n"
    assert captured.err == ""
    assert credential_value(root, "web-action-proof") == "fake:approve"
    assert credential_value(root, "mcp-token").startswith("fake:sgt_")

    with pytest.raises(SystemExit):
        main(["demo", "init", "--data-dir", str(root)])
    assert offline_smoke(root)["network_provider_calls"] == 0


def test_cli_fake_unknown_purge_preserves_uncertainty_and_redacts_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = new_demo(tmp_path, "unknown-purge")
    assembly, request_id, payload_hash = exhausted_fake_unknown(root)

    main(
        [
            "demo",
            "purge-unknown",
            "--data-dir",
            str(root),
            "--request-id",
            request_id,
            "--expected-version",
            "1",
            "--expected-payload-hash",
            payload_hash,
            "--acknowledge-possible-delivery",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "claimed": 2,
        "completed": 2,
        "failed": 0,
        "scheduled": 2,
        "state": "outcome_unknown",
        "status": "fake_only_content_purged",
        "uncertainty_preserved": True,
    }
    main(
        [
            "demo",
            "purge-unknown",
            "--data-dir",
            str(root),
            "--request-id",
            request_id,
            "--expected-version",
            "1",
            "--expected-payload-hash",
            payload_hash,
            "--acknowledge-possible-delivery",
        ]
    )
    replay = json.loads(capsys.readouterr().out)
    assert replay["scheduled"] == replay["claimed"] == replay["completed"] == 0
    assert replay["failed"] == 0
    assert replay["state"] == "outcome_unknown"
    restarted = build_demo(root)
    with restarted.database.read() as connection:
        stored = connection.execute(
            """
            SELECT request.state, request.safe_outcome_json,
                   payload.encrypted_payload, payload.payload_hash, payload.purge_reason,
                   attempt.safe_completion_json, attempt.reconciliation_resolution
            FROM approval_requests AS request
            JOIN payload_versions AS payload
              ON payload.request_id = request.request_id
             AND payload.version = request.current_version
            JOIN execution_attempts AS attempt
              ON attempt.request_id = request.request_id
             AND attempt.version = request.current_version
            WHERE request.request_id = ?
            """,
            (request_id,),
        ).fetchone()
        actions = connection.execute(
            """
            SELECT action FROM request_events
            WHERE request_id = ? AND action LIKE 'fake_only_unknown_content_purge_%'
            ORDER BY event_id
            """,
            (request_id,),
        ).fetchall()
    assert tuple(stored) == (
        "outcome_unknown",
        None,
        None,
        payload_hash,
        "fake_only_unknown_content",
        None,
        "exhausted",
    )
    assert [row["action"] for row in actions] == [
        "fake_only_unknown_content_purge_authorized",
        "fake_only_unknown_content_purge_completed",
    ]
    assert assembly.provider_clients["fastmail"].mutation_calls == 0


def test_fake_unknown_purge_cli_help_and_required_acknowledgement(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as help_exit:
        main(["demo", "purge-unknown", "--help"])
    assert help_exit.value.code == 0
    help_output = capsys.readouterr()
    assert help_output.err == ""
    normalized_help = " ".join(help_output.out.split())
    for phrase in (
        "FAKE-ONLY destructive logical redaction",
        "Stop the demo server first",
        "does not erase SQLite free pages",
        "authenticated expanded review",
        "full lowercase SHA-256 payload hash",
        "delivery remains possible",
    ):
        assert phrase in normalized_help

    with pytest.raises(SystemExit) as missing_ack:
        main(
            [
                "demo",
                "purge-unknown",
                "--data-dir",
                "/private/path-marker",
                "--request-id",
                "request-secret-marker",
                "--expected-version",
                "1",
                "--expected-payload-hash",
                "a" * 64,
            ]
        )
    assert missing_ack.value.code == 2
    failure = capsys.readouterr()
    assert "--acknowledge-possible-delivery" in failure.err
    assert "request-secret-marker" not in failure.err
    assert "/private/path-marker" not in failure.err
    assert "Traceback" not in failure.err


def test_fake_unknown_purge_cli_pin_lock_and_stale_binding_fail_without_authorizing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = new_demo(tmp_path, "unknown-purge-guards")
    assembly, request_id, payload_hash = exhausted_fake_unknown(root)
    args = [
        "demo",
        "purge-unknown",
        "--data-dir",
        str(root),
        "--request-id",
        request_id,
        "--expected-version",
        "1",
        "--expected-payload-hash",
        payload_hash,
        "--acknowledge-possible-delivery",
    ]

    pins = BackupPins(assembly.database)
    lease = pins.acquire(now=1_800_000_100)
    with pytest.raises(SystemExit) as pinned_exit:
        main(args)
    assert pinned_exit.value.code == 2
    pinned = capsys.readouterr()
    assert "backup is active" in pinned.err
    assert request_id not in pinned.err
    assert payload_hash not in pinned.err
    assert str(root) not in pinned.err
    assert "Traceback" not in pinned.err
    with assembly.database.read() as connection:
        assert (
            connection.execute(
                """
                SELECT count(*) FROM request_events
                WHERE request_id = ?
                  AND action = 'fake_only_unknown_content_purge_authorized'
                """,
                (request_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """
                SELECT count(*) FROM purge_jobs
                WHERE request_id = ? AND intent != 'backup_pin'
                """,
                (request_id,),
            ).fetchone()[0]
            == 0
        )
    pins.release(lease, now=1_800_000_101)

    stale_args = list(args)
    stale_args[stale_args.index(payload_hash)] = "b" * 64
    with pytest.raises(SystemExit) as stale_exit:
        main(stale_args)
    assert stale_exit.value.code == 2
    stale = capsys.readouterr()
    assert "revision is not the current unknown outcome" in stale.err
    assert request_id not in stale.err
    assert payload_hash not in stale.err
    assert "b" * 64 not in stale.err
    assert "Traceback" not in stale.err

    with demo_module._demo_server_lock(root), pytest.raises(SystemExit) as locked_exit:
        main(args)
    assert locked_exit.value.code == 2
    locked = capsys.readouterr()
    assert "already being served" in locked.err
    assert request_id not in locked.err
    assert payload_hash not in locked.err
    assert "Traceback" not in locked.err


def test_marker_permissions_policy_and_production_shaped_tokens_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path)
    assembly = build_demo(root)
    fake_token = credential_value(root, "mcp-token")
    with pytest.raises(CredentialError):
        assembly.token_registry.authenticate(
            f"Bearer {fake_token.removeprefix('fake:')}",
            alias="fastmail",
        )

    os.chmod(root / "demo-secrets.json", 0o644)
    with pytest.raises(DemoError, match="unsafe"):
        build_demo(root)
    os.chmod(root / "demo-secrets.json", 0o600)

    with monkeypatch.context() as scoped:
        scoped.setattr("signet.demo.os.geteuid", lambda: root.stat().st_uid + 1)
        with pytest.raises(DemoError, match="private mode 0700"):
            build_demo(root)

    private_target = tmp_path / "private-target"
    private_target.mkdir(mode=0o700)
    private_link = tmp_path / "private-link"
    private_link.symlink_to(private_target, target_is_directory=True)
    with pytest.raises(DemoError, match="private directory"):
        backup_demo(root, private_link / "backup.signet-backup")

    policy_path = root / "policy.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["downstreams"]["fastmail"]["url"] = "https://api.fastmail.com/mcp"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(DemoError, match="non-fake"):
        build_demo(root)


@pytest.mark.asyncio
async def test_mcp_fake_read_approval_deny_and_web_only_approval_surface(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        async with mcp_session(client, "fastmail") as session:
            listed = await session.list_tools()
            assert [tool.name for tool in listed.tools] == [
                "list_identities",
                "search_email",
                "send_email",
                "delete_email",
            ]
            read = await session.call_tool("list_identities", {})
            assert read.isError is False
            assert read.structuredContent == {
                "identities": [
                    {
                        "id": "fake:identity:primary",
                        "email": "fake-sender@demo.invalid",
                        "name": "Fake Demo Sender",
                    }
                ]
            }
            denied = await session.call_tool(
                "delete_email", {"message_id": "fake:message:never-delete"}
            )
            assert denied.isError is True
            assert denied.structuredContent["error"]["code"] == "policy_denied"
            denied_replay = await session.call_tool(
                "delete_email", {"message_id": "fake:message:different-private-value"}
            )
            assert denied_replay.structuredContent["error"]["code"] == "policy_denied"
            pending_fastmail = await session.call_tool("send_email", FASTMAIL_ARGUMENTS)
            assert pending_fastmail.isError is False
            fastmail_request_id = str(pending_fastmail.structuredContent["request_id"])

        async with mcp_session(client, "whatsapp") as session:
            read = await session.call_tool("list_chats", {})
            assert read.structuredContent["chats"][0]["label"] == "fake:demo-chat"
            denied = await session.call_tool("delete_chat", {"jid": "15555550123@s.whatsapp.net"})
            assert denied.isError is True
            pending = await session.call_tool("send_text", WHATSAPP_ARGUMENTS)
            assert pending.structuredContent["status"] == "pending_approval"
            whatsapp_request_id = str(pending.structuredContent["request_id"])

        async with mcp_session(client, "approvals") as session:
            listed = await session.list_tools()
            names = [tool.name for tool in listed.tools]
            assert "approve_request" not in names
            assert names == [
                "check_approval_status",
                "list_pending_approvals",
                "cancel_request",
                "request_tool_access",
            ]
            pending = await session.call_tool("list_pending_approvals", {})
            assert pending.isError is False
            serialized = json.dumps(pending.structuredContent)
            assert FASTMAIL_ARGUMENTS["to"][0] not in serialized
            assert WHATSAPP_ARGUMENTS["to"] not in serialized
            summaries = {
                str(item["request_id"]): str(item["destination_summary"])
                for item in pending.structuredContent["requests"]
            }
            assert summaries[fastmail_request_id] == "f*** at demo.invalid"
            assert summaries[whatsapp_request_id] == "*******0123@s.whatsapp.net"
            for request_id, raw_destination in (
                (fastmail_request_id, FASTMAIL_ARGUMENTS["to"][0]),
                (whatsapp_request_id, WHATSAPP_ARGUMENTS["to"]),
            ):
                status = await session.call_tool(
                    "check_approval_status", {"request_id": request_id}
                )
                assert status.isError is False
                status_json = json.dumps(status.structuredContent)
                assert raw_destination not in status_json
                assert status.structuredContent["summary_available"] is True
            with pytest.raises(McpError):
                await session.call_tool(
                    "approve_request",
                    {
                        "request_id": "req_fake",
                        "totp_code": "000000",
                        "expected_version_hash": "a" * 8,
                    },
                )
    assert assembly.provider_clients["fastmail"].mutation_calls == 0
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0
    with assembly.database.read() as connection:
        denied_events = connection.execute(
            """
            SELECT request.request_id, request.origin_namespace,
                   payload.encrypted_payload
            FROM approval_requests AS request
            JOIN payload_versions AS payload
              ON payload.request_id = request.request_id
             AND payload.version = request.current_version
            WHERE request.gateway_internal = 1
              AND request.tool_name = 'request_tool_access'
            ORDER BY request.request_id
            """
        ).fetchall()
        denied_idempotency = connection.execute(
            """
            SELECT count(*) FROM idempotency_records AS idempotency
            JOIN approval_requests AS request USING(request_id)
            WHERE request.gateway_internal = 1
              AND request.tool_name = 'request_tool_access'
            """
        ).fetchone()[0]
    assert len(denied_events) == 2
    assert denied_idempotency == 2
    assert {row["origin_namespace"] for row in denied_events} == {DEMO_NAMESPACE}
    for row in denied_events:
        ciphertext = bytes(row["encrypted_payload"])
        assert b"never-delete" not in ciphertext
        assert b"different-private-value" not in ciphertext
        assert b"15555550123" not in ciphertext


@pytest.mark.asyncio
async def test_immediate_browser_deny_then_approve_has_zero_then_one_provider_call(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        denied_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Deny this fake request"},
        )
        approved_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Approve this fake request"},
        )

    denied = await web_action(assembly, denied_id, "deny")
    assert denied.status_code == 303
    assert request_state(assembly, denied_id) == "denied"
    denied_delivery, _notifications = await assembly.workers.run_once()
    assert denied_delivery == 0
    assert assembly.provider_clients["fastmail"].mutation_calls == 0

    approved = await web_action(assembly, approved_id, "approve")
    assert approved.status_code == 303
    delivered, _notifications = await assembly.workers.run_once()
    assert delivered == 1
    assert request_state(assembly, approved_id) == "succeeded"
    assert assembly.provider_clients["fastmail"].mutation_calls == 1
    safe = assembly.state_machine.get_request(approved_id)["safe_outcome_json"]
    assert "fake:message" not in str(safe)
    assert "sgref_" in str(safe)

    restarted = build_demo(assembly.root)
    assert request_state(restarted, approved_id) == "succeeded"
    assert (await restarted.workers.run_once())[0] == 0
    assert restarted.provider_clients["fastmail"].mutation_calls == 0


@pytest.mark.asyncio
async def test_workers_reclaim_only_pre_dispatch_and_reconcile_abandoned_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        reclaimable_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Reclaim before fake dispatch"},
        )
        unknown_id = await enqueue(
            client,
            "whatsapp",
            "send_text",
            {**WHATSAPP_ARGUMENTS, "message": "Recover after fake dispatch boundary"},
        )
    assert (await web_action(assembly, reclaimable_id, "approve")).status_code == 303
    assert (await web_action(assembly, unknown_id, "approve")).status_code == 303

    started_at = int(time.time())
    assembly.state_machine.claim_execution(
        reclaimable_id,
        worker_id="fake:crashed-before-dispatch",
        now=started_at,
        lease_seconds=1,
    )
    unknown_lease = assembly.state_machine.claim_execution(
        unknown_id,
        worker_id="fake:crashed-after-dispatch",
        now=started_at,
        lease_seconds=1,
    )
    assembly.state_machine.mark_dispatch_started(unknown_lease, now=started_at)
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE execution_attempts SET lease_expires_at = ? WHERE request_id IN (?, ?)",
            (started_at - 1, reclaimable_id, unknown_id),
        )

    stop = asyncio.Event()
    result: tuple[int, int] | None = None
    original_run_once = assembly.workers.run_once

    async def run_one_supervised_cycle(*, now: int | None = None) -> tuple[int, int]:
        nonlocal result
        result = await original_run_once(now=now)
        stop.set()
        return result

    monkeypatch.setattr(assembly.workers, "run_once", run_one_supervised_cycle)
    await assembly.workers.serve(stop)
    monkeypatch.setattr(assembly.workers, "run_once", original_run_once)
    assert result is not None
    delivered, _notifications = result
    assert delivered == 1
    assert request_state(assembly, reclaimable_id) == "succeeded"
    assert request_state(assembly, unknown_id) == "outcome_unknown"
    assert assembly.provider_clients["fastmail"].mutation_calls == 1
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0
    with assembly.database.read() as connection:
        reclaimed = connection.execute(
            "SELECT worker_generation, phase FROM execution_attempts WHERE request_id = ?",
            (reclaimable_id,),
        ).fetchone()
        unknown = connection.execute(
            """
            SELECT reconciliation_attempt_count, reconciliation_next_at,
                   reconciliation_resolution
            FROM execution_attempts WHERE request_id = ?
            """,
            (unknown_id,),
        ).fetchone()
    assert tuple(reclaimed) == (2, "succeeded")
    assert unknown["reconciliation_attempt_count"] == 1
    assert unknown["reconciliation_resolution"] == "inconclusive"

    while unknown["reconciliation_resolution"] != "exhausted":
        next_at = int(unknown["reconciliation_next_at"])
        await assembly.workers.run_once(now=next_at)
        with assembly.database.read() as connection:
            unknown = connection.execute(
                """
                SELECT reconciliation_attempt_count, reconciliation_next_at,
                       reconciliation_resolution
                FROM execution_attempts WHERE request_id = ?
                """,
                (unknown_id,),
            ).fetchone()
    assert unknown["reconciliation_attempt_count"] == 5
    assert unknown["reconciliation_next_at"] is None
    assert assembly.provider_clients["fastmail"].mutation_calls == 1
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0


@pytest.mark.asyncio
async def test_fake_fastmail_ambiguous_result_is_resolved_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        request_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Reconcile this fake send"},
        )
    assert (await web_action(assembly, request_id, "approve")).status_code == 303

    provider = assembly.provider_clients["fastmail"]
    original_call = provider.call_tool

    async def ambiguous_result(
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        result = await original_call(tool_name, arguments)
        if tool_name == "send_email":
            result["status"] = "ambiguous"
        return result

    monkeypatch.setattr(provider, "call_tool", ambiguous_result)
    now = int(time.time())
    delivered, _notifications = await assembly.workers.run_once(now=now)
    assert delivered == 1
    assert request_state(assembly, request_id) == "outcome_unknown"
    assert provider.mutation_calls == 1

    await assembly.workers.run_once(now=now + 60)
    assert request_state(assembly, request_id) == "succeeded"
    assert provider.mutation_calls == 1
    with assembly.database.read() as connection:
        attempt = connection.execute(
            """
            SELECT reconciliation_attempt_count, reconciliation_resolution
            FROM execution_attempts WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
    assert tuple(attempt) == (1, "confirmed_effect")


@pytest.mark.asyncio
async def test_workers_schedule_private_notifications_and_retention_once(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        request_id = await enqueue(client, "whatsapp", "send_text", WHATSAPP_ARGUMENTS)

    now = int(time.time())
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE approval_requests SET expires_at = ? WHERE request_id = ?",
            (now + 60, request_id),
        )
    _delivered, notifications = await assembly.workers.run_once(now=now)
    assert notifications == 3
    with assembly.database.read() as connection:
        kinds = [
            str(row["kind"])
            for row in connection.execute(
                "SELECT kind FROM notification_outbox ORDER BY kind"
            ).fetchall()
        ]
    assert kinds == ["approaching_expiry", "daily_digest", "new_pending"]
    assert (await assembly.workers.run_once(now=now))[1] == 0

    await assembly.workers.run_once(now=now + 61)
    assert request_state(assembly, request_id) == "expired"
    with assembly.database.read() as connection:
        payload = connection.execute(
            "SELECT encrypted_payload, purged_at FROM payload_versions WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        retention = connection.execute(
            """
            SELECT intent, completed_at FROM purge_jobs
            WHERE request_id = ? ORDER BY intent
            """,
            (request_id,),
        ).fetchall()
    assert payload["encrypted_payload"] is not None
    assert payload["purged_at"] is None
    assert [tuple(row) for row in retention] == [("sensitive_rows", None)]


@pytest.mark.asyncio
async def test_worker_supervision_retries_and_health_reports_persistent_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    stop = asyncio.Event()
    third_failure = asyncio.Event()
    calls = 0

    original_sweep = assembly.state_machine.sweep_expired

    def flaky_expiry_sweep(*, now: int, limit: int) -> int:
        nonlocal calls
        calls += 1
        if calls <= 3:
            if calls == 3:
                third_failure.set()
            raise RuntimeError("private fake expiry failure")
        stop.set()
        return original_sweep(now=now, limit=limit)

    assembly.workers.interval_seconds = 0.05
    monkeypatch.setattr(assembly.state_machine, "sweep_expired", flaky_expiry_sweep)
    task = asyncio.create_task(assembly.workers.serve(stop))
    await asyncio.wait_for(third_failure.wait(), timeout=2)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=assembly.web),
        base_url="http://127.0.0.1:8790",
    ) as client:
        for _ in range(20):
            health = await client.get("/healthz")
            if health.status_code == 503:
                break
            await asyncio.sleep(0.01)
    assert health.status_code == 503
    assert health.json() == {"status": "unavailable", "service": "signet-web"}

    await asyncio.wait_for(task, timeout=2)
    assert calls == 4


@pytest.mark.asyncio
async def test_offline_operations_under_serve_lock_never_recover_execution(
    tmp_path: Path,
) -> None:
    root = new_demo(tmp_path, "live-source")
    assembly = build_demo(root)
    async with mcp_client(assembly) as client:
        request_id = await enqueue(client, "whatsapp", "send_text", WHATSAPP_ARGUMENTS)
    assert (await web_action(assembly, request_id, "approve")).status_code == 303

    now = int(time.time())
    lease = assembly.state_machine.claim_execution(
        request_id,
        worker_id="fake:live-dispatch",
        now=now,
        lease_seconds=30,
    )
    assembly.state_machine.mark_dispatch_started(lease, now=now)
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE execution_attempts SET lease_expires_at = ? WHERE request_id = ?",
            (now - 1, request_id),
        )

    private = tmp_path / "offline-artifacts"
    private.mkdir(mode=0o700)
    with demo_module._demo_server_lock(root):
        assert request_state(build_demo(root), request_id) == "executing"
        assert offline_smoke(root)["status"] == "ok"
        assert request_state(assembly, request_id) == "executing"
        bundle = backup_demo(root, private / "concurrent.signet-backup")
        assert request_state(assembly, request_id) == "executing"
        restored = restore_demo(root, bundle, private / "restored")
        assert request_state(build_demo(restored.root), request_id) == "executing"
        assert request_state(assembly, request_id) == "executing"

    recovered = assembly.state_machine.recover_startup(now=now)
    assert recovered.routed_to_reconciliation == (request_id,)
    assert request_state(assembly, request_id) == "outcome_unknown"


def test_demo_serve_lock_rejects_links_and_reuses_stale_regular_file(tmp_path: Path) -> None:
    root = new_demo(tmp_path)
    lock_path = root / ".serve.lock"
    outside = tmp_path / "outside-lock"
    outside.write_text("not a lock\n", encoding="utf-8")
    os.chmod(outside, 0o600)

    lock_path.symlink_to(outside)
    with (
        pytest.raises(DemoError, match="unavailable or unsafe"),
        demo_module._demo_server_lock(root),
    ):
        pass
    lock_path.unlink()

    os.link(outside, lock_path)
    with (
        pytest.raises(DemoError, match="unavailable or unsafe"),
        demo_module._demo_server_lock(root),
    ):
        pass
    lock_path.unlink()

    lock_path.write_text("stale owner metadata is ignored\n", encoding="utf-8")
    os.chmod(lock_path, 0o600)
    with (
        demo_module._demo_server_lock(root),
        pytest.raises(DemoError, match="already being served"),
        demo_module._demo_server_lock(root),
    ):
        pass
    with demo_module._demo_server_lock(root):
        pass


@pytest.mark.asyncio
async def test_direct_workers_serve_cannot_recover_while_lifespan_holds_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path)
    holder = build_demo(root)
    contender = build_demo(root)
    recovery_calls = 0

    def unexpected_recovery(*, now: int) -> Any:
        nonlocal recovery_calls
        del now
        recovery_calls += 1
        raise AssertionError("unlocked recovery ran")

    monkeypatch.setattr(contender.state_machine, "recover_startup", unexpected_recovery)
    async with holder.web.router.lifespan_context(holder.web):
        with pytest.raises(DemoError, match="already being served"):
            await contender.workers.serve(asyncio.Event())
        assert recovery_calls == 0
        assert contender.provider_clients["fastmail"].mutation_calls == 0
        assert contender.provider_clients["whatsapp"].mutation_calls == 0


def test_testclient_lifespan_cannot_start_second_worker_before_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path)
    holder = build_demo(root)
    contender = build_demo(root)
    recovery_calls = 0

    def unexpected_recovery(*, now: int) -> Any:
        nonlocal recovery_calls
        del now
        recovery_calls += 1
        raise AssertionError("unlocked recovery ran")

    monkeypatch.setattr(contender.state_machine, "recover_startup", unexpected_recovery)
    with TestClient(holder.web, base_url="http://127.0.0.1:8790") as client:
        assert client.get("/healthz").status_code == 200
        with (
            pytest.raises(DemoError, match="already being served"),
            TestClient(
                contender.web,
                base_url="http://127.0.0.1:8790",
            ),
        ):
            pass
        assert recovery_calls == 0
        assert contender.provider_clients["fastmail"].mutation_calls == 0
        assert contender.provider_clients["whatsapp"].mutation_calls == 0


@pytest.mark.asyncio
async def test_corrupt_approved_payload_fails_before_fake_provider_call(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        request_id = await enqueue(client, "whatsapp", "send_text", WHATSAPP_ARGUMENTS)
    assert (await web_action(assembly, request_id, "approve")).status_code == 303
    with assembly.database.transaction() as connection:
        connection.execute(
            """
            UPDATE payload_versions
            SET encrypted_payload = NULL, purged_at = ?
            WHERE request_id = ?
            """,
            (1_800_000_001, request_id),
        )
    delivered, _notifications = await assembly.workers.run_once()
    assert delivered == 0
    assert request_state(assembly, request_id) == "failed"
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0


@pytest.mark.asyncio
async def test_encrypted_backup_restore_preserves_pending_request_and_attachment(
    tmp_path: Path,
) -> None:
    root = new_demo(tmp_path, "source")
    assembly = build_demo(root)
    content = b"fake pending attachment content\n"
    source = root / "imports" / "pending.txt"
    source.write_bytes(content)
    os.chmod(source, 0o600)
    staged = assembly.staging.stage_path(
        source,
        adapter="fastmail",
        account="fake:fastmail-account",
        filename="pending.txt",
        declared_mime="text/plain",
    )
    attachment = {
        "staged_id": staged.opaque_id,
        "filename": staged.filename,
        "mime_type": staged.declared_mime,
        "detected_mime": staged.detected_mime,
        "size": staged.size,
        "sha256": staged.sha256,
    }
    async with mcp_client(assembly) as client:
        request_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {
                **FASTMAIL_ARGUMENTS,
                "subject": "Back up this pending fake request",
                "attachments": [attachment],
            },
        )
    assert request_state(assembly, request_id) == "pending_approval"

    old_token = credential_value(root, "mcp-token")
    old_password = credential_value(root, "web-password")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    bundle = backup_demo(root, private / "demo.signet-backup")
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    encrypted = bundle.read_bytes()
    assert old_token.encode() not in encrypted
    assert old_password.encode() not in encrypted
    assert content not in encrypted

    destination = private / "restored"
    restored = restore_demo(root, bundle, destination)
    assert restored.root == destination
    assert [item["attachment_id"] for item in restored.manifest["attachments"]] == [
        staged.opaque_id
    ]
    assert credential_value(destination, "mcp-token") != old_token
    assert credential_value(destination, "web-password") != old_password
    assert credential_value(destination, "mcp-token").startswith("fake:sgt_")
    assert offline_smoke(destination)["status"] == "ok"
    restarted = build_demo(destination)
    assert request_state(restarted, request_id) == "pending_approval"
    restored_record, restored_content = restarted.staging.read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="fake:fastmail-account",
    )
    assert restored_content == content
    assert restored_record.path.parent == destination / "attachments"

    existing = private / "existing"
    existing.mkdir(mode=0o700)
    with pytest.raises(BackupError, match="must not already exist"):
        restore_demo(root, bundle, existing)
    assert existing.is_dir()

    bad_bundle = private / "bad.signet-backup"
    bad_bundle.write_bytes(b"not-a-signet-backup")
    os.chmod(bad_bundle, 0o600)
    failed_destination = private / "failed-restore"
    with pytest.raises(BackupError):
        restore_demo(root, bad_bundle, failed_destination)
    assert not failed_destination.exists()


def test_cli_backup_errors_are_bounded_and_hermes_shape_is_restrictive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path)
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                str(public_parent / "backup.signet-backup"),
            ]
        )
    error = capsys.readouterr().err
    assert "Traceback" not in error
    assert credential_value(root, "mcp-token") not in error
    assert "private directory" in error

    document = yaml.safe_load(hermes_config(mcp_port=18789))
    assert set(document["mcp_servers"]) == {
        "signet_demo_fastmail",
        "signet_demo_whatsapp",
        "signet_demo_approvals",
    }
    for server in document["mcp_servers"].values():
        assert server == {
            "url": server["url"],
            "headers": {"Authorization": "Bearer ${SIGNET_DEMO_MCP_CALLER_TOKEN}"},
            "enabled": True,
            "connect_timeout": 10,
            "timeout": 120,
            "supports_parallel_tool_calls": False,
            "tools": {"resources": False, "prompts": False},
            "sampling": {"enabled": False},
        }
        assert server["url"].startswith("http://127.0.0.1:18789/mcp/")


@pytest.mark.parametrize(
    "stop_signal",
    (signal.SIGINT, signal.SIGTERM),
    ids=("sigint", "sigterm"),
)
def test_demo_serve_stops_both_listeners_within_bound(
    tmp_path: Path,
    stop_signal: signal.Signals,
) -> None:
    root = new_demo(tmp_path)
    ports = _available_ports()
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and in-repo entry point
        [
            sys.executable,
            "-c",
            "from signet.app import main; main()",
            "demo",
            "serve",
            "--data-dir",
            str(root),
            "--mcp-port",
            str(ports[0]),
            "--web-port",
            str(ports[1]),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_listener(process, ports[1])
        assert live_smoke(mcp_port=ports[0], web_port=ports[1]) == {
            "status": "ok",
            "mode": "fake-only",
            "services": ["mcp", "web"],
        }
        contender_ports = _available_ports()
        contender = subprocess.run(  # noqa: S603 - fixed interpreter and entry point
            [
                sys.executable,
                "-c",
                "from signet.app import main; main()",
                "demo",
                "serve",
                "--data-dir",
                str(root),
                "--mcp-port",
                str(contender_ports[0]),
                "--web-port",
                str(contender_ports[1]),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert contender.returncode != 0
        assert "already being served" in contender.stderr
        assert "Traceback" not in contender.stderr
        assert stat.S_IMODE((root / ".serve.lock").stat().st_mode) == 0o600
        started_shutdown = time.monotonic()
        process.send_signal(stop_signal)
        stdout, stderr = process.communicate(timeout=DEMO_GRACEFUL_SHUTDOWN_SECONDS + 5)
        shutdown_elapsed = time.monotonic() - started_shutdown
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    combined = stdout + stderr
    assert process.returncode == 0
    assert "Signet fake-only demo MCP:" in stdout
    assert "Signet fake-only demo web:" in stdout
    assert "Traceback" not in combined
    assert "CancelledError" not in combined
    assert "ERROR" not in combined
    assert shutdown_elapsed < DEMO_GRACEFUL_SHUTDOWN_SECONDS + 3
    with pytest.raises(DemoError, match="live mcp health check failed"):
        live_smoke(mcp_port=ports[0], web_port=ports[1])
    for port in ports:
        with socket.socket() as candidate:
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            candidate.bind(("127.0.0.1", port))


def test_live_smoke_rejects_oversized_health_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OversizedResponse:
        status = 200

        @staticmethod
        def read(_maximum: int) -> bytes:
            return b"x" * 4097

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        @staticmethod
        def request(_method: str, _path: str) -> None:
            pass

        @staticmethod
        def getresponse() -> OversizedResponse:
            return OversizedResponse()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr("signet.demo.http.client.HTTPConnection", FakeConnection)
    with pytest.raises(DemoError, match="live mcp health check failed"):
        live_smoke(mcp_port=18789, web_port=18790)


def test_forced_request_cancellation_is_bounded_sanitized_error(tmp_path: Path) -> None:
    root = new_demo(tmp_path)
    token = credential_value(root, "mcp-token")
    ports = _available_ports()
    script = """
import asyncio
import signet.demo as demo

original_build_demo = demo.build_demo

def instrumented_build_demo(*args, **kwargs):
    assembly = original_build_demo(*args, **kwargs)

    async def stuck_request():
        await asyncio.Event().wait()

    assembly.web.add_api_route('/_test_stuck', stuck_request, methods=['GET'])
    return assembly

demo.build_demo = instrumented_build_demo
from signet.app import main
main()
"""
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and test script
        [
            sys.executable,
            "-c",
            script,
            "demo",
            "serve",
            "--data-dir",
            str(root),
            "--mcp-port",
            str(ports[0]),
            "--web-port",
            str(ports[1]),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    connection: socket.socket | None = None
    try:
        _wait_for_listener(process, ports[1])
        connection = socket.create_connection(("127.0.0.1", ports[1]), timeout=2)
        connection.sendall(
            b"GET /_test_stuck HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        time.sleep(0.2)
        started_shutdown = time.monotonic()
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=DEMO_GRACEFUL_SHUTDOWN_SECONDS + 5)
        shutdown_elapsed = time.monotonic() - started_shutdown
    finally:
        if connection is not None:
            connection.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    combined = stdout + stderr
    assert process.returncode == 2
    assert "demo shutdown exceeded its graceful safety deadline" in stderr
    assert token not in combined
    assert "Traceback" not in combined
    assert "CancelledError" not in combined
    assert shutdown_elapsed < DEMO_GRACEFUL_SHUTDOWN_SECONDS + 3


def _available_ports() -> list[int]:
    ports: list[int] = []
    while len(ports) < 2:
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            selected = int(candidate.getsockname()[1])
            if selected not in ports:
                ports.append(selected)
    return ports


def _wait_for_listener(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("demo listener did not become ready")

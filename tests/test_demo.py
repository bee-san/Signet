from __future__ import annotations

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

from signet.app import main
from signet.backup import BackupError
from signet.credential_broker import CredentialError
from signet.demo import (
    DEMO_ACTION_PROOF,
    DEMO_GRACEFUL_SHUTDOWN_SECONDS,
    DEMO_LOGIN_PROOF,
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

        async with mcp_session(client, "whatsapp") as session:
            read = await session.call_tool("list_chats", {})
            assert read.structuredContent["chats"][0]["label"] == "fake:demo-chat"
            denied = await session.call_tool("delete_chat", {"jid": "15555550123@s.whatsapp.net"})
            assert denied.isError is True
            pending = await session.call_tool("send_text", WHATSAPP_ARGUMENTS)
            assert pending.structuredContent["status"] == "pending_approval"

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

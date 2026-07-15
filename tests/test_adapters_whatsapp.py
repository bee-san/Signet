from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from signet.adapters import (
    AdapterRequest,
    AdapterValidationError,
    ExecutionAttempt,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    WhatsAppFileAdapter,
    WhatsAppTextAdapter,
)
from signet.delivery import standardize_safe_metadata
from signet.wacli_wrapper import WacliConfig, WacliError, WacliWrapper
from tests.attachment_fixtures import staging_store as make_staging_store

ROOT = Path(__file__).resolve().parents[1]


class FakeOwnedClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        return {"data": {"sent": True, "message_id": "wa-safe-id"}}


def text_arguments() -> dict[str, Any]:
    with (ROOT / "spec/fixtures/whatsapp-send-input.json").open(encoding="utf-8") as handle:
        fixture = json.load(handle)
    return fixture["arguments"]


def adapter_request(tool: str, arguments: Mapping[str, Any]) -> AdapterRequest:
    return AdapterRequest(
        request_id="req_whatsapp_fixture",
        downstream_alias="whatsapp",
        tool_name=tool,
        arguments=arguments,
        account="personal",
        payload_hash="c" * 64,
    )


def make_fake_wacli(
    tmp_path: Path,
    *,
    version: str = "0.12.0",
    send_body: str = '{"sent":true,"message_id":"wa-safe-id"}',
    send_prelude: str = "",
) -> tuple[Path, Path]:
    executable = tmp_path / "fake-wacli"
    log = tmp_path / "argv.log"
    script = f"""#!/bin/sh
printf '%s\\n' CALL >> {str(log)!r}
printf '%s\\n' "$@" >> {str(log)!r}
/usr/bin/env >> {str(log)!r}
case " $* " in
  *" version "*) printf '%s' '{json.dumps({"version": version})}' ;;
  *" send "*) {send_prelude} printf '%s' '{send_body}' ;;
  *) printf '%s' '{{"error":"unexpected"}}'; exit 2 ;;
esac
"""
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o700)
    return executable, log


def wrapper_config(executable: Path, tmp_path: Path, **changes: Any) -> WacliConfig:
    values: dict[str, Any] = {
        "account": "personal",
        "executable": executable,
        "expected_version": "0.12.0",
        "expected_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "staging_root": tmp_path / "staging",
        "home": tmp_path / "home",
        "timeout_seconds": 2,
        "max_output_bytes": 16 * 1024,
        "reviewed_dispatch_enabled": True,
        "execution_snapshot_root": tmp_path / "exec-snapshots",
        "test_only_allow_script": True,
    }
    values.update(changes)
    return WacliConfig(**values)


@pytest.mark.asyncio
async def test_whatsapp_text_reply_executes_exact_owned_tool_once() -> None:
    adapter = WhatsAppTextAdapter(account="personal", reviewed_dispatch_enabled=True)
    arguments = text_arguments()
    arguments.update({"reply_to": "message-123", "reply_to_sender": "+15550102030"})
    summary = adapter.summarize_for_web(arguments)
    masked = adapter.masked_destination_summary(arguments)
    assert summary.destination_summary == "+15550102030"
    assert masked == "+*******2030"
    assert summary.destination_summary not in masked
    assert any(block.kind == "reply" for block in summary.detail_blocks)

    downstream = FakeOwnedClient()
    payload = adapter.prepare_for_execution(adapter_request("send_text", arguments))
    result = await adapter.execute(downstream, payload)
    assert downstream.calls == [("send_text", payload)]
    assert adapter.classify_outcome(result) is Outcome.SUCCEEDED
    assert adapter.safe_result_metadata(result) == {
        "status": "sent",
        "chat_message_id": "wa-safe-id",
    }


def test_whatsapp_jid_agent_summary_is_deterministic_and_never_full() -> None:
    adapter = WhatsAppTextAdapter(account="personal")
    arguments = {
        "to": "15555550123@s.whatsapp.net",
        "message": "private message",
    }

    first = adapter.masked_destination_summary(arguments)
    second = adapter.masked_destination_summary(arguments)

    assert first == second == "*******0123@s.whatsapp.net"
    assert arguments["to"] not in first


def test_whatsapp_safe_result_accepts_only_the_owned_wrapper_shape() -> None:
    adapter = WhatsAppTextAdapter(account="personal")
    result = {
        "data": {"sent": True, "message_id": "3EB0.Abc_123:def@example.test"},
        "isError": False,
    }

    assert adapter.classify_outcome(result) is Outcome.SUCCEEDED
    assert adapter.safe_result_metadata(result) == {
        "status": "sent",
        "chat_message_id": "3EB0.Abc_123:def@example.test",
    }


@pytest.mark.parametrize(
    "result",
    [
        {
            "sent": True,
            "message_id": "wa-safe-id",
            "message": "private request content echoed by provider",
        },
        {"sent": True, "message_id": "private request content echoed by provider"},
        {"sent": True, "message_id": "m" * 257},
        {"sent": True, "message_id": 12345},
        {"sent": True, "id": "wa-safe-id"},
        {"sent": True, "message_id": "wa-safe-id", "status": "private message"},
        {"sent": True},
        {"data": {"data": {"sent": True, "message_id": "wa-safe-id"}}},
        {
            "data": {"sent": True, "message_id": "wa-safe-id"},
            "unexpected": "private request content",
        },
    ],
)
def test_whatsapp_safe_result_rejects_echoes_nesting_and_unreviewed_fields(
    result: dict[str, Any],
) -> None:
    adapter = WhatsAppTextAdapter(account="personal")

    assert adapter.safe_result_metadata(result) == {}
    assert dict(standardize_safe_metadata(adapter, result)) == {}
    assert adapter.classify_outcome(result) is Outcome.OUTCOME_UNKNOWN


@pytest.mark.parametrize(
    "to",
    ["Autumn", "Family", "; touch /tmp/not-allowed", "1555 010 2030", ""],
)
def test_whatsapp_rejects_ambiguous_or_non_deterministic_destinations(to: str) -> None:
    arguments = text_arguments()
    arguments["to"] = to
    with pytest.raises(AdapterValidationError):
        WhatsAppTextAdapter(account="personal").validate(arguments)


def test_whatsapp_preserves_exact_executable_text_and_requires_region() -> None:
    arguments = text_arguments()
    arguments["message"] = "Cafe\u0301\r\nsecond line"
    adapter = WhatsAppTextAdapter(account="personal")
    assert adapter.canonicalize(arguments) == arguments

    arguments["to"] = "15550102030"
    with pytest.raises(AdapterValidationError, match="invalid_destination"):
        adapter.validate(arguments)


@pytest.mark.asyncio
async def test_whatsapp_reconciliation_is_inconclusive_without_any_lookup() -> None:
    adapter = WhatsAppTextAdapter(account="personal")
    downstream = FakeOwnedClient()
    restricted = ReadOnlyMCPClient(downstream, adapter.reconciliation_tools)
    request = adapter_request("send_text", text_arguments())
    attempt = ExecutionAttempt(attempt_id="attempt-wa", started_at=datetime.now(UTC))

    assert await adapter.reconcile(restricted, request, attempt) is Reconciliation.INCONCLUSIVE
    assert downstream.calls == []
    assert adapter.supports_idempotency is False


@pytest.mark.asyncio
async def test_wacli_wrapper_is_pinned_no_shell_minimal_env_and_json_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, log = make_fake_wacli(tmp_path)
    marker = tmp_path / "shell-injection"
    hostile_message = f"literal $(touch {marker}) ; echo not-a-command"
    monkeypatch.setenv("WACLI_MUST_NOT_INHERIT", "secret-environment-marker")
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path))

    result = await wrapper.send_text({"to": "+15550102030", "message": hostile_message})
    logged = log.read_text(encoding="utf-8")

    assert result == {"sent": True, "message_id": "wa-safe-id"}
    assert not marker.exists()
    assert "secret-environment-marker" not in logged
    assert logged.count("CALL") == 2  # version preflight and the send
    assert "--account\npersonal\n--json\n--timeout\n15s" in logged
    assert "send\ntext\n--to\n+15550102030" in logged
    assert f"--message\n{hostile_message}\n--no-preview" in logged


@pytest.mark.asyncio
async def test_wacli_wrapper_fails_closed_on_version_drift_before_send(tmp_path: Path) -> None:
    executable, log = make_fake_wacli(tmp_path, version="0.13.0")
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path))

    with pytest.raises(WacliError) as caught:
        await wrapper.send_text(text_arguments())

    assert caught.value.code == "version_mismatch"
    assert caught.value.dispatch_may_have_occurred is False
    assert "send\ntext" not in log.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_wacli_wrapper_rejects_binary_change_after_version_preflight(tmp_path: Path) -> None:
    executable, log = make_fake_wacli(tmp_path)

    class SwappingWrapper(WacliWrapper):
        async def verify_version(self) -> None:
            await super().verify_version()
            executable.write_text(
                executable.read_text(encoding="utf-8") + "\n# changed after preflight\n",
                encoding="utf-8",
            )

    wrapper = SwappingWrapper(wrapper_config(executable, tmp_path))
    with pytest.raises(WacliError) as caught:
        await wrapper.send_text(text_arguments())

    assert caught.value.code == "executable_digest_mismatch"
    assert caught.value.dispatch_may_have_occurred is False
    assert "send\ntext" not in log.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_wacli_wrapper_executes_verified_descriptor_not_swapped_path(
    tmp_path: Path,
) -> None:
    executable, log = make_fake_wacli(tmp_path)
    malicious_marker = tmp_path / "replacement-executed"

    class SwapAfterOpenWrapper(WacliWrapper):
        opens = 0

        def _open_verified_executable(
            self,
        ) -> tuple[int, tuple[int, int, int, int, str]]:
            descriptor, signature = super()._open_verified_executable()
            self.opens += 1
            if self.opens == 2:
                replacement = tmp_path / "replacement-wacli"
                replacement.write_text(
                    "#!/bin/sh\n"
                    f"touch {str(malicious_marker)!r}\n"
                    "printf '%s' '{\"sent\":true}'\n",
                    encoding="utf-8",
                )
                replacement.chmod(0o700)
                os.replace(replacement, executable)
            return descriptor, signature

    wrapper = SwapAfterOpenWrapper(wrapper_config(executable, tmp_path))
    result = await wrapper.send_text(text_arguments())

    assert result == {"sent": True, "message_id": "wa-safe-id"}
    assert not malicious_marker.exists()
    assert log.read_text(encoding="utf-8").count("CALL") == 2


@pytest.mark.asyncio
async def test_wacli_wrapper_rejects_non_json_success_as_ambiguous(tmp_path: Path) -> None:
    executable, _ = make_fake_wacli(tmp_path, send_body="human output is forbidden")
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path))

    with pytest.raises(WacliError) as caught:
        await wrapper.send_text(text_arguments())

    assert caught.value.code == "invalid_json_output"
    assert caught.value.dispatch_may_have_occurred is True


@pytest.mark.asyncio
async def test_wacli_wrapper_timeout_is_ambiguous_and_bounded(tmp_path: Path) -> None:
    executable, _ = make_fake_wacli(tmp_path, send_prelude="sleep 2;")
    wrapper = WacliWrapper(
        wrapper_config(executable, tmp_path, timeout_seconds=0.05)
    )

    with pytest.raises(WacliError) as caught:
        await wrapper.send_text(text_arguments())

    assert caught.value.code == "process_timeout"
    assert caught.value.dispatch_may_have_occurred is True


@pytest.mark.asyncio
async def test_wacli_wrapper_kills_process_group_when_cancelled(tmp_path: Path) -> None:
    pid_file = tmp_path / "send.pid"
    executable, _ = make_fake_wacli(
        tmp_path,
        send_prelude=f"echo $$ > {str(pid_file)!r}; sleep 30;",
    )
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path))
    task = asyncio.create_task(wrapper.send_text(text_arguments()))
    for _ in range(100):
        if pid_file.exists():
            break
        await asyncio.sleep(0.01)
    assert pid_file.exists()
    process_id = int(pid_file.read_text(encoding="utf-8"))

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(100):
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.01)
    with pytest.raises(ProcessLookupError):
        os.kill(process_id, 0)


@pytest.mark.asyncio
async def test_wacli_wrapper_rejects_oversized_output_as_ambiguous(tmp_path: Path) -> None:
    executable, _ = make_fake_wacli(
        tmp_path,
        send_prelude="/usr/bin/head -c 4096 /dev/zero | /usr/bin/tr '\\000' x; exit 0;",
    )
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path, max_output_bytes=1024))

    with pytest.raises(WacliError) as caught:
        await wrapper.send_text(text_arguments())

    assert caught.value.code == "output_limit_exceeded"
    assert caught.value.dispatch_may_have_occurred is True


@pytest.mark.asyncio
async def test_whatsapp_media_is_decrypted_only_to_an_inherited_anonymous_descriptor(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    staging_root = tmp_path / "staging"
    store = make_staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    source = source_root / "photo.jpg"
    source.write_bytes(b"inert jpeg fixture")
    adapter = WhatsAppFileAdapter(
        staging_store=store,
        account="personal",
        reviewed_dispatch_enabled=True,
    )
    reference = adapter.stage_media(source, filename="photo.jpg", mime_type="image/jpeg")
    arguments = {"to": "+15550102030", "caption": "inert caption", "media": reference}
    payload = adapter.prepare_for_execution(adapter_request("send_file", arguments))
    assert payload["expected_size"] == len(b"inert jpeg fixture")
    assert len(payload["expected_sha256"]) == 64

    executable, log = make_fake_wacli(tmp_path)
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path), staging_store=store)
    result = await adapter.execute(wrapper, payload)

    assert result["sent"] is True
    logged = log.read_text(encoding="utf-8")
    assert "send\nfile\n--to\n+15550102030\n--file\n/dev/fd/" in logged
    assert "--filename\nphoto.jpg\n--mime\nimage/jpeg" in logged


@pytest.mark.asyncio
async def test_wacli_wrapper_rehashes_open_descriptor_after_adapter_prepare(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    staging_root = tmp_path / "staging"
    store = make_staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    source = source_root / "media.bin"
    source.write_bytes(b"approved-bytes")
    adapter = WhatsAppFileAdapter(
        staging_store=store,
        account="personal",
        reviewed_dispatch_enabled=True,
    )
    reference = adapter.stage_media(
        source,
        filename="media.bin",
        mime_type="application/octet-stream",
    )
    arguments = {"to": "+15550102030", "media": reference}
    payload = adapter.prepare_for_execution(adapter_request("send_file", arguments))
    (store.root / reference["staged_id"]).write_bytes(b"changed--bytes")
    executable, log = make_fake_wacli(tmp_path)
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path), staging_store=store)

    with pytest.raises(WacliError) as caught:
        await adapter.execute(wrapper, payload)

    assert caught.value.code == "media_integrity_mismatch"
    assert caught.value.dispatch_may_have_occurred is False
    assert not log.exists()


@pytest.mark.asyncio
async def test_wacli_wrapper_rejects_media_outside_staging_before_process(tmp_path: Path) -> None:
    executable, log = make_fake_wacli(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("not staged", encoding="utf-8")
    wrapper = WacliWrapper(wrapper_config(executable, tmp_path))

    with pytest.raises(WacliError) as caught:
        await wrapper.send_file(
            {
                "to": "+15550102030",
                "staged_id": "../../outside",
                "filename": "outside.txt",
                "mime_type": "text/plain",
                "expected_size": outside.stat().st_size,
                "expected_sha256": "0" * 64,
            }
        )

    assert caught.value.dispatch_may_have_occurred is False
    assert not log.exists()


@pytest.mark.asyncio
async def test_wacli_wrapper_rejects_symlinked_media_directory_before_process(
    tmp_path: Path,
) -> None:
    executable, log = make_fake_wacli(tmp_path)
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "media.bin"
    source.write_bytes(b"approved bytes")
    store = make_staging_store(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    record = store.stage_path(
        source,
        adapter="whatsapp",
        account="personal",
        filename="media.bin",
        declared_mime="application/octet-stream",
    )
    outside = tmp_path / "outside.bin"
    outside.write_bytes(record.path.read_bytes())
    record.path.unlink()
    record.path.symlink_to(outside)
    wrapper = WacliWrapper(
        wrapper_config(executable, tmp_path), staging_store=store
    )

    with pytest.raises(WacliError) as caught:
        await wrapper.send_file(
            {
                "to": "+15550102030",
                "staged_id": record.opaque_id,
                "filename": "media.bin",
                "mime_type": "application/octet-stream",
                "expected_size": record.size,
                "expected_sha256": record.sha256,
            }
        )

    assert caught.value.code == "media_integrity_mismatch"
    assert caught.value.dispatch_may_have_occurred is False
    assert not log.exists()


def test_wacli_config_requires_absolute_pinned_executable() -> None:
    with pytest.raises(ValueError, match="absolute pinned path"):
        WacliConfig(account="personal", executable=Path("wacli"))

    with pytest.raises(ValueError, match="reviewed executable digest"):
        WacliConfig(
            account="personal",
            executable=Path("/opt/reviewed/wacli"),
            reviewed_dispatch_enabled=True,
            execution_snapshot_root=Path("/private/snapshots"),
        )


@pytest.mark.asyncio
async def test_wacli_wrapper_rejects_group_writable_reviewed_executable(
    tmp_path: Path,
) -> None:
    executable, log = make_fake_wacli(tmp_path)
    config = wrapper_config(executable, tmp_path)
    executable.chmod(0o720)
    wrapper = WacliWrapper(config)

    with pytest.raises(WacliError) as caught:
        await wrapper.send_text(text_arguments())

    assert caught.value.code == "executable_permissions_unsafe"
    assert caught.value.dispatch_may_have_occurred is False
    assert not log.exists()


@pytest.mark.asyncio
async def test_wacli_dispatch_defaults_to_inactive(tmp_path: Path) -> None:
    executable, log = make_fake_wacli(tmp_path)
    config = wrapper_config(executable, tmp_path, reviewed_dispatch_enabled=False)
    with pytest.raises(WacliError) as caught:
        await WacliWrapper(config).send_text(text_arguments())
    assert caught.value.code == "provider_contract_inactive"
    assert not log.exists()


def test_whatsapp_ambiguous_wrapper_failure_remains_unknown() -> None:
    adapter = WhatsAppTextAdapter(account="personal")
    error = WacliError("process_timeout", dispatch_may_have_occurred=True)
    assert adapter.classify_outcome(error) is Outcome.OUTCOME_UNKNOWN
    assert adapter.classify_outcome(
        {"isError": True, "status": "ok", "sent": True}
    ) is Outcome.OUTCOME_UNKNOWN
    assert adapter.classify_outcome(
        {"data": {"isError": True, "sent": True}}
    ) is Outcome.OUTCOME_UNKNOWN

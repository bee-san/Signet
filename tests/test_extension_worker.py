from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from signet.extension_worker import (
    ExtensionWorker,
    ExtensionWorkerError,
    ExtensionWorkerProtocolError,
    ExtensionWorkerTimeout,
    ReviewedWorkerCommand,
    StaticWorkerCommandResolver,
    WorkerLimits,
    WorkerOperation,
)


@dataclass(frozen=True)
class Metadata:
    command_ref: str
    executable_sha256: str
    protocol_version: int
    operations: tuple[str, ...]


def worker_script(tmp_path: Path, behavior: str = "normal") -> tuple[Path, str]:
    path = tmp_path / f"worker-{behavior}"
    bodies = {
        "normal": """
request = json.loads(sys.stdin.readline())
operation = request["operation"]
payload = request["payload"]
if operation == "identity":
    result = {"operations": ["identity", "canonicalize"], "protocol_version": 1,
              "worker_id": "fake.worker", "worker_version": "1.0.0"}
elif operation == "canonicalize":
    result = {"value": payload}
else:
    result = {"value": payload}
response = {"error": None, "ok": True, "operation": operation, "protocol_version": 1,
            "request_id": request["request_id"], "result": result}
print(json.dumps(response, ensure_ascii=False, allow_nan=False, sort_keys=True,
                 separators=(",", ":")))
""",
        "environment": """
request = json.loads(sys.stdin.readline())
response = {"error": None, "ok": True, "operation": request["operation"],
            "protocol_version": 1, "request_id": request["request_id"],
            "result": {"value": dict(sorted(os.environ.items()))}}
print(json.dumps(response, sort_keys=True, separators=(",", ":")))
""",
        "nondeterministic": """
request = json.loads(sys.stdin.readline())
response = {"error": None, "ok": True, "operation": request["operation"],
            "protocol_version": 1, "request_id": request["request_id"],
            "result": {"value": time.time_ns()}}
print(json.dumps(response, sort_keys=True, separators=(",", ":")))
""",
        "invalid": "sys.stdin.readline()\nprint('{not-json')\n",
        "oversized": "sys.stdin.readline()\nsys.stdout.write('x' * 4096)\n",
        "timeout": "sys.stdin.readline()\ntime.sleep(10)\n",
        "wrong_protocol": """
request = json.loads(sys.stdin.readline())
response = {"error": None, "ok": True, "operation": request["operation"],
            "protocol_version": 2, "request_id": request["request_id"],
            "result": {"value": {}}}
print(json.dumps(response, sort_keys=True, separators=(",", ":")))
""",
    }
    source = (
        f"#!{sys.executable}\n"
        "import json\nimport os\nimport sys\nimport time\n" + bodies[behavior].lstrip()
    )
    path.write_text(source, encoding="utf-8")
    path.chmod(0o700)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def assembled_worker(
    path: Path,
    digest: str,
    *,
    operations: tuple[str, ...] = ("canonicalize",),
    limits: WorkerLimits | None = None,
) -> ExtensionWorker:
    command = ReviewedWorkerCommand(
        command_ref="fake.worker",
        executable=path,
        executable_sha256=digest,
    )
    metadata = Metadata(
        command_ref=command.command_ref,
        executable_sha256=digest,
        protocol_version=1,
        operations=operations,
    )
    return ExtensionWorker(
        metadata,
        StaticWorkerCommandResolver((command,)),
        limits=limits,
    )


@pytest.mark.asyncio
async def test_worker_runs_only_canonical_synthetic_json_with_minimal_environment(
    tmp_path: Path,
) -> None:
    path, digest = worker_script(tmp_path, "environment")
    worker = assembled_worker(path, digest)

    result = await worker.run(
        WorkerOperation.CANONICALIZE,
        {"fixture_identity": "fake:environment"},
        request_id="request-1",
        verify_determinism=False,
    )

    environment = result.result["value"]
    assert {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
    }.items() <= environment.items()
    # Darwin injects this locale-only value even when posix_spawn receives an
    # exact environment.  It contains no caller or Signet authority.
    assert set(environment) <= {
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONHASHSEED",
        "__CF_USER_TEXT_ENCODING",
    }
    assert "HOME" not in environment


@pytest.mark.asyncio
async def test_worker_verifies_digest_before_every_launch(tmp_path: Path) -> None:
    path, digest = worker_script(tmp_path)
    worker = assembled_worker(path, digest)
    path.write_text(path.read_text(encoding="utf-8") + "\n# replaced\n", encoding="utf-8")
    path.chmod(0o700)

    with pytest.raises(ExtensionWorkerError, match="worker_executable_digest_mismatch"):
        await worker.run(
            "canonicalize",
            {"fixture_identity": "fake:replacement"},
            request_id="request-2",
        )


@pytest.mark.asyncio
async def test_worker_executes_the_verified_descriptor_and_rejects_a_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest = worker_script(tmp_path)
    worker = assembled_worker(path, digest)
    marker = tmp_path / "replacement-executed"
    from signet import extension_worker as worker_module

    real_target = worker_module._execution_target

    def swap_after_verification(
        executable: Path,
        descriptor: int,
    ) -> tuple[str, tuple[str, ...], tuple[int, ...]]:
        target = real_target(executable, descriptor)
        replacement = tmp_path / "replacement-worker"
        replacement.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n",
            encoding="utf-8",
        )
        replacement.chmod(0o700)
        os.replace(replacement, executable)
        return target

    monkeypatch.setattr(worker_module, "_execution_target", swap_after_verification)

    with pytest.raises(ExtensionWorkerError, match="worker_executable_changed"):
        await worker.run(
            "canonicalize",
            {"fixture_identity": "fake:path-swap"},
            request_id="request-path-swap",
            verify_determinism=False,
        )
    assert not marker.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("behavior", "error"),
    [
        ("invalid", "worker_response_invalid_json"),
        ("oversized", "worker_output_oversized"),
        ("wrong_protocol", "worker_response_binding_mismatch"),
    ],
)
async def test_worker_rejects_malformed_oversized_and_misversioned_output(
    tmp_path: Path,
    behavior: str,
    error: str,
) -> None:
    path, digest = worker_script(tmp_path, behavior)
    limits = WorkerLimits(output_limit_bytes=1024)
    worker = assembled_worker(path, digest, limits=limits)

    with pytest.raises(ExtensionWorkerError, match=error):
        await worker.run(
            "canonicalize",
            {"fixture_identity": f"fake:{behavior}"},
            request_id="request-3",
            verify_determinism=False,
        )


@pytest.mark.asyncio
async def test_worker_timeout_terminates_and_fails_closed(tmp_path: Path) -> None:
    path, digest = worker_script(tmp_path, "timeout")
    worker = assembled_worker(
        path,
        digest,
        limits=WorkerLimits(timeout_seconds=0.05),
    )

    with pytest.raises(ExtensionWorkerTimeout, match="worker_timeout"):
        await worker.run(
            "canonicalize",
            {"fixture_identity": "fake:timeout"},
            request_id="request-4",
            verify_determinism=False,
        )


@pytest.mark.asyncio
async def test_canonicalization_is_double_run_and_nondeterminism_is_rejected(
    tmp_path: Path,
) -> None:
    path, digest = worker_script(tmp_path, "nondeterministic")
    worker = assembled_worker(path, digest)

    with pytest.raises(ExtensionWorkerProtocolError, match="worker_nondeterministic_response"):
        await worker.run(
            "canonicalize",
            {"fixture_identity": "fake:nondeterminism"},
            request_id="request-5",
        )


@pytest.mark.asyncio
async def test_worker_rejects_non_synthetic_and_secret_bearing_payloads(tmp_path: Path) -> None:
    path, digest = worker_script(tmp_path)
    worker = assembled_worker(path, digest)

    with pytest.raises(ExtensionWorkerError, match="requires_synthetic"):
        await worker.run("canonicalize", {"value": 1}, request_id="request-6")
    with pytest.raises(ExtensionWorkerError, match="secret_like"):
        await worker.run(
            "canonicalize",
            {"fixture_identity": "fake:secret", "value": "Bearer abcdefghijk"},
            request_id="request-7",
        )


def test_worker_metadata_and_command_references_are_strict(tmp_path: Path) -> None:
    path, digest = worker_script(tmp_path)
    command = ReviewedWorkerCommand("fake.worker", path, digest)
    resolver = StaticWorkerCommandResolver((command,))

    with pytest.raises(ValueError, match="protocol version"):
        ExtensionWorker(Metadata("fake.worker", digest, 2, ("identity",)), resolver)
    with pytest.raises(ValueError, match="shell"):
        ReviewedWorkerCommand("fake.shell", Path("/bin/sh"), "a" * 64)
    with pytest.raises(ValueError, match="absolute"):
        ReviewedWorkerCommand("fake.relative", Path("worker"), "a" * 64)


@pytest.mark.asyncio
async def test_worker_cancellation_terminates_child(tmp_path: Path) -> None:
    marker = tmp_path / "worker.pid"
    path = tmp_path / "worker-cancel"
    path.write_text(
        f"#!{sys.executable}\n"
        "import os\nimport sys\nimport time\n"
        f"open({str(marker)!r}, 'w').write(str(os.getpid()))\n"
        "sys.stdin.readline()\ntime.sleep(10)\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    worker = assembled_worker(path, digest, limits=WorkerLimits(timeout_seconds=20))
    task = asyncio.create_task(
        worker.run(
            "canonicalize",
            {"fixture_identity": "fake:cancellation"},
            request_id="request-8",
            verify_determinism=False,
        )
    )
    for _ in range(100):
        if marker.exists():
            break
        await asyncio.sleep(0.01)
    assert marker.exists()
    pid = int(marker.read_text(encoding="utf-8"))

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)

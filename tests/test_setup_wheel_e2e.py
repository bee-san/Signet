from __future__ import annotations

import json
import os
import subprocess
import zipfile
from pathlib import Path


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_installed_wheel_setup_interruption_resume_rerun_and_conflict_refusal(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    built = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(dist)],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert built.returncode == 0, built.stderr
    wheels = tuple(dist.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as wheel:
        assert any(name.endswith("/share/man/man1/signet.1") for name in wheel.namelist())

    environment_dir = tmp_path / "environment"
    created = subprocess.run(
        ["uv", "venv", "--python", "3.12", str(environment_dir)],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert created.returncode == 0, created.stderr
    installed = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(environment_dir / "bin" / "python"),
            str(wheels[0]),
        ],
        check=False,
        capture_output=True,
        env={**os.environ, "UV_LINK_MODE": "copy"},
        text=True,
        timeout=180,
    )
    assert installed.returncode == 0, installed.stderr
    assert (environment_dir / "share" / "man" / "man1" / "signet.1").is_file()

    fakes = tmp_path / "fakes"
    fakes.mkdir()
    (fakes / "sitecustomize.py").write_text(
        """
import json
import os
from pathlib import Path

import signet.setup_cli as setup_cli


class InstalledFakePlatform:
    def __init__(self, *, output=print):
        self.output = output

    @staticmethod
    def _events(spec):
        return spec.root.parent / "fake-platform-events.json"

    def preflight(self, spec):
        return None

    def validate_private_paths(self, spec, setup_id):
        return None

    def apply(self, step, spec, setup_id):
        path = self._events(spec)
        events = json.loads(path.read_text()) if path.exists() else []
        events.append(step)
        path.write_text(json.dumps(events))
        fail_step = os.environ.get("SIGNET_E2E_FAIL_ONCE_STEP")
        sentinel = spec.root.parent / f"failed-{step}"
        if step == fail_step and not sentinel.exists():
            sentinel.write_text("injected once")
            raise RuntimeError("private injected detail")

    def rollback(self, step, spec, setup_id):
        return None

    def service_status(self, spec):
        return {"signet-mcp": "active", "signet-web": "active"}


setup_cli.ProductionSetupPlatform = InstalledFakePlatform
""".lstrip(),
        encoding="utf-8",
    )

    home = tmp_path / "home"
    home.mkdir()
    root = home / ".local" / "share" / "signet"
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "PATH": f"{environment_dir / 'bin'}:{environment.get('PATH', '')}",
            "PYTHONPATH": str(fakes),
            "SIGNET_E2E_FAIL_ONCE_STEP": "database",
        }
    )
    command = [
        str(environment_dir / "bin" / "signet"),
        "setup",
        "--yes",
        "--no-open-browser",
        "--origin",
        "https://signet.example",
        "--profile",
        "personal",
    ]

    interrupted = _run(command, cwd=home, environment=environment)
    assert interrupted.returncode == 2
    assert "Recovery:" in interrupted.stderr
    assert "private injected detail" not in interrupted.stderr
    assert "setup_id" not in json.loads(interrupted.stdout)
    failed_journal = json.loads((root / ".setup-journal.json").read_text(encoding="utf-8"))
    assert failed_journal["status"] == "failed"
    assert failed_journal["steps"][4]["status"] == "failed"

    resumed = _run(command, cwd=home, environment=environment)
    assert resumed.returncode == 0, resumed.stderr
    assert '"automatic_steps"' in resumed.stdout
    assert '"human_ceremonies"' in resumed.stdout
    assert '"deferred_provider_proof"' in resumed.stdout
    assert "/reload-mcp" in resumed.stdout
    assert "private injected detail" not in resumed.stdout

    rerun = _run(command, cwd=home, environment=environment)
    assert rerun.returncode == 0, rerun.stderr
    journal = json.loads((root / ".setup-journal.json").read_text(encoding="utf-8"))
    assert journal["status"] == "completed"
    assert all(step["attempts"] == 1 for step in journal["steps"] if step["name"] != "database")

    authenticators = _run(
        [
            command[0],
            "authenticators",
            "open",
            "--root",
            str(root),
            "--no-open-browser",
        ],
        cwd=home,
        environment=environment,
    )
    assert authenticators.returncode == 0, authenticators.stderr
    assert "HUMAN CEREMONY" in authenticators.stdout
    assert "https://signet.example/authenticators" in authenticators.stdout
    assert next(step for step in journal["steps"] if step["name"] == "database")["attempts"] == 2

    conflict = _run([*command, "--owner", "user:other"], cwd=home, environment=environment)
    assert conflict.returncode == 2
    assert "different setup specification" in conflict.stderr
    assert "Refused to adopt or overwrite" in conflict.stderr

    help_result = _run(
        [str(environment_dir / "bin" / "signet"), "authenticators", "open", "--help"],
        cwd=home,
        environment=environment,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "named passkey and TOTP" in help_result.stdout

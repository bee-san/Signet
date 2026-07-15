from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from signet.adapters.fastmail import FASTMAIL_SEND_SCHEMA, FastmailAdapter
from signet.adapters.whatsapp import WHATSAPP_FILE_SCHEMA, WHATSAPP_TEXT_SCHEMA
from signet.wacli_wrapper import (
    DEFAULT_WACLI_EXECUTABLE,
    REVIEWED_WACLI_VERSION,
    WacliConfig,
)

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ROOT / "spec/providers"


def load(name: str) -> dict[str, Any]:
    with (PROVIDERS / name).open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict)
    return value


def test_fastmail_characterization_matches_implementation_and_never_enables_live_send() -> None:
    fixture = load("fastmail-send-email-adapter-v1.json")
    adapter = fixture["adapter"]
    Draft202012Validator.check_schema(adapter["input_schema"])

    assert fixture["must_not_dispatch"] is True
    assert fixture["runtime_activation_default"] == "disabled"
    assert FastmailAdapter().reviewed_dispatch_enabled is False
    assert fixture["schema_status"] == "live_tools_list_capture_required_before_enablement"
    assert adapter["input_schema"] == dict(FASTMAIL_SEND_SCHEMA)
    assert adapter["reconciliation_tools"] == sorted(FastmailAdapter.reconciliation_tools)
    assert fixture["execution"]["provider_idempotency_key"] is None
    assert fixture["reconciliation"]["confirmed_no_effect_supported"] is False


def test_owned_wacli_contract_matches_pinned_wrapper_and_adapter_schemas() -> None:
    fixture = load("wacli-owned-wrapper-v1.json")
    executable = fixture["executable"]
    tools = fixture["tools"]
    for tool in tools.values():
        Draft202012Validator.check_schema(tool["input_schema"])

    assert fixture["must_not_dispatch"] is True
    assert fixture["runtime_activation_default"] == "disabled"
    assert WacliConfig(account="fixture").reviewed_dispatch_enabled is False
    assert executable["path"] == str(DEFAULT_WACLI_EXECUTABLE)
    assert executable["version"] == REVIEWED_WACLI_VERSION
    assert executable["shell"] is False
    assert executable["output"] == "single_json_object"
    assert tools["send_text"]["input_schema"] == dict(WHATSAPP_TEXT_SCHEMA)
    assert tools["send_file"]["input_schema"] == dict(WHATSAPP_FILE_SCHEMA)
    assert fixture["media_boundary"]["size_and_sha256_reverified_after_open"] is True
    assert fixture["reconciliation"]["read_only_tools"] == []
    assert fixture["reconciliation"]["provider_idempotency_key"] is None
    assert fixture["reconciliation"]["decision"] == "inconclusive"

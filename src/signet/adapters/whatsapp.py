"""Owned WhatsApp adapter backed by the bounded :mod:`signet.wacli_wrapper`.

Only deterministic phone/JID destinations are accepted.  Contact names are
excluded because non-interactive ambiguity resolution could target the wrong
person.  Media remains in Signet's local staging root until approval.  ``wacli``
has no reviewed stable idempotency key and local history cannot uniquely prove
an ambiguous repeated send, so reconciliation is unconditionally inconclusive.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from signet.adapters.base import (
    AdapterProtocolError,
    AdapterRequest,
    AdapterValidationError,
    ApprovalSummary,
    DetailBlock,
    ExecutionAttempt,
    MCPClient,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    conservative_outcome,
    copy_json_object,
    redact_json,
)
from signet.staging import StagedFile, StagingError, StagingStore
from signet.wacli_wrapper import WacliError, normalize_destination, validate_message

_COMMON_PROPERTIES: dict[str, Any] = {
    "to": {"type": "string", "minLength": 7, "maxLength": 64},
    "reply_to": {"type": "string", "minLength": 1, "maxLength": 512},
    "reply_to_sender": {"type": "string", "minLength": 7, "maxLength": 64},
}
_OPAQUE_MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~:@/+=-]{0,255}$")
_WHATSAPP_RESULT_FIELDS = frozenset({"sent", "message_id", "isError"})

WHATSAPP_TEXT_SCHEMA: Mapping[str, Any] = MappingProxyType(
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://signet.local/schemas/wacli-send-text-v1.json",
        "type": "object",
        "additionalProperties": False,
        "required": ["to", "message"],
        "properties": {
            **_COMMON_PROPERTIES,
            "message": {"type": "string", "minLength": 1, "maxLength": 65_536},
        },
    }
)

WHATSAPP_FILE_SCHEMA: Mapping[str, Any] = MappingProxyType(
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://signet.local/schemas/wacli-send-file-v1.json",
        "type": "object",
        "additionalProperties": False,
        "required": ["to", "media"],
        "properties": {
            **_COMMON_PROPERTIES,
            "caption": {"type": "string", "maxLength": 65_536},
            "media": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "staged_id",
                    "filename",
                    "mime_type",
                    "detected_mime",
                    "size",
                    "sha256",
                ],
                "properties": {
                    "staged_id": {"type": "string", "pattern": "^stg_[A-Za-z0-9_]+$"},
                    "filename": {"type": "string", "minLength": 1, "maxLength": 255},
                    "mime_type": {"type": "string", "minLength": 3, "maxLength": 255},
                    "detected_mime": {
                        "type": "string",
                        "minLength": 3,
                        "maxLength": 255,
                    },
                    "size": {"type": "integer", "minimum": 0, "maximum": 50 * 1024 * 1024},
                    "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                },
            },
        },
    }
)

def _reviewed_send_result(result: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Validate the exact owned-wrapper result, with one optional data envelope."""

    if not all(isinstance(key, str) for key in result):
        return None
    payload: Mapping[str, Any] = result
    if "data" in result:
        if set(result) not in ({"data"}, {"data", "isError"}):
            return None
        if "isError" in result and result["isError"] is not False:
            return None
        nested = result.get("data")
        if not isinstance(nested, Mapping) or not all(isinstance(key, str) for key in nested):
            return None
        payload = nested
    if set(payload) not in (
        {"sent", "message_id"},
        {"sent", "message_id", "isError"},
    ):
        return None
    if not set(payload) <= _WHATSAPP_RESULT_FIELDS:
        return None
    if payload.get("sent") is not True:
        return None
    if "isError" in payload and payload["isError"] is not False:
        return None
    message_id = payload.get("message_id")
    if not isinstance(message_id, str) or not _OPAQUE_MESSAGE_ID_RE.fullmatch(message_id):
        return None
    return payload


class WhatsAppAdapter:
    """Adapter for one exact owned wrapper tool: ``send_text`` or ``send_file``."""

    adapter_version = "1"
    downstream_alias = "whatsapp"
    communication_send = True
    supports_idempotency = False
    reconciliation_tools: frozenset[str] = frozenset()
    reconciliation_characterization = (
        "wacli exposes no reviewed idempotency key; local history cannot uniquely prove "
        "an ambiguous repeated send, so reconciliation makes no call and is inconclusive"
    )

    def __init__(
        self,
        *,
        tool_name: str = "send_text",
        staging_store: StagingStore | None = None,
        account: str = "configured-account",
        reviewed_dispatch_enabled: bool = False,
    ) -> None:
        if tool_name not in {"send_text", "send_file"}:
            raise ValueError("WhatsApp adapter tool must be send_text or send_file")
        if not account:
            raise ValueError("WhatsApp account scope is required")
        self.tool_name = tool_name
        self.adapter_id = f"whatsapp.{tool_name}"
        self.input_schema = (
            WHATSAPP_TEXT_SCHEMA if tool_name == "send_text" else WHATSAPP_FILE_SCHEMA
        )
        self.staging_store = staging_store
        self.account = account
        self.reviewed_dispatch_enabled = reviewed_dispatch_enabled
        self._validator = Draft202012Validator(dict(self.input_schema))

    def validate(self, arguments: Mapping[str, Any]) -> None:
        detached = copy_json_object(arguments)
        try:
            self._validator.validate(detached)
        except ValidationError as exc:
            path = ".".join(str(part) for part in exc.absolute_path) or "arguments"
            raise AdapterValidationError(f"invalid WhatsApp arguments at {path}") from exc
        try:
            normalize_destination(cast(str, detached["to"]))
            if self.tool_name == "send_text":
                validate_message(cast(str, detached["message"]))
            else:
                caption = detached.get("caption")
                if isinstance(caption, str) and "\x00" in caption:
                    raise WacliError("invalid_caption", dispatch_may_have_occurred=False)
            reply_sender = detached.get("reply_to_sender")
            if isinstance(reply_sender, str):
                normalize_destination(reply_sender)
        except WacliError as exc:
            raise AdapterValidationError(exc.code) from exc
        reply_to = detached.get("reply_to")
        if isinstance(reply_to, str) and "\x00" in reply_to:
            raise AdapterValidationError("invalid_reply")

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        return copy_json_object(arguments)

    def stage_media(
        self,
        source: Path,
        *,
        filename: str,
        mime_type: str,
    ) -> dict[str, Any]:
        """Create a local media reference without invoking ``wacli``."""
        if self.staging_store is None:
            raise StagingError("WhatsApp media staging is not configured")
        record = self.staging_store.stage_path(
            source,
            adapter=self.downstream_alias,
            account=self.account,
            filename=filename,
            declared_mime=mime_type,
        )
        return self._media_reference(record)

    @staticmethod
    def _media_reference(record: StagedFile) -> dict[str, Any]:
        return {
            "staged_id": record.opaque_id,
            "filename": record.filename,
            "mime_type": record.declared_mime,
            "detected_mime": record.detected_mime,
            "size": record.size,
            "sha256": record.sha256,
        }

    def summarize_for_web(self, arguments: Mapping[str, Any]) -> ApprovalSummary:
        canonical = self.canonicalize(arguments)
        blocks = [DetailBlock("To", "whatsapp_destination", canonical["to"])]
        if self.tool_name == "send_text":
            blocks.append(DetailBlock("Message", "plain_text", canonical["message"]))
            title = "WhatsApp message"
        else:
            blocks.append(DetailBlock("Caption", "plain_text", canonical.get("caption", "")))
            blocks.append(DetailBlock("Media", "file", canonical["media"]))
            title = cast(dict[str, Any], canonical["media"])["filename"]
        if "reply_to" in canonical:
            blocks.append(
                DetailBlock(
                    "Reply context",
                    "reply",
                    {
                        "message_id": canonical["reply_to"],
                        "sender": canonical.get("reply_to_sender"),
                    },
                )
            )
        return ApprovalSummary(
            service="WhatsApp",
            action=self.tool_name,
            title=title,
            destination_summary=cast(str, canonical["to"]),
            detail_blocks=tuple(blocks),
            warnings=(
                "No automatic retry is available after an ambiguous send.",
                *(
                    ("Declared and detected media MIME types differ.",)
                    if self.tool_name == "send_file"
                    and canonical["media"]["mime_type"]
                    != canonical["media"]["detected_mime"]
                    else ()
                ),
            ),
        )

    def redact_for_audit(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        canonical = self.canonicalize(arguments)
        return redact_json(
            canonical,
            sensitive_keys={"to", "message", "caption", "reply_to_sender", "staged_id"},
        )

    def prepare_for_execution(self, request: AdapterRequest) -> dict[str, Any]:
        if request.downstream_alias != self.downstream_alias or request.tool_name != self.tool_name:
            raise AdapterValidationError("request does not match the WhatsApp adapter")
        if request.account != self.account:
            raise AdapterValidationError("request has the wrong WhatsApp account scope")
        payload = self.canonicalize(request.arguments)
        if self.tool_name == "send_file":
            if self.staging_store is None:
                raise StagingError("WhatsApp media staging is not configured")
            reference = cast(dict[str, Any], payload.pop("media"))
            record = self.staging_store.resolve(
                cast(str, reference["staged_id"]),
                adapter=self.downstream_alias,
                account=self.account,
            )
            if self._media_reference(record) != reference:
                raise StagingError("frozen media metadata no longer matches staging")
            payload.update(
                {
                    "file_path": str(record.path),
                    "filename": record.filename,
                    "mime_type": record.declared_mime,
                    "expected_size": record.size,
                    "expected_sha256": record.sha256,
                }
            )
        return payload

    async def execute(
        self, downstream: MCPClient, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not self.reviewed_dispatch_enabled:
            raise WacliError("provider_contract_inactive", dispatch_may_have_occurred=False)
        detached = copy_json_object(payload)
        if self.tool_name == "send_text":
            self.validate(detached)
        else:
            expected = {"to", "file_path", "filename", "mime_type"}
            if not expected <= set(detached):
                raise AdapterValidationError("prepared WhatsApp media payload is incomplete")
        result = await downstream.call_tool(self.tool_name, detached)
        if not isinstance(result, Mapping):
            raise AdapterProtocolError("wacli wrapper result must be a JSON object")
        return copy_json_object(result)

    def classify_outcome(self, result_or_error: object) -> Outcome:
        common = conservative_outcome(result_or_error)
        if common is Outcome.DEFINITE_FAILURE:
            return common
        if (
            isinstance(result_or_error, Mapping)
            and _reviewed_send_result(result_or_error) is not None
        ):
            return Outcome.SUCCEEDED
        return Outcome.OUTCOME_UNKNOWN

    async def reconcile(
        self,
        downstream: ReadOnlyMCPClient,
        request: AdapterRequest,
        attempt: ExecutionAttempt,
    ) -> Reconciliation:
        del downstream, request, attempt
        return Reconciliation.INCONCLUSIVE

    def safe_result_metadata(self, downstream_result: Mapping[str, Any]) -> dict[str, Any]:
        payload = _reviewed_send_result(downstream_result)
        if payload is None:
            return {}
        return {"status": "sent", "chat_message_id": payload["message_id"]}


class WhatsAppTextAdapter(WhatsAppAdapter):
    def __init__(
        self,
        *,
        staging_store: StagingStore | None = None,
        account: str = "configured-account",
        reviewed_dispatch_enabled: bool = False,
    ) -> None:
        super().__init__(
            tool_name="send_text",
            staging_store=staging_store,
            account=account,
            reviewed_dispatch_enabled=reviewed_dispatch_enabled,
        )


class WhatsAppFileAdapter(WhatsAppAdapter):
    def __init__(
        self,
        *,
        staging_store: StagingStore | None = None,
        account: str = "configured-account",
        reviewed_dispatch_enabled: bool = False,
    ) -> None:
        super().__init__(
            tool_name="send_file",
            staging_store=staging_store,
            account=account,
            reviewed_dispatch_enabled=reviewed_dispatch_enabled,
        )

"""Fastmail send adapter with local attachment staging.

The public input contract uses opaque Signet attachment references.  Provider
uploads happen only while executing an approved request, immediately before the
single ``send_email`` call.  The currently reviewed Fastmail MCP surface does not
promise a stable idempotency key.  Reconciliation can therefore confirm an
effect only when a captured result contains a provider message/submission ID that
the read-only sent-mail lookup returns; an empty search is never treated as proof
of no effect.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from collections.abc import Mapping
from email import policy
from email.headerregistry import Address
from email.parser import Parser
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
    DispatchError,
    ExecutionAttempt,
    MCPClient,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    conservative_outcome,
    copy_json_object,
    redact_json,
)
from signet.models import AttachmentReference
from signet.staging import StagedFile, StagingError, StagingStore

_HEADER_FORBIDDEN = frozenset(
    {
        "\r",
        "\n",
        "\x00",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_OPAQUE_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~:@/+=-]{0,255}$")
_FASTMAIL_RESULT_FIELDS = frozenset(
    {"messageId", "submissionId", "threadId", "status", "isError"}
)
_FASTMAIL_PROVIDER_STATUSES = frozenset({"sent", "submitted"})
FASTMAIL_SEND_SCHEMA: Mapping[str, Any] = MappingProxyType(
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["from", "to", "subject", "body"],
        "properties": {
            "from": {"type": "string", "minLength": 3, "maxLength": 998},
            "to": {
                "type": "array",
                "items": {"type": "string", "minLength": 3, "maxLength": 998},
                "maxItems": 100,
            },
            "cc": {
                "type": "array",
                "items": {"type": "string", "minLength": 3, "maxLength": 998},
                "maxItems": 100,
            },
            "bcc": {
                "type": "array",
                "items": {"type": "string", "minLength": 3, "maxLength": 998},
                "maxItems": 100,
            },
            "subject": {"type": "string", "maxLength": 998},
            "body": {"type": "string", "maxLength": 2_000_000},
            "attachments": {
                "type": "array",
                "maxItems": 20,
                "items": {
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
                        "staged_id": {
                            "type": "string",
                            "pattern": "^stg_[A-Za-z0-9_]+$",
                        },
                        "filename": {"type": "string", "minLength": 1, "maxLength": 255},
                        "mime_type": {"type": "string", "minLength": 3, "maxLength": 255},
                        "detected_mime": {
                            "type": "string",
                            "minLength": 3,
                            "maxLength": 255,
                        },
                        "size": {"type": "integer", "minimum": 0, "maximum": 25 * 1024 * 1024},
                        "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    },
                },
            },
        },
    }
)


def _contains_forbidden_header_character(value: str) -> bool:
    return any(character in value for character in _HEADER_FORBIDDEN)


def _parse_mailbox(value: str) -> Address:
    if _contains_forbidden_header_character(value):
        raise AdapterValidationError("email address contains a forbidden header character")
    message = Parser(policy=policy.default).parsestr(f"To: {value}\n\n")
    header = message["To"]
    if header is None or header.defects:
        raise AdapterValidationError("email address is invalid")
    addresses = tuple(header.addresses)
    if len(addresses) != 1 or any(group.display_name is not None for group in header.groups):
        raise AdapterValidationError("each recipient entry must contain exactly one mailbox")
    address = addresses[0]
    if not address.username or not address.domain:
        raise AdapterValidationError("email address must include a local part and domain")
    try:
        domain = address.domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise AdapterValidationError("email domain is invalid") from exc
    return Address(
        display_name=unicodedata.normalize("NFC", address.display_name).strip(),
        username=unicodedata.normalize("NFC", address.username),
        domain=domain,
    )


def _mailbox_key(value: str) -> str:
    address = _parse_mailbox(value)
    return f"{address.username.casefold()}@{address.domain.lower()}"


def _normalize_header(value: str, *, name: str) -> str:
    normalized = unicodedata.normalize("NFC", value).strip()
    if _contains_forbidden_header_character(normalized):
        raise AdapterValidationError(f"{name} contains a forbidden header character")
    return normalized


def _opaque_provider_id(value: object) -> str | None:
    if isinstance(value, str) and _OPAQUE_PROVIDER_ID_RE.fullmatch(value):
        return value
    return None


def _one_level_result_payload(value: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Accept a direct result or one explicit MCP-style ``data`` envelope."""

    if not all(isinstance(key, str) for key in value):
        return None
    if "data" not in value:
        return value
    if set(value) not in ({"data"}, {"data", "isError"}):
        return None
    if "isError" in value and value["isError"] is not False:
        return None
    payload = value.get("data")
    if not isinstance(payload, Mapping) or not all(isinstance(key, str) for key in payload):
        return None
    return payload


def _reviewed_attachment_id(value: Mapping[str, Any]) -> str | None:
    payload = _one_level_result_payload(value)
    if payload is None or set(payload) not in (
        {"attachmentId"},
        {"attachmentId", "isError"},
    ):
        return None
    if "isError" in payload and payload["isError"] is not False:
        return None
    return _opaque_provider_id(payload.get("attachmentId"))


def _reviewed_send_result(value: Mapping[str, Any]) -> Mapping[str, Any] | None:
    payload = _one_level_result_payload(value)
    if payload is None or not set(payload) <= _FASTMAIL_RESULT_FIELDS:
        return None
    if "isError" in payload and payload["isError"] is not False:
        return None
    if not ({"messageId", "submissionId"} & set(payload)):
        return None
    for field in ("messageId", "submissionId", "threadId"):
        if field in payload and _opaque_provider_id(payload[field]) is None:
            return None
    status = payload.get("status")
    if "status" in payload and status not in _FASTMAIL_PROVIDER_STATUSES:
        return None
    return payload


def _candidate_send_identity(value: Mapping[str, Any] | None) -> str | None:
    """Read a bounded provider identity from one read-only search candidate."""

    if value is None:
        return None
    for key in ("messageId", "submissionId"):
        candidate = _opaque_provider_id(value.get(key))
        if candidate is not None:
            return candidate
    return None


def _candidate_objects(result: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    for key in ("messages", "emails", "results", "items"):
        candidates = result.get(key)
        if isinstance(candidates, list):
            return tuple(candidate for candidate in candidates if isinstance(candidate, Mapping))
    data = result.get("data")
    if isinstance(data, Mapping):
        for key in ("messages", "emails", "results", "items"):
            candidates = data.get(key)
            if isinstance(candidates, list):
                return tuple(
                    candidate for candidate in candidates if isinstance(candidate, Mapping)
                )
    return ()


class FastmailAdapter:
    """Reviewed adapter for Fastmail's immediate ``send_email`` mutation."""

    adapter_id = "fastmail.send"
    adapter_version = "1"
    downstream_alias = "fastmail"
    tool_name = "send_email"
    communication_send = True
    supports_idempotency = False
    reconciliation_tools = frozenset({"search_email"})
    input_schema = FASTMAIL_SEND_SCHEMA
    reconciliation_characterization = (
        "search_email can confirm a captured provider ID in Sent mail; it cannot prove "
        "non-delivery and never returns confirmed_no_effect"
    )

    def __init__(
        self,
        *,
        staging_store: StagingStore | None = None,
        account: str = "configured-account",
        reviewed_dispatch_enabled: bool = False,
    ) -> None:
        if not account:
            raise ValueError("Fastmail account scope is required")
        self.staging_store = staging_store
        self.account = account
        self.reviewed_dispatch_enabled = reviewed_dispatch_enabled
        self._validator = Draft202012Validator(dict(FASTMAIL_SEND_SCHEMA))

    def validate(self, arguments: Mapping[str, Any]) -> None:
        detached = copy_json_object(arguments)
        try:
            self._validator.validate(detached)
        except ValidationError as exc:
            path = ".".join(str(part) for part in exc.absolute_path) or "arguments"
            raise AdapterValidationError(f"invalid Fastmail arguments at {path}") from exc

        _parse_mailbox(cast(str, detached["from"]))
        recipient_count = 0
        seen: set[str] = set()
        for field in ("to", "cc", "bcc"):
            recipients = detached.get(field, [])
            for recipient in cast(list[str], recipients):
                recipient_count += 1
                key = _mailbox_key(recipient)
                if key in seen:
                    raise AdapterValidationError(
                        "a mailbox appears in more than one recipient slot"
                    )
                seen.add(key)
        if recipient_count == 0:
            raise AdapterValidationError("at least one recipient is required")
        if recipient_count > 100:
            raise AdapterValidationError("at most 100 total recipients are allowed")
        _normalize_header(cast(str, detached["subject"]), name="subject")
        if "\x00" in cast(str, detached["body"]):
            raise AdapterValidationError("body contains a NUL character")
        for attachment in cast(list[dict[str, Any]], detached.get("attachments", [])):
            if not _SHA256_RE.fullmatch(cast(str, attachment["sha256"])):
                raise AdapterValidationError("attachment hash is invalid")
            _normalize_header(cast(str, attachment["filename"]), name="attachment filename")

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        return copy_json_object(arguments)

    def freeze_attachments(
        self, arguments: Mapping[str, Any]
    ) -> tuple[AttachmentReference, ...]:
        canonical = self.canonicalize(arguments)
        references = cast(list[dict[str, Any]], canonical["attachments"])
        if references and self.staging_store is None:
            raise StagingError("Fastmail attachment staging is not configured")
        frozen: list[AttachmentReference] = []
        for reference in references:
            store = self.staging_store
            if store is None:
                raise StagingError("Fastmail attachment staging is not configured")
            record = store.resolve(
                cast(str, reference["staged_id"]),
                adapter=self.downstream_alias,
                account=self.account,
            )
            if self._attachment_reference(record) != reference:
                raise StagingError("frozen attachment metadata no longer matches staging")
            frozen.append(
                AttachmentReference(
                    attachment_id=record.opaque_id,
                    filename=record.filename,
                    mime_type=record.declared_mime,
                    size_bytes=record.size,
                    sha256=record.sha256,
                    storage_path=str(record.path),
                )
            )
        return tuple(frozen)

    def stage_attachment(
        self,
        source: Path,
        *,
        filename: str,
        mime_type: str,
    ) -> dict[str, Any]:
        """Create an opaque local reference without any provider call."""
        if self.staging_store is None:
            raise StagingError("Fastmail attachment staging is not configured")
        record = self.staging_store.stage_path(
            source,
            adapter=self.downstream_alias,
            account=self.account,
            filename=filename,
            declared_mime=mime_type,
        )
        return self._attachment_reference(record)

    @staticmethod
    def _attachment_reference(record: StagedFile) -> dict[str, Any]:
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
        recipients = [*canonical["to"], *canonical["cc"], *canonical["bcc"]]
        attachments = cast(list[dict[str, Any]], canonical["attachments"])
        warnings = tuple(
            f"Declared and detected MIME differ for {attachment['filename']}"
            for attachment in attachments
            if attachment["mime_type"] != attachment["detected_mime"]
        )
        blocks = (
            DetailBlock("From", "mailbox", canonical["from"]),
            DetailBlock(
                "Recipients",
                "recipient_groups",
                {"to": canonical["to"], "cc": canonical["cc"], "bcc": canonical["bcc"]},
            ),
            DetailBlock("Subject", "text", canonical["subject"]),
            DetailBlock("Message", "plain_text", canonical["body"]),
            DetailBlock("Attachments", "files", attachments),
        )
        return ApprovalSummary(
            service="Fastmail",
            action="send_email",
            title=canonical["subject"] or "Email with no subject",
            destination_summary=", ".join(cast(list[str], recipients)),
            detail_blocks=blocks,
            warnings=warnings,
        )

    def redact_for_audit(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        canonical = self.canonicalize(arguments)
        redacted = redact_json(
            canonical,
            sensitive_keys={
                "from",
                "to",
                "cc",
                "bcc",
                "subject",
                "body",
                "filename",
                "staged_id",
            },
        )
        redacted["recipient_count"] = sum(len(canonical[field]) for field in ("to", "cc", "bcc"))
        redacted["attachment_count"] = len(canonical["attachments"])
        return redacted

    def prepare_for_execution(self, request: AdapterRequest) -> dict[str, Any]:
        if request.downstream_alias != self.downstream_alias or request.tool_name != self.tool_name:
            raise AdapterValidationError("request does not match the Fastmail adapter")
        if request.account != self.account:
            raise AdapterValidationError("request has the wrong Fastmail account scope")
        payload = self.canonicalize(request.arguments)
        references = cast(list[dict[str, Any]], payload["attachments"])
        resolved: list[dict[str, Any]] = []
        if references and self.staging_store is None:
            raise StagingError("Fastmail attachment staging is not configured")
        for reference in references:
            store = self.staging_store
            if store is None:
                raise StagingError("Fastmail attachment staging is not configured")
            record, content = store.read_verified(
                cast(str, reference["staged_id"]),
                adapter=self.downstream_alias,
                account=self.account,
            )
            if self._attachment_reference(record) != reference:
                raise StagingError("frozen attachment metadata no longer matches staging")
            resolved.append(
                {
                    **reference,
                    "content_base64": base64.b64encode(content).decode("ascii"),
                }
            )
        payload["_signet_resolved_attachments"] = resolved
        return payload

    async def execute(
        self, downstream: MCPClient, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not self.reviewed_dispatch_enabled:
            raise DispatchError(
                "Fastmail provider contract is not activated",
                dispatch_may_have_occurred=False,
            )
        detached = copy_json_object(payload)
        resolved_value = detached.pop("_signet_resolved_attachments", [])
        if not isinstance(resolved_value, list):
            raise AdapterValidationError("resolved attachment payload is invalid")
        self.validate(detached)

        uploaded: list[dict[str, Any]] = []
        for item in resolved_value:
            if not isinstance(item, dict):
                raise AdapterValidationError("resolved attachment payload is invalid")
            upload_arguments = {
                "filename": item.get("filename"),
                "content_type": item.get("mime_type"),
                "content_base64": item.get("content_base64"),
            }
            try:
                result = await downstream.call_tool("upload_attachment", upload_arguments)
            except Exception as exc:
                raise DispatchError(
                    "Fastmail attachment upload failed before email dispatch",
                    dispatch_may_have_occurred=False,
                ) from exc
            if not isinstance(result, Mapping) or result.get("isError") is True:
                raise DispatchError(
                    "Fastmail attachment upload was rejected before email dispatch",
                    dispatch_may_have_occurred=False,
                )
            attachment_id = _reviewed_attachment_id(result)
            if attachment_id is None:
                raise DispatchError(
                    "Fastmail attachment upload returned no reviewed identifier",
                    dispatch_may_have_occurred=False,
                )
            uploaded.append(
                {
                    "attachment_id": attachment_id,
                    "filename": item["filename"],
                    "mime_type": item["mime_type"],
                }
            )

        send_arguments = detached
        if "attachments" in send_arguments or uploaded:
            send_arguments["attachments"] = uploaded
        result = await downstream.call_tool(self.tool_name, send_arguments)
        if not isinstance(result, Mapping):
            raise AdapterProtocolError("Fastmail send result must be a JSON object")
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
        if request.downstream_alias != self.downstream_alias or request.tool_name != self.tool_name:
            raise AdapterValidationError("request does not match the Fastmail adapter")
        identity = _candidate_send_identity(attempt.downstream_result)
        if identity is None:
            return Reconciliation.INCONCLUSIVE
        result = await downstream.call_tool(
            "search_email",
            {"query": identity, "folder": "Sent", "limit": 10},
        )
        if result.get("isError") is True or result.get("is_error") is True:
            return Reconciliation.INCONCLUSIVE
        if any(
            _candidate_send_identity(candidate) == identity
            for candidate in _candidate_objects(result)
        ):
            return Reconciliation.CONFIRMED_EFFECT
        return Reconciliation.INCONCLUSIVE

    def safe_result_metadata(self, downstream_result: Mapping[str, Any]) -> dict[str, Any]:
        payload = _reviewed_send_result(downstream_result)
        if payload is None:
            return {}
        safe: dict[str, Any] = {}
        if "messageId" in payload:
            safe["message_id"] = payload["messageId"]
        if "submissionId" in payload:
            safe["submission_id"] = payload["submissionId"]
        if "threadId" in payload:
            safe["thread_id"] = payload["threadId"]
        if "status" in payload:
            safe["provider_status"] = payload["status"]
        return safe

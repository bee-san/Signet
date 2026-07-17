"""Provider-neutral effect evidence and conservative policy recommendations.

MCP annotations, tool names, schemas, and plugin mappings are evidence.  None of
them is an authorization decision.  Only an authenticated human review records a
final :class:`EffectProfile`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from signet.canonical import canonical_json, sha256_hex


class EffectError(ValueError):
    """Effect evidence or a reviewed conclusion is malformed."""


class MutationEffect(StrEnum):
    NONE = "none"
    ADDITIVE = "additive"
    MUTATING = "mutating"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class TriState(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    @classmethod
    def from_hint(cls, value: object) -> TriState:
        if value is True:
            return cls.TRUE
        if value is False:
            return cls.FALSE
        return cls.UNKNOWN


class RecommendedMode(StrEnum):
    DENY = "deny"
    APPROVAL = "approval"
    PASSTHROUGH = "passthrough"


class EvidenceSource(StrEnum):
    MCP_ANNOTATIONS = "mcp_annotations"
    NAME_SCHEMA_HEURISTIC = "name_schema_heuristic"
    PLUGIN_PROPOSAL = "plugin_proposal"


@dataclass(frozen=True, slots=True)
class EffectProfile:
    mutation: MutationEffect = MutationEffect.UNKNOWN
    external_communication: TriState = TriState.UNKNOWN
    code_execution: TriState = TriState.UNKNOWN
    privilege_change: TriState = TriState.UNKNOWN
    open_world: TriState = TriState.UNKNOWN
    idempotent: TriState = TriState.UNKNOWN

    def as_dict(self) -> dict[str, str]:
        return {
            "mutation": self.mutation.value,
            "external_communication": self.external_communication.value,
            "code_execution": self.code_execution.value,
            "privilege_change": self.privilege_change.value,
            "open_world": self.open_world.value,
            "idempotent": self.idempotent.value,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> EffectProfile:
        expected = {
            "mutation",
            "external_communication",
            "code_execution",
            "privilege_change",
            "open_world",
            "idempotent",
        }
        if set(value) != expected:
            raise EffectError("effect profile must contain every exact effect axis")
        try:
            selected = {key: _enum_text(value[key]) for key in expected}
            return cls(
                mutation=MutationEffect(selected["mutation"]),
                external_communication=TriState(selected["external_communication"]),
                code_execution=TriState(selected["code_execution"]),
                privilege_change=TriState(selected["privilege_change"]),
                open_world=TriState(selected["open_world"]),
                idempotent=TriState(selected["idempotent"]),
            )
        except (TypeError, ValueError):
            raise EffectError("effect profile contains an unsupported value") from None

    @property
    def complete(self) -> bool:
        return self.mutation is not MutationEffect.UNKNOWN and all(
            value is not TriState.UNKNOWN
            for value in (
                self.external_communication,
                self.code_execution,
                self.privilege_change,
                self.open_world,
                self.idempotent,
            )
        )


@dataclass(frozen=True, slots=True)
class EffectEvidence:
    source: EvidenceSource
    proposed_profile: EffectProfile
    signals: tuple[str, ...]
    action_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source": self.source.value,
            "proposed_profile": self.proposed_profile.as_dict(),
            "signals": list(self.signals),
        }
        if self.action_id is not None:
            result["action_id"] = self.action_id
        return result

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_dict())

    @property
    def digest(self) -> str:
        return sha256_hex(self.canonical_bytes)


_READ_WORDS = frozenset(
    {"fetch", "find", "get", "health", "inspect", "list", "query", "read", "search", "status"}
)
_ADDITIVE_WORDS = frozenset({"add", "create", "invite", "post", "publish", "send", "upload"})
_MUTATING_WORDS = frozenset({"edit", "move", "rename", "set", "update"})
_DESTRUCTIVE_WORDS = frozenset({"delete", "purge", "remove"})
_COMMUNICATION_WORDS = frozenset(
    {"email", "mail", "message", "post", "publish", "send", "sms", "telegram", "whatsapp"}
)
_CODE_WORDS = frozenset({"deploy", "eval", "execute", "run", "script", "shell"})
_PRIVILEGE_WORDS = frozenset(
    {
        "admin",
        "grant",
        "invite",
        "member",
        "membership",
        "permission",
        "privilege",
        "revoke",
        "role",
    }
)


def recommend_policy(profile: EffectProfile) -> RecommendedMode:
    """Return the most permissive conservative recommendation for a human profile."""

    if not profile.complete:
        return RecommendedMode.DENY
    if (
        profile.mutation in {MutationEffect.DESTRUCTIVE, MutationEffect.UNKNOWN}
        or profile.code_execution is TriState.TRUE
        or profile.privilege_change is TriState.TRUE
        or profile.open_world is TriState.TRUE
    ):
        return RecommendedMode.DENY
    if (
        profile.mutation is MutationEffect.NONE
        and profile.external_communication is TriState.FALSE
        and profile.code_execution is TriState.FALSE
        and profile.privilege_change is TriState.FALSE
        and profile.open_world is TriState.FALSE
    ):
        return RecommendedMode.PASSTHROUGH
    if (
        profile.mutation
        in {
            MutationEffect.NONE,
            MutationEffect.ADDITIVE,
            MutationEffect.MUTATING,
        }
        and profile.code_execution is TriState.FALSE
        and profile.privilege_change is TriState.FALSE
        and profile.open_world is TriState.FALSE
    ):
        return RecommendedMode.APPROVAL
    return RecommendedMode.DENY


def annotation_evidence(tool: Mapping[str, Any]) -> EffectEvidence:
    annotations = tool.get("annotations")
    values = annotations if isinstance(annotations, Mapping) else {}
    read_only = values.get("readOnlyHint")
    destructive = values.get("destructiveHint")
    if destructive is True:
        mutation = MutationEffect.DESTRUCTIVE
    elif read_only is True:
        mutation = MutationEffect.NONE
    else:
        mutation = MutationEffect.UNKNOWN
    signals = tuple(
        f"annotation:{key}={str(values[key]).lower()}"
        for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
        if type(values.get(key)) is bool
    )
    if read_only is True and destructive is True:
        signals += ("conflict:read_only_and_destructive",)
    return EffectEvidence(
        source=EvidenceSource.MCP_ANNOTATIONS,
        proposed_profile=EffectProfile(
            mutation=mutation,
            open_world=TriState.from_hint(values.get("openWorldHint")),
            idempotent=TriState.from_hint(values.get("idempotentHint")),
        ),
        signals=signals,
    )


def heuristic_evidence(tool: Mapping[str, Any]) -> EffectEvidence:
    name = tool.get("name")
    if not isinstance(name, str) or not name:
        raise EffectError("heuristic evidence requires an exact tool name")
    words = _name_words(name)
    mutation = MutationEffect.UNKNOWN
    if words & _DESTRUCTIVE_WORDS:
        mutation = MutationEffect.DESTRUCTIVE
    elif words & _MUTATING_WORDS:
        mutation = MutationEffect.MUTATING
    elif words & _ADDITIVE_WORDS:
        mutation = MutationEffect.ADDITIVE
    elif words & _READ_WORDS:
        mutation = MutationEffect.NONE
    signals = tuple(f"name:{word}" for word in sorted(words & _KNOWN_WORDS))
    return EffectEvidence(
        source=EvidenceSource.NAME_SCHEMA_HEURISTIC,
        proposed_profile=EffectProfile(
            mutation=mutation,
            external_communication=(
                TriState.TRUE if words & _COMMUNICATION_WORDS else TriState.UNKNOWN
            ),
            code_execution=TriState.TRUE if words & _CODE_WORDS else TriState.UNKNOWN,
            privilege_change=(TriState.TRUE if words & _PRIVILEGE_WORDS else TriState.UNKNOWN),
        ),
        signals=signals,
    )


def plugin_evidence(action_id: str, profile: EffectProfile) -> EffectEvidence:
    if (
        not isinstance(action_id, str)
        or re.fullmatch(r"[a-z][a-z0-9._:-]{0,127}", action_id) is None
    ):
        raise EffectError("plugin action identifier is invalid")
    return EffectEvidence(
        source=EvidenceSource.PLUGIN_PROPOSAL,
        proposed_profile=profile,
        signals=(f"plugin_action:{action_id}",),
        action_id=action_id,
    )


def evidence_bundle_digest(evidence: Sequence[EffectEvidence]) -> str:
    """Bind a review page to the complete, ordered-by-source evidence packet."""

    if not evidence:
        raise EffectError("an effect review requires evidence")
    sources = [item.source for item in evidence]
    if len(set(sources)) != len(sources):
        raise EffectError("effect evidence contains a duplicate source")
    packet = [item.as_dict() for item in sorted(evidence, key=lambda item: item.source.value)]
    return sha256_hex(canonical_json(packet))


def evidence_disagreements(evidence: Sequence[EffectEvidence]) -> tuple[str, ...]:
    disagreements: list[str] = []
    fields = tuple(EffectProfile.__dataclass_fields__)
    for field in fields:
        observed = {
            getattr(item.proposed_profile, field)
            for item in evidence
            if getattr(item.proposed_profile, field).value != "unknown"
        }
        if len(observed) > 1:
            disagreements.append(field)
    return tuple(disagreements)


def _name_words(name: str) -> set[str]:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return {word for word in re.split(r"[_.:-]+", separated.lower()) if word}


_KNOWN_WORDS = (
    _READ_WORDS
    | _ADDITIVE_WORDS
    | _MUTATING_WORDS
    | _DESTRUCTIVE_WORDS
    | _COMMUNICATION_WORDS
    | _CODE_WORDS
    | _PRIVILEGE_WORDS
)


def _enum_text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value

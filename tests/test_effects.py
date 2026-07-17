from __future__ import annotations

import pytest

from signet.effects import (
    EffectError,
    EffectProfile,
    MutationEffect,
    RecommendedMode,
    TriState,
    annotation_evidence,
    evidence_bundle_digest,
    evidence_disagreements,
    heuristic_evidence,
    plugin_evidence,
    recommend_policy,
)


def profile(
    *,
    mutation: MutationEffect = MutationEffect.NONE,
    communication: TriState = TriState.FALSE,
    code: TriState = TriState.FALSE,
    privilege: TriState = TriState.FALSE,
    open_world: TriState = TriState.FALSE,
    idempotent: TriState = TriState.TRUE,
) -> EffectProfile:
    return EffectProfile(
        mutation=mutation,
        external_communication=communication,
        code_execution=code,
        privilege_change=privilege,
        open_world=open_world,
        idempotent=idempotent,
    )


def test_recommendations_require_complete_conservative_human_conclusions() -> None:
    assert recommend_policy(profile()) is RecommendedMode.PASSTHROUGH
    assert (
        recommend_policy(
            profile(
                mutation=MutationEffect.ADDITIVE,
                communication=TriState.TRUE,
                idempotent=TriState.FALSE,
            )
        )
        is RecommendedMode.APPROVAL
    )
    assert recommend_policy(profile(mutation=MutationEffect.DESTRUCTIVE)) is RecommendedMode.DENY
    assert recommend_policy(profile(code=TriState.TRUE)) is RecommendedMode.DENY
    assert recommend_policy(profile(privilege=TriState.TRUE)) is RecommendedMode.DENY
    assert recommend_policy(profile(open_world=TriState.TRUE)) is RecommendedMode.DENY
    assert recommend_policy(profile(idempotent=TriState.UNKNOWN)) is RecommendedMode.DENY


def test_annotations_heuristics_and_plugin_proposals_remain_separate_evidence() -> None:
    tool = {
        "name": "delete_message",
        "inputSchema": {"type": "object", "additionalProperties": False},
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    }
    annotations = annotation_evidence(tool)
    heuristic = heuristic_evidence(tool)
    proposal = plugin_evidence(
        "mail.delete_message",
        profile(mutation=MutationEffect.MUTATING, idempotent=TriState.FALSE),
    )

    assert annotations.proposed_profile.mutation is MutationEffect.DESTRUCTIVE
    assert "conflict:read_only_and_destructive" in annotations.signals
    assert heuristic.proposed_profile.external_communication is TriState.TRUE
    assert evidence_disagreements((annotations, heuristic, proposal)) == (
        "mutation",
        "external_communication",
        "idempotent",
    )
    assert evidence_bundle_digest((proposal, heuristic, annotations)) == evidence_bundle_digest(
        (annotations, proposal, heuristic)
    )


def test_effect_profiles_and_evidence_packets_reject_ambiguous_shapes() -> None:
    with pytest.raises(EffectError, match="every exact"):
        EffectProfile.from_mapping({"mutation": "none"})
    with pytest.raises(EffectError, match="duplicate"):
        evidence_bundle_digest((annotation_evidence({"name": "read"}),) * 2)
    with pytest.raises(EffectError, match="action"):
        plugin_evidence("wild*card", profile())

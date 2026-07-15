from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

import signet.policy as policy_module
from signet.policy import PolicyError, PolicyMode, load_policy, parse_policy_yaml


def test_bounded_yaml_aliases_preserve_strict_policy_behavior() -> None:
    snapshot = parse_policy_yaml(
        b"""
version: 1
default_mode: deny
downstreams:
  service:
    transport: http
    url: https://provider.example.test/mcp
    tools:
      first: &denied
        mode: deny
      second: *denied
"""
    )

    assert snapshot.resolve("service", "first") is PolicyMode.DENY
    assert snapshot.resolve("service", "second") is PolicyMode.DENY


@pytest.mark.parametrize(
    ("document_factory", "message"),
    [
        (
            lambda: b"version: &recursive [*recursive]\n",
            "recursive policy YAML aliases",
        ),
        (
            lambda: (b"[" * 33) + b"0" + (b"]" * 33),
            "nesting-depth limit",
        ),
        (
            lambda: b"value: " + (b"a" * (16 * 1024 + 1)) + b"\n",
            "scalar-length limit",
        ),
        (
            lambda: b"base: &base deny\naliases:\n" + (b"  - *base\n" * 129),
            "alias limit",
        ),
        (
            lambda: b"- value\n" * 50_000,
            "node limit",
        ),
        (
            lambda: b"value: &" + (b"a" * 257) + b" anchored\n",
            "anchor-name limit",
        ),
    ],
)
def test_policy_yaml_composition_limits_apply_before_construction(
    document_factory: Callable[[], bytes],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    def forbidden_construction(loader: object, node: object) -> object:
        del loader, node
        nonlocal constructed
        constructed = True
        raise AssertionError("unsafe YAML reached object construction")

    monkeypatch.setattr(
        policy_module._UniqueKeySafeLoader,
        "construct_document",
        forbidden_construction,
    )
    with pytest.raises(yaml.YAMLError, match=message):
        parse_policy_yaml(document_factory())
    assert not constructed


def test_policy_yaml_rejects_exponential_alias_graph_before_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lines = ["level0: &level0 [value]"]
    for level in range(1, 18):
        lines.append(f"level{level}: &level{level} [*level{level - 1}, *level{level - 1}]")
    lines.append("root: *level17")
    document = ("\n".join(lines) + "\n").encode()
    constructed = False

    def forbidden_construction(loader: object, node: object) -> object:
        del loader, node
        nonlocal constructed
        constructed = True
        raise AssertionError("alias bomb reached object construction")

    monkeypatch.setattr(
        policy_module._UniqueKeySafeLoader,
        "construct_document",
        forbidden_construction,
    )
    with pytest.raises(yaml.YAMLError, match="alias expansion exceeds"):
        parse_policy_yaml(document)
    assert not constructed


def test_policy_yaml_byte_limit_applies_to_direct_parser_calls() -> None:
    oversized = b"#" * (4 * 1024 * 1024 + 1)

    with pytest.raises(PolicyError, match="byte limit"):
        parse_policy_yaml(oversized)


def test_load_policy_bounds_file_read_before_yaml_composition(tmp_path: Path) -> None:
    path = tmp_path / "oversized.yaml"
    path.write_bytes(b"#" * (4 * 1024 * 1024 + 2))

    with pytest.raises(PolicyError, match="byte limit"):
        load_policy(path)

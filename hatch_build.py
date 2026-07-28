from __future__ import annotations

import platform
import re
import sys
import sysconfig
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def supported_wheel_tag(system: str, machine: str, sysconfig_platform: str) -> str:
    """Return the reviewed platform tag or reject an unsupported release target."""

    normalized_machine = machine.lower()
    if system == "darwin" and normalized_machine == "arm64":
        platform_tag = "macosx_11_0_arm64"
    elif system == "linux" and normalized_machine in {"x86_64", "amd64"}:
        platform_tag = "linux_x86_64"
    elif system == "linux" and normalized_machine in {"aarch64", "arm64"}:
        platform_tag = "linux_aarch64"
    else:
        raise RuntimeError(
            "unsupported release platform; expected macOS arm64 or Linux x86_64/arm64"
        )
    observed = sysconfig_platform.replace("-", "_").replace(".", "_")
    valid_observed = (
        re.fullmatch(r"macosx_\d+_\d+_arm64", observed) is not None
        if system == "darwin"
        else observed == platform_tag
    )
    if not valid_observed:
        raise RuntimeError(
            f"unsupported release platform tag {observed}; expected {platform_tag}"
        )
    return f"py3-none-{platform_tag}"


class PlatformWheelBuildHook(BuildHookInterface):
    """Prevent a POSIX-only distribution from advertising a universal wheel."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        del version
        if self.target_name != "wheel":
            return
        build_data["tag"] = supported_wheel_tag(
            sys.platform,
            platform.machine(),
            sysconfig.get_platform(),
        )
        build_data["pure_python"] = False

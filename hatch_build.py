from __future__ import annotations

import sys
import sysconfig
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class PlatformWheelBuildHook(BuildHookInterface):
    """Prevent a POSIX-only distribution from advertising a universal wheel."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        del version
        if self.target_name != "wheel":
            return
        if sys.platform not in {"darwin", "linux"}:
            raise RuntimeError("signet-gateway wheels support Linux and macOS only")
        platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
        build_data["tag"] = f"py3-none-{platform_tag}"
        build_data["pure_python"] = False

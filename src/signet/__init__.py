"""Signet MCP human approval gateway."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("signet-gateway")
except PackageNotFoundError:  # pragma: no cover - source tree without installation metadata
    __version__ = "0+unknown"

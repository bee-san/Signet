from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from playwright.sync_api import ConsoleMessage, Locator, Page, Request, Route, sync_playwright

from signet.canonical import canonical_json
from signet.connector_config import detached_connector_document, parse_connector_config
from signet.connector_discovery import ConnectorDiscoveryService
from signet.demo import (
    DEMO_GRACEFUL_SHUTDOWN_SECONDS,
    DEMO_NAMESPACE,
    DEMO_USER_ID,
    build_demo,
    credential_value,
    initialize_demo,
)
from signet.integration_store import SQLiteIntegrationStore
from signet.plugin_manifest import (
    load_reference_discovery_fixture,
    load_reference_plugin,
)

BROWSER_ATTACHMENT_CONTENT = (
    b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("not executed")</script></svg>'
)

EMAIL_ARGUMENTS = {
    "from": "fake-sender@demo.invalid",
    "to": ["finance-review@demo.invalid"],
    "cc": [],
    "bcc": [],
    "subject": "Q3 payroll approval browser acceptance",
    "body": "Release the fake-only payroll notice after a human review.",
    "attachments": [],
}
WHATSAPP_ARGUMENTS = {
    "to": "15555550123@s.whatsapp.net",
    "message": "Send the fake-only incident handoff after a human review.",
}
ACCESS_ARGUMENTS = {
    "alias": "fastmail",
    "tool": "search_email",
    "reason": "Allow this reviewed read-only tool through Signet.",
}
APPROVAL_ACCESS_ARGUMENTS = {
    "alias": "fastmail",
    "tool": "send_email",
    "reason": "Gate this reviewed communication tool behind per-call human approval.",
}
APPROVAL_NOTE = "exact_request_approved"
APPROVAL_REASON = "Exact content, destination, and scope reviewed and approved"
DENIAL_NOTE = "request_no_longer_needed"
DENIAL_REASON = "Request is no longer needed"

NO_EGRESS_DEMO_ENTRYPOINT = r"""
import errno
import ipaddress
import socket

_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex
_original_getaddrinfo = socket.getaddrinfo
_original_sendto = socket.socket.sendto


def _loopback_address(address):
    if isinstance(address, str):
        return True
    if not isinstance(address, tuple) or not address:
        return False
    try:
        return ipaddress.ip_address(address[0]).is_loopback
    except ValueError:
        return address[0] == "localhost"


def _connect(sock, address):
    if not _loopback_address(address):
        raise OSError(errno.ENETUNREACH, "browser acceptance blocks non-loopback network")
    return _original_connect(sock, address)


def _connect_ex(sock, address):
    if not _loopback_address(address):
        return errno.ENETUNREACH
    return _original_connect_ex(sock, address)


def _getaddrinfo(host, *args, **kwargs):
    if host not in (None, "localhost", "127.0.0.1", "::1"):
        raise socket.gaierror(socket.EAI_NONAME, "browser acceptance blocks external DNS")
    return _original_getaddrinfo(host, *args, **kwargs)


def _sendto(sock, data, *args):
    address = args[-1] if args else None
    if not _loopback_address(address):
        raise OSError(errno.ENETUNREACH, "browser acceptance blocks non-loopback network")
    return _original_sendto(sock, data, *args)


socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex
socket.socket.sendto = _sendto
socket.getaddrinfo = _getaddrinfo

import signet.demo as _demo

_original_build_demo = _demo.build_demo


def _fake_only_build_demo(*args, **kwargs):
    assembly = _original_build_demo(*args, **kwargs)
    clients = assembly.provider_clients
    if set(clients) != {"fastmail", "whatsapp"} or any(
        type(client) is not _demo.FakeOnlyProviderClient for client in clients.values()
    ):
        raise _demo.DemoError("browser acceptance requires exact fake provider clients")
    return assembly


_demo.build_demo = _fake_only_build_demo

from signet.app import main

main()
"""


@dataclass(frozen=True)
class LiveDemo:
    root: Path
    mcp_origin: str
    web_origin: str


@dataclass
class BrowserSignals:
    console_errors: int = 0
    page_errors: int = 0
    failed_requests: int = 0
    error_responses: int = 0
    external_requests: int = 0
    post_requests: int = 0
    exact_post_origins: bool = True
    expected_download_url: str | None = None
    failed_request_details: list[str] = field(default_factory=list)


def _available_ports() -> tuple[int, int]:
    reservations = (socket.socket(), socket.socket())
    try:
        for reservation in reservations:
            reservation.bind(("127.0.0.1", 0))
        selected = tuple(int(item.getsockname()[1]) for item in reservations)
        return selected[0], selected[1]
    finally:
        for reservation in reservations:
            reservation.close()


def _wait_until_ready(process: subprocess.Popen[bytes], origins: tuple[str, str]) -> None:
    deadline = time.monotonic() + 30
    with httpx.Client(timeout=0.5, trust_env=False) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            ready = True
            for origin in origins:
                try:
                    response = client.get(f"{origin}/healthz")
                    payload = response.json()
                    ready = (
                        ready
                        and response.status_code == 200
                        and isinstance(payload, dict)
                        and payload.get("status") == "ok"
                    )
                except (httpx.HTTPError, ValueError):
                    ready = False
            if ready:
                return
            time.sleep(0.05)
    pytest.fail("fake demo listeners did not become ready", pytrace=False)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=DEMO_GRACEFUL_SHUTDOWN_SECONDS + 5)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@contextmanager
def _served_demo(
    tmp_path: Path,
    *,
    force_deny_tool: tuple[str, str, str] | None = None,
    seed_fastmail_integration: bool = False,
) -> Iterator[LiveDemo]:
    private_parent = tmp_path / "browser-acceptance"
    private_parent.mkdir(mode=0o700)
    os.chmod(private_parent, 0o700)
    root = private_parent / "state"
    initialize_demo(root)
    if seed_fastmail_integration:
        _seed_fastmail_integration(root)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        pytest.fail("browser demo state directory is not private", pytrace=False)
    if force_deny_tool is not None:
        alias, tool_name, expected_mode = force_deny_tool
        policy_path = root / "policy.yaml"
        document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        try:
            tool_policy = document["downstreams"][alias]["tools"][tool_name]
        except (KeyError, TypeError):
            pytest.fail("browser access target is missing from demo policy", pytrace=False)
        if tool_policy.get("mode") != expected_mode:
            pytest.fail("browser access target has an unexpected starting mode", pytrace=False)
        tool_policy["mode"] = "deny"
        policy_path.write_text(
            yaml.safe_dump(document, allow_unicode=False, sort_keys=False),
            encoding="utf-8",
        )
        policy_path.chmod(0o600)

    mcp_port, web_port = _available_ports()
    mcp_origin = f"http://127.0.0.1:{mcp_port}"
    web_origin = f"http://127.0.0.1:{web_port}"
    log_path = private_parent / "server.log"
    log_descriptor = os.open(log_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    log_file = os.fdopen(log_descriptor, "wb")
    environment = os.environ.copy()
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        environment[name] = "http://127.0.0.1:9"
    environment["NO_PROXY"] = "127.0.0.1,localhost"
    environment["no_proxy"] = "127.0.0.1,localhost"
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and in-repo entry point
        [
            sys.executable,
            "-c",
            NO_EGRESS_DEMO_ENTRYPOINT,
            "demo",
            "serve",
            "--data-dir",
            str(root),
            "--mcp-port",
            str(mcp_port),
            "--web-port",
            str(web_port),
        ],
        env=environment,
        start_new_session=True,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    completed = False
    try:
        _wait_until_ready(process, (mcp_origin, web_origin))
        yield LiveDemo(root=root, mcp_origin=mcp_origin, web_origin=web_origin)
        completed = True
    finally:
        _stop_process(process)
        log_file.close()
        if completed:
            if process.returncode != 0:
                pytest.fail("fake demo server did not shut down cleanly", pytrace=False)
            if log_path.stat().st_size > 1_000_000:
                pytest.fail("fake demo server produced excessive output", pytrace=False)
            server_output = log_path.read_bytes()
            if any(
                marker in server_output for marker in (b"Traceback", b"CancelledError", b"ERROR")
            ):
                pytest.fail("fake demo server reported an internal error", pytrace=False)


def _seed_fastmail_integration(root: Path) -> None:
    """Install and discover one provider-free reference connector before serving."""

    assembly = build_demo(root)
    store = SQLiteIntegrationStore(assembly.database)
    manifest = load_reference_plugin("fastmail")
    template = manifest.manifest.connectors[0]
    seeded_at = int(time.time()) - 2
    identity = store.install_plugin(manifest, installed_at=seeded_at)
    validated = parse_connector_config(
        canonical_json(
            {
                "connector_config_version": 1,
                "transport": "streamable_http",
                "credential_ref": "keychain://Signet/reference-fastmail-fixture",
                "credential_identity_digest": "f" * 64,
                "url": "https://fastmail-fixture.invalid/mcp",
            }
        ),
        template=template,
    )
    detached = detached_connector_document(validated)
    credential_ref = detached.pop("credential_ref")
    credential_identity_digest = detached.pop("credential_identity_digest")
    store.configure_connector(
        plugin_id=identity.plugin_id,
        connector_id=template.connector_id,
        alias="fastmail-staged",
        config=detached,
        credential_ref=credential_ref,
        credential_identity_digest=credential_identity_digest,
        canonical_config_bytes=validated.canonical_bytes,
        canonical_config_sha256=validated.sha256,
        configured_at=seeded_at + 1,
    )
    asyncio.run(
        ConnectorDiscoveryService.staged(store).discover_fixture(
            "fastmail-staged",
            load_reference_discovery_fixture("fastmail"),
            discovered_at=seeded_at + 2,
        )
    )


async def _enqueue(demo: LiveDemo) -> tuple[str, str, dict[str, Any]]:
    source = demo.root / "imports" / "payroll-review.svg"
    source.write_bytes(BROWSER_ATTACHMENT_CONTENT)
    source.chmod(0o600)
    assembly = build_demo(demo.root)
    staged = assembly.staging.stage_path(
        source,
        adapter="fastmail",
        account="fake:fastmail-account",
        filename="payroll-review.svg",
        declared_mime="image/svg+xml",
    )
    attachment = {
        "staged_id": staged.opaque_id,
        "filename": staged.filename,
        "mime_type": staged.declared_mime,
        "detected_mime": staged.detected_mime,
        "detection_source": staged.detection_source,
        "size": staged.size,
        "sha256": staged.sha256,
    }
    email_arguments: dict[str, Any] = {
        **EMAIL_ARGUMENTS,
        "attachments": [attachment],
    }
    token = credential_value(demo.root, "mcp-token")
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
        trust_env=False,
    ) as client:
        request_ids: list[str] = []
        for alias, tool_name, arguments in (
            ("fastmail", "send_email", email_arguments),
            ("whatsapp", "send_text", WHATSAPP_ARGUMENTS),
        ):
            async with (
                streamable_http_client(
                    f"{demo.mcp_origin}/mcp/{alias}",
                    http_client=client,
                ) as (read_stream, write_stream, _get_session_id),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
            content = result.structuredContent
            if (
                result.isError
                or not isinstance(content, dict)
                or content.get("status") != "pending_approval"
                or not isinstance(content.get("request_id"), str)
            ):
                raise RuntimeError("fake MCP did not enqueue an approval request")
            request_ids.append(content["request_id"])
    return request_ids[0], request_ids[1], email_arguments


def _enqueue_requests(demo: LiveDemo) -> tuple[str, str, dict[str, Any]]:
    try:
        return asyncio.run(_enqueue(demo))
    except Exception:
        pytest.fail("authenticated fake MCP enqueue failed", pytrace=False)


async def _enqueue_access(demo: LiveDemo, arguments: Mapping[str, str]) -> str:
    token = credential_value(demo.root, "mcp-token")
    async with (
        httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
            trust_env=False,
        ) as client,
        streamable_http_client(
            f"{demo.mcp_origin}/mcp/approvals",
            http_client=client,
        ) as (read_stream, write_stream, _get_session_id),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        result = await session.call_tool("request_tool_access", dict(arguments))
    content = result.structuredContent
    if (
        result.isError
        or not isinstance(content, dict)
        or content.get("status") != "pending_approval"
        or not isinstance(content.get("request_id"), str)
    ):
        raise RuntimeError("fake MCP did not enqueue a tool-access request")
    return content["request_id"]


def _enqueue_access_request(demo: LiveDemo, arguments: Mapping[str, str]) -> str:
    try:
        return asyncio.run(_enqueue_access(demo, arguments))
    except Exception:
        pytest.fail("authenticated fake MCP tool-access request failed", pytrace=False)


def _install_network_guards(page: Page, demo: LiveDemo, signals: BrowserSignals) -> None:
    def route_request(route: Route) -> None:
        parsed = urlsplit(route.request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.scheme in {"http", "https"} and origin != demo.web_origin:
            signals.external_requests += 1
            route.abort("blockedbyclient")
            return
        route.continue_()

    def observe_request(request: Request) -> None:
        parsed = urlsplit(request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.scheme in {"http", "https"} and origin != demo.web_origin:
            signals.external_requests += 1
        if request.method == "POST":
            signals.post_requests += 1
            try:
                signals.exact_post_origins = (
                    signals.exact_post_origins
                    and request.all_headers().get("origin") == demo.web_origin
                )
            except Exception:
                signals.exact_post_origins = False

    def observe_console(message: ConsoleMessage) -> None:
        if message.type == "error":
            signals.console_errors += 1

    def observe_failed(request: Request) -> None:
        # Chromium reports a successful browser-managed download as ERR_ABORTED.
        # Ignore only the exact link selected by this acceptance test.
        if (
            request.method == "GET"
            and request.url == signals.expected_download_url
            and request.failure == "net::ERR_ABORTED"
        ):
            return
        signals.failed_requests += 1
        signals.failed_request_details.append(
            f"{request.method} {request.url} ({request.failure or 'unknown failure'}; "
            f"page={page.url})"
        )

    page.context.route("**/*", route_request)
    page.on("request", observe_request)
    page.on("requestfailed", observe_failed)
    page.on(
        "response",
        lambda response: setattr(
            signals, "error_responses", signals.error_responses + (response.status >= 400)
        ),
    )
    page.on("console", observe_console)
    page.on("pageerror", lambda _error: setattr(signals, "page_errors", signals.page_errors + 1))


def _expand_request(page: Page, request_id: str) -> Locator:
    fragment = page.locator(f'[data-decision-request-id="{request_id}"] [data-review-fragment]')
    if fragment.count() == 0:
        fragment = page.locator(f'[data-review-url="/requests/{request_id}/review"]')
    if fragment.count() != 1:
        pytest.fail("expected request is missing from the current list", pytrace=False)
    expander = fragment.locator("..")
    if expander.get_attribute("open") is None:
        expander.locator(":scope > summary").click()
    review = fragment.locator(".request-review")
    review.wait_for(state="visible")
    return review


def _assert_context_sections(review: Locator) -> None:
    review_text = review.text_content() or ""
    for section in (
        "Request context",
        "Reviewed content",
        "Frozen execution arguments",
        "Attachments",
        "Event timeline",
    ):
        if section not in review_text:
            pytest.fail("expanded request context is incomplete", pytrace=False)
    context = review.locator(".context-band")
    context_text = context.text_content() or ""
    historical = review.get_attribute("data-historical-event-id") is not None
    for label in (
        "Request",
        "Current request state" if historical else "State",
        "Created",
        "Expires",
        "Selected payload version" if historical else "Version",
        "Selected payload hash" if historical else "Payload hash",
        "Downstream",
        "Tool",
        "Policy mode",
        "Policy version",
        "Adapter version",
        "Schema version",
        "Origin",
    ):
        if label not in context_text:
            pytest.fail("expanded request provenance is incomplete", pytrace=False)


def _normalized_text(locator: Locator) -> str:
    return " ".join((locator.text_content() or "").split())


def _context_definition(review: Locator, label: str) -> Locator:
    terms = review.locator(".context-band dt")
    for index in range(terms.count()):
        term = terms.nth(index)
        if (term.text_content() or "").strip() == label:
            return term.locator("xpath=following-sibling::dd[1]")
    pytest.fail(f"expanded request context omitted {label!r}", pytrace=False)


def _context_value(review: Locator, label: str) -> str:
    return _normalized_text(_context_definition(review, label))


def _definition_value(container: Locator, label: str) -> str:
    terms = container.locator("dt")
    for index in range(terms.count()):
        term = terms.nth(index)
        if (term.text_content() or "").strip() == label:
            return _normalized_text(term.locator("xpath=following-sibling::dd[1]"))
    pytest.fail(f"expanded review omitted {label!r}", pytrace=False)


def _decision_locator(page: Page, request_id: str) -> Locator:
    return page.locator(f'[data-decision-request-id="{request_id}"]').first


def _utc_datetime(value: str | None) -> datetime:
    if value is None or not value.endswith("Z"):
        pytest.fail("expanded request context included an invalid UTC timestamp", pytrace=False)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        pytest.fail("expanded request context included an invalid UTC timestamp", pytrace=False)
    if parsed.tzinfo != UTC:
        pytest.fail("expanded request context included an invalid UTC timestamp", pytrace=False)
    return parsed


def _assert_bound_context(
    review: Locator,
    *,
    request_id: str,
    state: str,
    alias: str,
    tool_name: str,
    arguments: Mapping[str, object],
) -> None:
    _assert_context_sections(review)
    historical = review.get_attribute("data-historical-event-id") is not None
    expected_values = {
        "Request": request_id,
        "Current request state" if historical else "State": state.replace("_", " "),
        "Reviewed content": "Available",
        "Downstream": alias,
        "Tool": tool_name,
        "Account": f"fake:{alias}-account",
        "Policy mode": "approval",
        "Policy version": "1",
        "Adapter version": "1",
        "Origin": DEMO_NAMESPACE,
        "Gateway request": "No",
        "Manual retry": "Not allowed",
    }
    for label, expected in expected_values.items():
        if _context_value(review, label) != expected:
            pytest.fail(
                "expanded request context contained an incorrect bound value", pytrace=False
            )

    version_label = "Selected payload version" if historical else "Version"
    payload_hash_label = "Selected payload hash" if historical else "Payload hash"
    if re.fullmatch(r"[1-9][0-9]*", _context_value(review, version_label)) is None:
        pytest.fail("expanded request context included an invalid version", pytrace=False)
    payload_hash = _context_value(review, payload_hash_label)
    schema_version = _context_value(review, "Schema version")
    if (
        re.fullmatch(r"[a-f0-9]{64}", payload_hash) is None
        or re.fullmatch(r"[a-f0-9]{64}", schema_version) is None
    ):
        pytest.fail("expanded request context included an invalid integrity hash", pytrace=False)
    if re.fullmatch(r"[1-9][0-9]*", _context_value(review, "Canonical bytes")) is None:
        pytest.fail("expanded request context included an invalid canonical size", pytrace=False)

    created = _utc_datetime(
        _context_definition(review, "Created").locator("time").get_attribute("datetime")
    )
    expires = _utc_datetime(
        _context_definition(review, "Expires").locator("time").get_attribute("datetime")
    )
    if created >= expires:
        pytest.fail("expanded request context included an invalid lifetime", pytrace=False)
    timestamps = review.locator("time[datetime]")
    if timestamps.count() < 2:
        pytest.fail("expanded request context omitted UTC timestamps", pytrace=False)
    for index in range(timestamps.count()):
        _utc_datetime(timestamps.nth(index).get_attribute("datetime"))

    arguments_text = review.locator(".arguments-band pre").text_content()
    try:
        frozen_arguments = json.loads(arguments_text or "")
    except json.JSONDecodeError:
        pytest.fail("expanded request context included invalid frozen arguments", pytrace=False)
    if frozen_arguments != dict(arguments):
        pytest.fail("expanded request context did not match the frozen request", pytrace=False)

    attachment_band = review.locator(".attachment-band")
    expected_attachments = arguments.get("attachments", [])
    if expected_attachments:
        if attachment_band.locator("tbody tr").count() != len(expected_attachments):
            pytest.fail("expanded request context omitted an attachment", pytrace=False)
    elif (
        _normalized_text(attachment_band).count("None") != 2
        or attachment_band.locator("table").count() != 0
    ):
        pytest.fail("expanded request context misstated empty attachments", pytrace=False)
    timeline = review.locator(".timeline")
    timeline_text = _normalized_text(timeline)
    if timeline.locator("li").count() < 1 or "queued" not in timeline_text:
        pytest.fail("expanded request context omitted its event history", pytrace=False)
    if payload_hash not in timeline_text:
        pytest.fail("expanded request event history lost payload integrity", pytrace=False)


def _assert_layout(page: Page) -> None:
    metrics = page.evaluate(
        """
        () => {
          const root = document.documentElement;
          const body = document.body;
          const horizontalOverflow =
            root.scrollWidth > root.clientWidth + 1 || body.scrollWidth > body.clientWidth + 1;
          const controls = document.querySelectorAll(
            "button, input:not([type='hidden']), select, textarea, summary, a[href]"
          );
          const undersized = Array.from(controls).flatMap((element) => {
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            const visible =
              style.display !== "none" &&
              style.visibility !== "hidden" &&
              rect.width > 0 &&
              rect.height > 0;
            if (!visible || (rect.width >= 43.5 && rect.height >= 43.5)) {
              return [];
            }
            return [{
              tag: element.tagName.toLowerCase(),
              id: element.id,
              className: typeof element.className === "string" ? element.className : "",
              label: (element.getAttribute("aria-label") || element.textContent || "")
                .trim()
                .replace(/\\s+/g, " ")
                .slice(0, 120),
              width: rect.width,
              height: rect.height,
            }];
          });
          return {
            horizontalOverflow,
            rootClientWidth: root.clientWidth,
            rootScrollWidth: root.scrollWidth,
            bodyClientWidth: body.clientWidth,
            bodyScrollWidth: body.scrollWidth,
            undersized,
          };
        }
        """
    )
    if metrics["horizontalOverflow"] or metrics["undersized"]:
        pytest.fail(
            "browser layout overflowed or exposed an undersized control: "
            f"{json.dumps(metrics, sort_keys=True)}",
            pytrace=False,
        )


def _assert_truth_state_not_clipped(review: Locator) -> None:
    metrics = review.locator(".truth-state span").evaluate(
        """
        (element) => {
          const rect = element.getBoundingClientRect();
          const parentRect = element.parentElement.getBoundingClientRect();
          return {
            rect: {left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom},
            parent: {
              left: parentRect.left,
              right: parentRect.right,
              top: parentRect.top,
              bottom: parentRect.bottom,
            },
            viewportWidth: document.documentElement.clientWidth,
            scrollWidth: element.scrollWidth,
            clientWidth: element.clientWidth,
            whiteSpace: getComputedStyle(element).whiteSpace,
          };
        }
        """
    )
    rect = metrics["rect"]
    parent = metrics["parent"]
    clipped = (
        rect["left"] < parent["left"] - 1
        or rect["right"] > parent["right"] + 1
        or rect["top"] < parent["top"] - 1
        or rect["bottom"] > parent["bottom"] + 1
        or rect["left"] < -1
        or rect["right"] > metrics["viewportWidth"] + 1
        or metrics["scrollWidth"] > metrics["clientWidth"] + 1
        or metrics["whiteSpace"] == "nowrap"
    )
    if clipped:
        pytest.fail(
            f"mobile truth-state text is clipped: {json.dumps(metrics, sort_keys=True)}",
            pytrace=False,
        )


def _assert_identifier_wraps(locator: Locator) -> None:
    metrics = locator.evaluate(
        """
        (element) => {
          const rect = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return {
            left: rect.left,
            right: rect.right,
            viewportWidth: document.documentElement.clientWidth,
            scrollWidth: element.scrollWidth,
            clientWidth: element.clientWidth,
            overflowWrap: style.overflowWrap,
          };
        }
        """
    )
    if (
        metrics["left"] < -1
        or metrics["right"] > metrics["viewportWidth"] + 1
        or metrics["scrollWidth"] > metrics["clientWidth"] + 1
        or metrics["overflowWrap"] != "anywhere"
    ):
        pytest.fail(
            f"maximum-length identifier did not wrap: {json.dumps(metrics, sort_keys=True)}",
            pytrace=False,
        )


def _login(page: Page, demo: LiveDemo) -> None:
    page.goto(f"{demo.web_origin}/login", wait_until="domcontentloaded")
    banner = page.locator(".fake-only-banner")
    if banner.count() != 1 or banner.text_content() != "Fake-only demo":
        pytest.fail("browser did not enter the fake-only UI", pytrace=False)
    _assert_layout(page)
    page.locator("#fallback-user").fill(credential_value(demo.root, "web-user"))
    page.locator("#password").fill(credential_value(demo.root, "web-password"))
    page.locator("#totp-proof").fill(credential_value(demo.root, "web-login-proof"))
    page.get_by_role("button", name="Enter fake demo").click()
    page.wait_for_url(f"{demo.web_origin}/")


def _submit_decision(
    page: Page,
    demo: LiveDemo,
    review: Locator,
    request_id: str,
    *,
    action: str,
    note: str,
) -> None:
    selector = "[data-approval-reason]" if action == "approve" else "[data-denial-reason]"
    review.locator(selector).select_option(note)
    form = review.locator("form.totp-action").first
    form.locator("input[name='totp_proof']").fill(credential_value(demo.root, "web-action-proof"))
    with page.expect_navigation(wait_until="domcontentloaded"):
        form.locator(f"button[name='action'][value='{action}']").click()
    page.wait_for_url(re.compile(rf"{re.escape(demo.web_origin)}/audit#decision-{request_id}$"))
    redirected_review = page.locator(
        f'[data-decision-request-id="{request_id}"] [data-review-fragment] .request-review'
    ).first
    redirected_review.wait_for(state="visible")


def _assert_passkey_note_routing(review: Locator) -> None:
    approval_reason = "exact_request_approved"
    denial_reason = "wrong_destination"
    review.locator("[data-approval-reason]").select_option(approval_reason)
    review.locator("[data-denial-reason]").select_option(denial_reason)
    captured = review.evaluate(
        """
        async (root) => {
          const originalFetch = window.fetch;
          const bodies = [];
          window.fetch = async (url, options = {}) => {
            if (String(url).includes("/actions/passkey/options")) {
              bodies.push(JSON.parse(options.body));
              return new Response(
                JSON.stringify({ error: { message: "captured without a ceremony" } }),
                { status: 422, headers: { "Content-Type": "application/json" } }
              );
            }
            return originalFetch.call(window, url, options);
          };
          try {
            for (const action of [
              "approve", "deny", "cancel", "edit",
              "promote_approval", "promote_passthrough"
            ]) {
              const button = document.createElement("button");
              button.type = "button";
              button.dataset.passkeyAction = action;
              root.append(button);
              button.click();
              button.remove();
              await new Promise((resolve) => setTimeout(resolve, 0));
            }
            root.dataset.gatewayInternal = "true";
            const policyApprove = document.createElement("button");
            policyApprove.type = "button";
            policyApprove.dataset.passkeyAction = "approve";
            root.append(policyApprove);
            policyApprove.click();
            policyApprove.remove();
            await new Promise((resolve) => setTimeout(resolve, 0));
            return bodies;
          } finally {
            window.fetch = originalFetch;
          }
        }
        """
    )
    if [body["action"] for body in captured] != [
        "approve",
        "deny",
        "cancel",
        "edit",
        "promote_approval",
        "promote_passthrough",
        "approve",
    ]:
        pytest.fail("passkey action capture was incomplete", pytrace=False)
    for index, body in enumerate(captured):
        expected_note = {
            "approve": approval_reason,
            "deny": denial_reason,
        }.get(body["action"])
        if index == len(captured) - 1:
            expected_note = None
        if body.get("decision_note") != expected_note:
            pytest.fail("passkey action routed rationale to the wrong action", pytrace=False)


def _wait_for_success(page: Page, demo: LiveDemo, request_id: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        page.goto(f"{demo.web_origin}/audit", wait_until="domcontentloaded")
        state = _decision_locator(page, request_id).locator(".state")
        if state.count() == 1 and state.inner_text().strip() == "succeeded":
            return
        page.wait_for_timeout(100)
    pytest.fail("approved fake request did not reach a terminal success state", pytrace=False)


def _assert_keyboard_focus(page: Page) -> None:
    page.evaluate("document.activeElement?.blur()")
    focused_summary = False
    for _ in range(12):
        page.keyboard.press("Tab")
        if page.evaluate("document.activeElement?.tagName === 'SUMMARY'"):
            focused_summary = True
            break
    if not focused_summary:
        pytest.fail("decision summaries are not keyboard reachable", pytrace=False)
    focus_style = page.evaluate(
        """
        () => {
          const style = getComputedStyle(document.activeElement);
          return { outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth };
        }
        """
    )
    if focus_style["outlineStyle"] == "none" or focus_style["outlineWidth"] == "0px":
        pytest.fail("keyboard focus is not visibly indicated", pytrace=False)


def test_fake_demo_browser_staged_fastmail_effect_review_is_inert(
    tmp_path: Path,
) -> None:
    with _served_demo(tmp_path, seed_fastmail_integration=True) as demo:
        signals = BrowserSignals()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--no-first-run",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                locale="en-US",
                timezone_id="UTC",
                service_workers="block",
            )
            page = context.new_page()
            page.set_default_timeout(10_000)
            page.set_default_navigation_timeout(15_000)
            _install_network_guards(page, demo, signals)

            _login(page, demo)
            integrations_link = page.locator("a.primary-integrations-link")
            if not integrations_link.is_visible():
                pytest.fail("authenticated demo did not expose Integrations", pytrace=False)
            integrations_link.click()
            page.wait_for_url(f"{demo.web_origin}/integrations")

            workspace = _normalized_text(page.locator("main"))
            for expected in (
                "Live dispatch is disabled",
                "Fastmail staged integration",
                "fastmail-staged",
                "fixture",
                "search_email",
                "unreviewed",
            ):
                if expected not in workspace:
                    pytest.fail("staged integration workspace omitted exact state", pytrace=False)
            rows = page.locator(".integration-tools-table tbody tr")
            search_row = rows.filter(has_text="search_email")
            if rows.count() != 5 or search_row.count() != 1:
                pytest.fail("Fastmail fixture tools were not rendered exactly once", pytrace=False)
            search_row.get_by_role("link", name="Inspect exact definition").click()
            page.wait_for_url(re.compile(rf"{re.escape(demo.web_origin)}/integrations/tools/.+"))

            detail = page.locator("[data-integration-tool-id]")
            detail_text = _normalized_text(detail)
            for expected in (
                "Search email",
                "Search the fake mailbox without changing provider state.",
                "MCP annotations — untrusted server hints",
                "Name and schema classifier signals",
                "Plugin proposal — untrusted mapping evidence",
                "Effect evidence, not authorization",
            ):
                if expected not in detail_text:
                    pytest.fail(
                        f"exact Fastmail evidence omitted {expected!r}",
                        pytrace=False,
                    )
            if _definition_value(detail.locator(".context-band"), "Exact tool name") != (
                "search_email"
            ):
                pytest.fail("exact Fastmail tool name was not reviewable", pytrace=False)
            if detail.locator(".effect-evidence-card").count() != 3:
                pytest.fail("effect evidence sources were not retained separately", pytrace=False)
            try:
                discovered_tool = json.loads(
                    detail.locator(".integration-json").text_content() or ""
                )
            except json.JSONDecodeError:
                pytest.fail(
                    "exact discovered tool definition was not canonical JSON",
                    pytrace=False,
                )
            expected_tool = next(
                tool
                for tool in load_reference_discovery_fixture("fastmail")["tools"]
                if tool["name"] == "search_email"
            )
            if discovered_tool != expected_tool:
                pytest.fail(
                    "browser detail was not bound to the exact fixture schema",
                    pytrace=False,
                )

            form = detail.locator("#effect-review-form")
            form.locator("select[name='mutation']").select_option("none")
            for field in (
                "external_communication",
                "code_execution",
                "privilege_change",
                "open_world",
            ):
                form.locator(f"select[name='{field}']").select_option("false")
            form.locator("select[name='idempotent']").select_option("true")
            recommendation = _normalized_text(form.locator("[data-effect-recommendation]"))
            if recommendation != (
                "passthrough — staged recommendation only; live dispatch stays disabled."
            ):
                pytest.fail(
                    "browser recommendation did not match the complete profile",
                    pytrace=False,
                )
            form.locator("input[name='totp_proof']").fill(
                credential_value(demo.root, "web-action-proof")
            )
            with page.expect_navigation(wait_until="domcontentloaded"):
                form.get_by_role("button", name="Record review with fake proof").click()
            page.wait_for_url(
                re.compile(
                    rf"{re.escape(demo.web_origin)}/integrations/tools/.+#effect-review-current$"
                )
            )

            current = page.locator("#effect-review-current")
            current_text = _normalized_text(current)
            for expected in (
                "passthrough recommendation",
                "Current",
                f"Reviewed by web:{DEMO_USER_ID}",
                "TOTP via the authenticated web app",
            ):
                if expected not in current_text:
                    pytest.fail(
                        f"current effect review omitted {expected!r}",
                        pytrace=False,
                    )
            expected_effects = {
                "Mutation": "none",
                "External communication": "false",
                "Code execution": "false",
                "Privilege change": "false",
                "Open world": "false",
                "Idempotent": "true",
            }
            for label, expected in expected_effects.items():
                if _definition_value(current, label) != expected:
                    pytest.fail(
                        f"current effect review misstated {label!r}",
                        pytrace=False,
                    )
            if page.locator(".effect-review-history li").count() != 1:
                pytest.fail("effect review history was not append-only and singular", pytrace=False)
            if "Live dispatch is disabled" not in _normalized_text(page.locator("main")):
                pytest.fail("review result obscured the staged-only boundary", pytrace=False)
            _assert_layout(page)

            context.close()
            browser.close()

        if (
            signals.console_errors != 0
            or signals.page_errors != 0
            or signals.failed_requests != 0
            or signals.error_responses != 0
            or signals.external_requests != 0
        ):
            pytest.fail(
                "staged integration browser workflow emitted an application or network error: "
                f"console={signals.console_errors}, page={signals.page_errors}, "
                f"failed_requests={signals.failed_requests}, "
                f"error_responses={signals.error_responses}, "
                f"external_requests={signals.external_requests}, "
                f"request_failures={signals.failed_request_details!r}",
                pytrace=False,
            )
        if signals.post_requests != 2 or not signals.exact_post_origins:
            pytest.fail(
                "integration login and review POSTs did not carry the exact same-origin Origin",
                pytrace=False,
            )

    persisted = build_demo(demo.root)
    with persisted.database.read() as connection:
        review = connection.execute(
            """
            SELECT alias, tool_name, mutation, external_communication,
                   code_execution, privilege_change, open_world, idempotent,
                   recommended_mode, auth_kind
            FROM connector_effect_reviews
            """
        ).fetchall()
        dispatch_counts = {
            "approval_requests": int(
                connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]
            ),
            "execution_attempts": int(
                connection.execute("SELECT COUNT(*) FROM execution_attempts").fetchone()[0]
            ),
            "request_events": int(
                connection.execute("SELECT COUNT(*) FROM request_events").fetchone()[0]
            ),
        }
        enabled_schema_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM schema_cache WHERE review_state != 'unreviewed'"
            ).fetchone()[0]
        )
    assert [tuple(row) for row in review] == [
        (
            "fastmail-staged",
            "search_email",
            "none",
            "false",
            "false",
            "false",
            "false",
            "true",
            "passthrough",
            "totp",
        )
    ]
    assert dispatch_counts == {
        "approval_requests": 0,
        "execution_attempts": 0,
        "request_events": 0,
    }
    assert enabled_schema_count == 0
    assert all(client.mutation_calls == 0 for client in persisted.provider_clients.values())


def test_fake_demo_browser_approval_and_denial_workflow(tmp_path: Path) -> None:
    with _served_demo(tmp_path) as demo:
        approved_id, denied_id, email_arguments = _enqueue_requests(demo)
        signals = BrowserSignals()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--no-first-run",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                locale="en-US",
                timezone_id="UTC",
                service_workers="block",
            )
            page = context.new_page()
            page.set_default_timeout(10_000)
            page.set_default_navigation_timeout(15_000)
            _install_network_guards(page, demo, signals)

            _login(page, demo)
            queue_text = page.locator("body").inner_text()
            if "2 waiting" not in queue_text:
                pytest.fail("authenticated queue did not contain both requests", pytrace=False)

            email_review = _expand_request(page, approved_id)
            _assert_bound_context(
                email_review,
                request_id=approved_id,
                state="pending_approval",
                alias="fastmail",
                tool_name="send_email",
                arguments=email_arguments,
            )
            email_text = email_review.text_content() or ""
            for expected in (
                EMAIL_ARGUMENTS["from"],
                EMAIL_ARGUMENTS["to"][0],
                EMAIL_ARGUMENTS["subject"],
                EMAIL_ARGUMENTS["body"],
            ):
                if expected not in email_text:
                    pytest.fail("expanded email context omitted reviewed content", pytrace=False)
            attachment_row = email_review.locator(".attachment-band tbody tr")
            if attachment_row.count() != 1:
                pytest.fail("expanded email context omitted its frozen attachment", pytrace=False)
            attachment_text = _normalized_text(attachment_row)
            attachment = email_arguments["attachments"][0]
            for expected in (
                "payroll-review.svg",
                "image/svg+xml",
                str(attachment["detected_mime"]),
                str(attachment["sha256"]),
            ):
                if expected not in attachment_text:
                    pytest.fail("attachment review omitted frozen metadata", pytrace=False)
            download_link = attachment_row.get_by_role("link", name="Download frozen bytes")
            signals.expected_download_url = download_link.evaluate("(node) => node.href")
            with page.expect_download() as download_info:
                download_link.click()
            download = download_info.value
            if download.suggested_filename != "signet-attachment.bin":
                pytest.fail("attachment download exposed an unsafe source filename", pytrace=False)
            downloaded_path = download.path()
            if (
                downloaded_path is None
                or downloaded_path.read_bytes() != BROWSER_ATTACHMENT_CONTENT
            ):
                pytest.fail(
                    "attachment download did not preserve the exact frozen bytes",
                    pytrace=False,
                )
            _assert_layout(page)
            for viewport in (
                {"width": 390, "height": 844},
                {"width": 320, "height": 720},
                {"width": 640, "height": 450},
            ):
                page.set_viewport_size(viewport)
                _assert_layout(page)
            page.set_viewport_size({"width": 1280, "height": 900})
            page.evaluate("document.documentElement.style.zoom = '2'")
            _assert_layout(page)
            page.evaluate("document.documentElement.style.zoom = ''")
            page.emulate_media(forced_colors="active")
            _assert_layout(page)
            page.emulate_media(forced_colors="none")
            page.set_viewport_size({"width": 1440, "height": 900})

            _submit_decision(
                page,
                demo,
                email_review,
                approved_id,
                action="approve",
                note=APPROVAL_NOTE,
            )
            page.goto(f"{demo.web_origin}/", wait_until="domcontentloaded")
            whatsapp_review = _expand_request(page, denied_id)
            _assert_bound_context(
                whatsapp_review,
                request_id=denied_id,
                state="pending_approval",
                alias="whatsapp",
                tool_name="send_text",
                arguments=WHATSAPP_ARGUMENTS,
            )
            whatsapp_text = whatsapp_review.text_content() or ""
            for expected in (WHATSAPP_ARGUMENTS["to"], WHATSAPP_ARGUMENTS["message"]):
                if expected not in whatsapp_text:
                    pytest.fail("expanded WhatsApp context omitted reviewed content", pytrace=False)
            page.set_viewport_size({"width": 320, "height": 720})
            _assert_layout(page)
            page.set_viewport_size({"width": 1440, "height": 900})
            _submit_decision(
                page,
                demo,
                whatsapp_review,
                denied_id,
                action="deny",
                note=DENIAL_NOTE,
            )

            _wait_for_success(page, demo, approved_id)
            approved_review = _expand_request(page, approved_id)
            denied_review = _expand_request(page, denied_id)
            for review, request_id, alias, tool_name, arguments, expected in (
                (
                    approved_review,
                    approved_id,
                    "fastmail",
                    "send_email",
                    email_arguments,
                    (
                        "succeeded",
                        "Downstream effect confirmed",
                        APPROVAL_NOTE,
                        APPROVAL_REASON,
                    ),
                ),
                (
                    denied_review,
                    denied_id,
                    "whatsapp",
                    "send_text",
                    WHATSAPP_ARGUMENTS,
                    ("denied", "Nothing was executed downstream", DENIAL_NOTE, DENIAL_REASON),
                ),
            ):
                _assert_bound_context(
                    review,
                    request_id=request_id,
                    state=expected[0],
                    alias=alias,
                    tool_name=tool_name,
                    arguments=arguments,
                )
                review_text = _normalized_text(review)
                for value in (*expected, "Confirmation: TOTP via web"):
                    if value not in review_text:
                        pytest.fail(
                            "audit decision omitted terminal truth or rationale", pytrace=False
                        )

            approved_text = approved_review.text_content() or ""
            denied_text = denied_review.text_content() or ""
            for expected in (
                EMAIL_ARGUMENTS["to"][0],
                EMAIL_ARGUMENTS["subject"],
                EMAIL_ARGUMENTS["body"],
            ):
                if expected not in approved_text:
                    pytest.fail("approved audit context is incomplete", pytrace=False)
            for expected in (WHATSAPP_ARGUMENTS["to"], WHATSAPP_ARGUMENTS["message"]):
                if expected not in denied_text:
                    pytest.fail("denied audit context is incomplete", pytrace=False)

            audit_summary = _normalized_text(
                _decision_locator(page, approved_id).locator(":scope > details > summary")
            )
            if "TOTP via web" not in audit_summary or DEMO_USER_ID not in audit_summary:
                pytest.fail("audit summary omitted confirmation provenance", pytrace=False)
            audit_html = page.content()
            for field in ("web-password", "web-login-proof", "web-action-proof", "mcp-token"):
                if credential_value(demo.root, field) in audit_html:
                    pytest.fail("audit UI exposed a live credential", pytrace=False)

            _assert_keyboard_focus(page)
            for viewport in (
                {"width": 1440, "height": 900},
                {"width": 390, "height": 844},
                {"width": 320, "height": 720},
                {"width": 640, "height": 450},
            ):
                page.set_viewport_size(viewport)
                _assert_layout(page)

            page.set_viewport_size({"width": 390, "height": 844})
            page.goto(f"{demo.web_origin}/", wait_until="domcontentloaded")
            audit_link = page.locator("a.primary-audit-link")
            if not audit_link.is_visible():
                pytest.fail("mobile primary navigation hid Audit", pytrace=False)
            audit_box = audit_link.bounding_box()
            if audit_box is None or audit_box["width"] < 43.5 or audit_box["height"] < 43.5:
                pytest.fail("mobile Audit navigation target is undersized", pytrace=False)
            audit_link.click()
            page.wait_for_url(f"{demo.web_origin}/audit")
            page.wait_for_load_state("networkidle")

            context.close()
            browser.close()

        if (
            signals.console_errors != 0
            or signals.page_errors != 0
            or signals.failed_requests != 0
            or signals.error_responses != 0
            or signals.external_requests != 0
        ):
            pytest.fail(
                "browser workflow emitted a page, console, HTTP, or network error: "
                f"console={signals.console_errors}, page={signals.page_errors}, "
                f"failed_requests={signals.failed_requests}, "
                f"error_responses={signals.error_responses}, "
                f"external_requests={signals.external_requests}, "
                f"request_failures={signals.failed_request_details!r}",
                pytrace=False,
            )
        if signals.post_requests < 3 or not signals.exact_post_origins:
            pytest.fail(
                "browser form POSTs did not carry the exact same-origin Origin", pytrace=False
            )


def test_fake_demo_audit_expansions_are_event_bound_read_only_and_unique(
    tmp_path: Path,
) -> None:
    with _served_demo(tmp_path) as demo:
        request_id, _other_request_id, version_one_arguments = _enqueue_requests(demo)
        assembly = build_demo(demo.root)
        version_one = assembly.state_machine.get_request(request_id)
        version_one_hash = str(version_one["current_payload_hash"])
        long_actor = "web:" + "maximum_identifier_" * 16
        with assembly.database.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO request_events(
                    request_id, actor, action, occurred_at,
                    version, payload_hash, safe_details_json
                ) VALUES (?, ?, 'policy_promoted_to_approval', ?, 1, ?, ?)
                """,
                (
                    request_id,
                    long_actor,
                    int(time.time()),
                    version_one_hash,
                    json.dumps(
                        {
                            "alias": "fastmail",
                            "config_hash": "c" * 64,
                            "new_mode": "approval",
                            "old_mode": "deny",
                            "originating_event": "one_click_confirmation",
                            "policy_version": 2,
                            "tool": "send_email",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            promotion_event_id = int(cursor.lastrowid)

        signals = BrowserSignals()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                locale="en-US",
                timezone_id="UTC",
                service_workers="block",
            )
            page = context.new_page()
            page.set_default_timeout(10_000)
            page.set_default_navigation_timeout(15_000)
            _install_network_guards(page, demo, signals)
            _login(page, demo)

            current_review = _expand_request(page, request_id)
            version_two_arguments = {
                **version_one_arguments,
                "body": "This is the exact edited version two browser body.",
            }
            edit_form = current_review.locator(".edit-band form")
            edit_form.locator("[data-edit-json]").fill(json.dumps(version_two_arguments))
            edit_form.locator("input[name='totp_proof']").fill(
                credential_value(demo.root, "web-action-proof")
            )
            with page.expect_navigation(wait_until="domcontentloaded"):
                edit_form.get_by_role("button", name="Confirm edit").click()
            page.wait_for_url(f"{demo.web_origin}/requests/{request_id}")

            version_two = assembly.state_machine.get_request(request_id)
            version_two_hash = str(version_two["current_payload_hash"])
            if version_two_hash == version_one_hash or int(version_two["current_version"]) != 2:
                pytest.fail("browser edit did not create a distinct second revision", pytrace=False)
            _submit_decision(
                page,
                demo,
                page.locator(".request-review"),
                request_id,
                action="deny",
                note=DENIAL_NOTE,
            )
            with assembly.database.read() as connection:
                denial = connection.execute(
                    """
                    SELECT event_id FROM request_events
                    WHERE request_id = ? AND action = 'denied'
                    ORDER BY event_id DESC LIMIT 1
                    """,
                    (request_id,),
                ).fetchone()
            if denial is None:
                pytest.fail("browser denial did not retain its decision event", pytrace=False)
            denial_event_id = int(denial["event_id"])

            rows = page.locator(f'[data-decision-request-id="{request_id}"]')
            if rows.count() != 2:
                pytest.fail("Audit did not retain both decisions for one request", pytrace=False)
            promotion_fragment = page.locator(
                f'[data-review-url="/audit/events/{promotion_event_id}/review"]'
            )
            denial_fragment = page.locator(
                f'[data-review-url="/audit/events/{denial_event_id}/review"]'
            )
            for fragment in (promotion_fragment, denial_fragment):
                details = fragment.locator("..")
                if details.get_attribute("open") is None:
                    details.locator(":scope > summary").click()
                fragment.locator(".request-review").wait_for(state="visible")

            promotion_review = promotion_fragment.locator(".request-review")
            denial_review = denial_fragment.locator(".request-review")
            promotion_summary = _normalized_text(
                promotion_fragment.locator("..").locator(":scope > summary")
            )
            denial_summary = _normalized_text(
                denial_fragment.locator("..").locator(":scope > summary")
            )
            if "Policy change approved: approval" not in promotion_summary:
                pytest.fail("Audit mislabeled the approval policy change", pytrace=False)
            if "Request denied" not in denial_summary:
                pytest.fail("Audit mislabeled the request denial", pytrace=False)

            for review, event_id, version, payload_hash, expected_body in (
                (
                    promotion_review,
                    promotion_event_id,
                    "1",
                    version_one_hash,
                    str(version_one_arguments["body"]),
                ),
                (
                    denial_review,
                    denial_event_id,
                    "2",
                    version_two_hash,
                    str(version_two_arguments["body"]),
                ),
            ):
                text = _normalized_text(review)
                if (
                    expected_body not in text
                    or _context_value(review, "Selected payload version") != version
                    or _context_value(review, "Selected payload hash") != payload_hash
                    or review.get_attribute("data-historical-event-id") != str(event_id)
                ):
                    pytest.fail(
                        "Audit expansion was not bound to its exact event revision",
                        pytrace=False,
                    )
                if review.locator("form, [data-passkey-action], [data-csrf]").count() != 0:
                    pytest.fail(
                        "historical Audit expansion exposed mutation controls",
                        pytrace=False,
                    )
                if review.get_by_role("link", name="Download frozen bytes").count() != 0:
                    pytest.fail(
                        "historical Audit expansion exposed a current-only download",
                        pytrace=False,
                    )

            promotion_timeline = _normalized_text(promotion_review.locator(".timeline"))
            denial_timeline = _normalized_text(denial_review.locator(".timeline"))
            if "payload_edited" in promotion_timeline or "denied" in promotion_timeline:
                pytest.fail("earlier Audit event included later mutable history", pytrace=False)
            if "payload_edited" not in denial_timeline or "denied" not in denial_timeline:
                pytest.fail("later Audit event omitted its immutable prior context", pytrace=False)

            document_ids = page.locator("[id]").evaluate_all("nodes => nodes.map(node => node.id)")
            if len(document_ids) != len(set(document_ids)):
                pytest.fail("expanded Audit events produced duplicate DOM IDs", pytrace=False)
            if (
                promotion_review.locator(f"#context-audit-event-{promotion_event_id}").count() != 1
                or denial_review.locator(f"#context-audit-event-{denial_event_id}").count() != 1
            ):
                pytest.fail("expanded Audit events did not use event-derived IDs", pytrace=False)

            page.set_viewport_size({"width": 320, "height": 720})
            _assert_layout(page)
            _assert_identifier_wraps(
                promotion_fragment.locator("..").locator(".request-summary-meta > span").last
            )
            _assert_identifier_wraps(
                promotion_review.locator(".timeline li").last.locator(".timeline-heading span")
            )
            _assert_identifier_wraps(promotion_review.locator(".historical-band .hash-value"))

            failure_signals = BrowserSignals()
            failure_page = context.new_page()
            _install_network_guards(failure_page, demo, failure_signals)
            failure_page.goto(f"{demo.web_origin}/audit", wait_until="domcontentloaded")
            promotion_review_url = f"{demo.web_origin}/audit/events/{promotion_event_id}/review"
            failure_page.route(
                promotion_review_url,
                lambda route: route.fulfill(
                    status=503,
                    content_type="text/plain; charset=utf-8",
                    body="temporary exact-event review failure",
                ),
            )
            failed_fragment = failure_page.locator(
                f'[data-review-url="/audit/events/{promotion_event_id}/review"]'
            )
            failed_fragment.locator("..").locator(":scope > summary").click()
            failed_fragment.get_by_text("Close and reopen to retry", exact=False).wait_for()
            exact_fallback = failed_fragment.get_by_role("link", name="dedicated audit event view")
            if exact_fallback.get_attribute("href") != f"/audit/events/{promotion_event_id}":
                pytest.fail("failed Audit expansion lost its exact event route", pytrace=False)
            exact_fallback.click()
            failure_page.wait_for_url(f"{demo.web_origin}/audit/events/{promotion_event_id}")
            exact_review = failure_page.locator(".request-review")
            exact_review.wait_for(state="visible")
            if (
                _context_value(exact_review, "Selected payload version") != "1"
                or _context_value(exact_review, "Selected payload hash") != version_one_hash
                or str(version_one_arguments["body"]) not in _normalized_text(exact_review)
                or exact_review.locator("form, [data-passkey-action], [data-csrf]").count() != 0
            ):
                pytest.fail(
                    "failed Audit expansion fallback was not exact-event-bound and read-only",
                    pytrace=False,
                )
            _assert_layout(failure_page)
            failure_page.close()
            if (
                failure_signals.error_responses != 1
                # Chromium reports the deliberately injected 503 as one console error.
                or failure_signals.console_errors != 1
                or failure_signals.page_errors != 0
                or failure_signals.failed_requests != 0
                or failure_signals.external_requests != 0
            ):
                pytest.fail(
                    f"Unexpected Audit fallback browser signals: {failure_signals!r}",
                    pytrace=False,
                )

            no_js_signals = BrowserSignals()
            no_js_context = browser.new_context(
                viewport={"width": 390, "height": 844},
                locale="en-US",
                timezone_id="UTC",
                java_script_enabled=False,
                service_workers="block",
            )
            no_js_page = no_js_context.new_page()
            no_js_page.set_default_timeout(10_000)
            no_js_page.set_default_navigation_timeout(15_000)
            _install_network_guards(no_js_page, demo, no_js_signals)
            _login(no_js_page, demo)
            no_js_page.goto(f"{demo.web_origin}/audit", wait_until="domcontentloaded")
            no_js_fragment = no_js_page.locator(
                f'[data-review-url="/audit/events/{promotion_event_id}/review"]'
            )
            no_js_fragment.locator("..").locator(":scope > summary").click()
            no_js_fallback = no_js_fragment.get_by_role("link", name="dedicated audit event view")
            if (
                not no_js_fallback.is_visible()
                or no_js_fallback.get_attribute("href") != f"/audit/events/{promotion_event_id}"
            ):
                pytest.fail("no-JavaScript Audit omitted its exact event route", pytrace=False)
            no_js_fallback.click()
            no_js_page.wait_for_url(f"{demo.web_origin}/audit/events/{promotion_event_id}")
            no_js_review = no_js_page.locator(".request-review")
            if (
                _context_value(no_js_review, "Selected payload version") != "1"
                or _context_value(no_js_review, "Selected payload hash") != version_one_hash
                or str(version_one_arguments["body"]) not in _normalized_text(no_js_review)
                or no_js_review.locator("form, [data-passkey-action], [data-csrf]").count() != 0
            ):
                pytest.fail(
                    "no-JavaScript Audit fallback was not exact-event-bound and read-only",
                    pytrace=False,
                )
            _assert_layout(no_js_page)
            no_js_context.close()
            if (
                no_js_signals.console_errors != 0
                or no_js_signals.page_errors != 0
                or no_js_signals.failed_requests != 0
                or no_js_signals.error_responses != 0
                or no_js_signals.external_requests != 0
            ):
                pytest.fail(
                    f"no-JavaScript Audit workflow emitted a browser error: {no_js_signals!r}",
                    pytrace=False,
                )

            context.close()
            browser.close()

        if (
            signals.console_errors != 0
            or signals.page_errors != 0
            or signals.failed_requests != 0
            or signals.error_responses != 0
            or signals.external_requests != 0
        ):
            pytest.fail(
                "event-bound Audit browser workflow emitted an application or network error",
                pytrace=False,
            )
        if signals.post_requests < 3 or not signals.exact_post_origins:
            pytest.fail("event-bound Audit POSTs were not exact same-origin", pytrace=False)


@pytest.mark.parametrize(
    (
        "access_arguments",
        "force_deny_tool",
        "expected_mode",
        "expected_read_only",
        "expected_communication",
        "expected_classification",
        "expected_consequence",
    ),
    (
        (
            ACCESS_ARGUMENTS,
            ("fastmail", "search_email", "passthrough"),
            "passthrough",
            "Yes",
            "Not a communication send",
            "None",
            "Future calls will bypass approval.",
        ),
        (
            APPROVAL_ACCESS_ARGUMENTS,
            ("fastmail", "send_email", "approval"),
            "approval",
            "No",
            "Communication send",
            "None",
            "Future calls will still require separate approval.",
        ),
    ),
    ids=("passthrough", "approval"),
)
def test_fake_demo_browser_tool_access_approval_is_expandable(
    tmp_path: Path,
    access_arguments: Mapping[str, str],
    force_deny_tool: tuple[str, str, str] | None,
    expected_mode: str,
    expected_read_only: str,
    expected_communication: str,
    expected_classification: str,
    expected_consequence: str,
) -> None:
    with _served_demo(tmp_path, force_deny_tool=force_deny_tool) as demo:
        request_id = _enqueue_access_request(demo, access_arguments)
        signals = BrowserSignals()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                locale="en-US",
                timezone_id="UTC",
                service_workers="block",
            )
            page = context.new_page()
            page.set_default_timeout(10_000)
            page.set_default_navigation_timeout(15_000)
            _install_network_guards(page, demo, signals)
            _login(page, demo)

            queue_fragment = page.locator(f'[data-review-url="/requests/{request_id}/review"]')
            queue_summary = queue_fragment.locator("..").locator(":scope > summary")
            queue_summary.focus()
            page.keyboard.press("Enter")
            queue_review = queue_fragment.locator(".request-review")
            try:
                queue_review.wait_for(state="visible")
            except Exception:
                pytest.fail(
                    "tool-access review fragment did not load: "
                    f"{_normalized_text(queue_fragment)!r}",
                    pytrace=False,
                )
            queue_text = _normalized_text(queue_review)
            for expected in (
                "Tool access policy proposal",
                f"{access_arguments['alias']}.{access_arguments['tool']}",
                access_arguments["reason"],
                "Approval changes durable gateway policy; it does not call the requested tool.",
                "Exact policy change on approval",
                expected_consequence,
            ):
                if expected not in queue_text:
                    pytest.fail(
                        "tool-access queue review omitted frozen context "
                        f"{expected!r}: {queue_text!r}",
                        pytrace=False,
                    )
            policy_preview = queue_review.locator("[data-policy-preview]")
            expected_preview = {
                "Exact target": f"{access_arguments['alias']}.{access_arguments['tool']}",
                "Target mode at review": "deny",
                "Proposed new mode": expected_mode,
                "Reviewed read-only": expected_read_only,
                "Communication classification": expected_communication,
                "Reviewed classification": expected_classification,
                "Policy version at review": "1",
                "Expected next version at review": "2",
                "Active policy version": "1",
            }
            for label, value in expected_preview.items():
                if _definition_value(policy_preview, label) != value:
                    pytest.fail(
                        f"tool-access policy preview misstated {label}",
                        pytrace=False,
                    )
            if _context_value(queue_review, "Gateway request") != "Yes":
                pytest.fail("tool-access queue review lost its gateway provenance", pytrace=False)
            if queue_review.locator("[data-approval-reason]").count() != 0:
                pytest.fail("tool-access approval exposed an ordinary send reason", pytrace=False)
            if queue_review.locator(".edit-band").count() != 0:
                pytest.fail(
                    "tool-access approval exposed an invalid retargeting form", pytrace=False
                )

            form = queue_review.locator("form[data-decision-form]")
            form.locator("input[name='totp_proof']").fill(
                credential_value(demo.root, "web-action-proof")
            )
            with page.expect_navigation(wait_until="domcontentloaded"):
                form.locator("button[name='action'][value='approve']").click()
            page.wait_for_url(f"{demo.web_origin}/requests/{request_id}")
            detail_text = _normalized_text(page.locator("main"))
            if (
                "Gateway policy change confirmed; requested tool was not called" not in detail_text
                or "Downstream effect confirmed" in detail_text
            ):
                pytest.fail("tool-access detail misstated the policy-only outcome", pytrace=False)

            page.goto(f"{demo.web_origin}/audit", wait_until="domcontentloaded")
            decision = _decision_locator(page, request_id)
            if decision.count() != 1:
                pytest.fail("approved tool-access request is missing from Audit", pytrace=False)
            decision_summary = decision.locator(":scope > details > summary")
            summary_text = _normalized_text(decision_summary)
            for expected in (
                f"Policy change approved: {expected_mode}",
                "gateway / request_tool_access",
                "succeeded",
                f"web:{DEMO_USER_ID}",
                "TOTP via web",
            ):
                if expected not in summary_text:
                    pytest.fail("tool-access Audit summary omitted provenance", pytrace=False)

            decision_summary.focus()
            page.keyboard.press("Space")
            audit_review = decision.locator("[data-review-fragment] .request-review")
            audit_review.wait_for(state="visible")
            audit_text = _normalized_text(audit_review)
            for expected in (
                "Tool access policy proposal",
                "Gateway policy change confirmed; requested tool was not called",
                access_arguments["reason"],
                f"policy_promoted_to_{expected_mode}",
                "Confirmation: TOTP via web",
                f'"new_mode": "{expected_mode}"',
                '"old_mode": "deny"',
                '"status": "policy_updated"',
            ):
                if expected not in audit_text:
                    pytest.fail("tool-access Audit expansion omitted bound context", pytrace=False)
            if "Downstream effect confirmed" in audit_text:
                pytest.fail("tool-access Audit expansion claimed a downstream call", pytrace=False)
            if (
                audit_review.locator("form, [data-passkey-action], [data-csrf]").count() != 0
                or audit_review.get_by_role("link", name="Download frozen bytes").count() != 0
            ):
                pytest.fail("tool-access Audit expansion exposed mutation controls", pytrace=False)
            _assert_layout(page)
            page.set_viewport_size({"width": 320, "height": 720})
            _assert_layout(page)
            _assert_truth_state_not_clipped(audit_review)

            audit_html = page.content()
            for field in ("web-password", "web-login-proof", "web-action-proof", "mcp-token"):
                if credential_value(demo.root, field) in audit_html:
                    pytest.fail("tool-access Audit exposed a credential", pytrace=False)
            context.close()
            browser.close()

        if (
            signals.console_errors != 0
            or signals.page_errors != 0
            or signals.failed_requests != 0
            or signals.error_responses != 0
            or signals.external_requests != 0
        ):
            pytest.fail(
                "tool-access browser workflow emitted an application or network error",
                pytrace=False,
            )
        if signals.post_requests < 2 or not signals.exact_post_origins:
            pytest.fail(
                "tool-access browser POSTs did not carry the exact same-origin Origin",
                pytrace=False,
            )


def test_fake_demo_browser_stale_tool_access_keeps_context_and_can_be_denied(
    tmp_path: Path,
) -> None:
    with _served_demo(
        tmp_path,
        force_deny_tool=("fastmail", "search_email", "passthrough"),
    ) as demo:
        first_id = _enqueue_access_request(demo, ACCESS_ARGUMENTS)
        stale_arguments = {
            **ACCESS_ARGUMENTS,
            "reason": "Keep this exact stale proposal visible so a human can deny it.",
        }
        stale_id = _enqueue_access_request(demo, stale_arguments)
        signals = BrowserSignals()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                locale="en-US",
                timezone_id="UTC",
                service_workers="block",
            )
            page = context.new_page()
            page.set_default_timeout(10_000)
            page.set_default_navigation_timeout(15_000)
            _install_network_guards(page, demo, signals)
            _login(page, demo)

            first_review = _expand_request(page, first_id)
            first_form = first_review.locator("form[data-decision-form]")
            first_form.locator("input[name='totp_proof']").fill(
                credential_value(demo.root, "web-action-proof")
            )
            with page.expect_navigation(wait_until="domcontentloaded"):
                first_form.locator("button[name='action'][value='approve']").click()
            page.wait_for_url(f"{demo.web_origin}/requests/{first_id}")

            page.goto(f"{demo.web_origin}/", wait_until="domcontentloaded")
            stale_review = _expand_request(page, stale_id)
            stale_text = _normalized_text(stale_review)
            for expected in (
                "Frozen policy proposal at review",
                stale_arguments["reason"],
                "reviewed against policy v1, but active policy is v2",
                "It cannot be approved. Deny or cancel it, then request fresh access.",
            ):
                if expected not in stale_text:
                    pytest.fail(
                        f"stale tool-access review omitted {expected!r}: {stale_text!r}",
                        pytrace=False,
                    )
            stale_preview = stale_review.locator("[data-policy-preview]")
            for label, expected_value in {
                "Policy version at review": "1",
                "Expected next version at review": "2",
                "Active policy version": "2",
            }.items():
                if _definition_value(stale_preview, label) != expected_value:
                    pytest.fail(
                        f"stale tool-access review misstated {label}",
                        pytrace=False,
                    )
            if stale_review.locator("button[name='action'][value='approve']").count() != 0:
                pytest.fail("stale tool-access review still offered approval", pytrace=False)
            if stale_review.locator("button[name='action'][value='deny']").count() != 1:
                pytest.fail("stale tool-access review omitted denial", pytrace=False)
            if stale_review.locator("button[name='action'][value='cancel']").count() != 1:
                pytest.fail("stale tool-access review omitted cancellation", pytrace=False)

            page.set_viewport_size({"width": 320, "height": 720})
            _assert_layout(page)
            page.set_viewport_size({"width": 1280, "height": 900})
            _submit_decision(
                page,
                demo,
                stale_review,
                stale_id,
                action="deny",
                note=DENIAL_NOTE,
            )

            decision = _decision_locator(page, stale_id)
            if decision.count() != 1:
                pytest.fail("denied stale tool-access request is missing from Audit", pytrace=False)
            decision_details = decision.locator(":scope > details")
            if decision_details.get_attribute("open") is None:
                decision.locator(":scope > details > summary").click()
            audit_review = decision.locator("[data-review-fragment] .request-review")
            audit_review.wait_for(state="visible")
            audit_text = _normalized_text(audit_review)
            for expected in (
                "denied",
                "Nothing was executed downstream",
                "Frozen policy proposal at review",
                stale_arguments["reason"],
            ):
                if expected not in audit_text:
                    pytest.fail(
                        f"denied stale Audit expansion omitted {expected!r}",
                        pytrace=False,
                    )
            audit_preview = audit_review.locator("[data-policy-preview]")
            if (
                _definition_value(audit_preview, "Target mode at review") != "deny"
                or _definition_value(audit_preview, "Proposed new mode") != "passthrough"
            ):
                pytest.fail("denied stale Audit expansion misstated the proposal", pytrace=False)
            if audit_review.locator(".action-band").count() != 0:
                pytest.fail("terminal stale Audit expansion exposed action controls", pytrace=False)
            if audit_review.locator("form, [data-passkey-action], [data-csrf]").count() != 0:
                pytest.fail("denied stale Audit expansion was not read-only", pytrace=False)
            _assert_layout(page)
            context.close()
            browser.close()

        if (
            signals.console_errors != 0
            or signals.page_errors != 0
            or signals.failed_requests != 0
            or signals.error_responses != 0
            or signals.external_requests != 0
        ):
            pytest.fail(
                "stale tool-access browser workflow emitted an application or network error",
                pytrace=False,
            )
        if signals.post_requests < 3 or not signals.exact_post_origins:
            pytest.fail(
                "stale tool-access browser POSTs did not carry the exact same-origin Origin",
                pytrace=False,
            )


def test_fake_demo_browser_cancel_omits_shared_decision_rationale(tmp_path: Path) -> None:
    with _served_demo(tmp_path) as demo:
        request_id, _other_request_id, email_arguments = _enqueue_requests(demo)
        signals = BrowserSignals()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 390, "height": 844},
                locale="en-US",
                timezone_id="UTC",
                service_workers="block",
            )
            page = context.new_page()
            page.set_default_timeout(10_000)
            page.set_default_navigation_timeout(15_000)
            _install_network_guards(page, demo, signals)
            _login(page, demo)
            review = _expand_request(page, request_id)
            _assert_passkey_note_routing(review)

            edited_arguments = {
                **email_arguments,
                "body": "Edited in the browser before cancellation.",
            }
            edit_form = review.locator(".edit-band form")
            edit_form.locator("[data-edit-json]").fill(json.dumps(edited_arguments))
            edit_form.locator("input[name='totp_proof']").fill(
                credential_value(demo.root, "web-action-proof")
            )
            with page.expect_navigation(wait_until="domcontentloaded"):
                edit_form.get_by_role("button", name="Confirm edit").click()
            page.wait_for_url(f"{demo.web_origin}/requests/{request_id}")

            review = page.locator(".request-review")
            edited_event = review.locator(".timeline li").filter(has_text="payload_edited")
            if "Confirmation: TOTP via web" not in _normalized_text(edited_event):
                pytest.fail("browser edit omitted confirmation provenance", pytrace=False)

            rejected_note = "duplicate_request"
            review.locator("[data-denial-reason]").select_option(rejected_note)
            form = review.locator("form[data-decision-form]")
            form.locator("input[name='totp_proof']").fill(
                credential_value(demo.root, "web-action-proof")
            )
            with page.expect_navigation(wait_until="domcontentloaded"):
                form.locator("button[name='action'][value='cancel']").click()
            page.wait_for_url(f"{demo.web_origin}/requests/{request_id}")

            detail = _normalized_text(page.locator("main"))
            if "cancelled" not in detail or "Nothing was executed downstream" not in detail:
                pytest.fail("browser cancellation did not preserve terminal truth", pytrace=False)
            cancelled_event = page.locator(".timeline li").filter(has_text="cancelled")
            if "Confirmation: TOTP via web" not in _normalized_text(cancelled_event):
                pytest.fail("browser cancellation omitted confirmation provenance", pytrace=False)
            if rejected_note in detail:
                pytest.fail("cancellation retained a decision-only rationale", pytrace=False)
            _assert_layout(page)
            context.close()
            browser.close()

        if (
            signals.console_errors != 0
            or signals.page_errors != 0
            or signals.failed_requests != 0
            or signals.error_responses != 0
            or signals.external_requests != 0
        ):
            pytest.fail(
                "browser cancellation emitted an application or network error", pytrace=False
            )
        if signals.post_requests < 2 or not signals.exact_post_origins:
            pytest.fail(
                "browser cancellation did not carry the exact same-origin Origin", pytrace=False
            )


def test_expand_failure_preserves_dedicated_link_and_retries(tmp_path: Path) -> None:
    with _served_demo(tmp_path) as demo:
        request_id, _other_request_id, email_arguments = _enqueue_requests(demo)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 390, "height": 844},
                locale="en-US",
                timezone_id="UTC",
                service_workers="block",
            )
            page = context.new_page()
            page.set_default_timeout(10_000)
            page.set_default_navigation_timeout(15_000)
            _login(page, demo)
            attempts = 0

            def fail_once(route: Route) -> None:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    route.fulfill(
                        status=503,
                        content_type="text/plain; charset=utf-8",
                        body="temporary review failure",
                    )
                    return
                route.continue_()

            review_url = f"{demo.web_origin}/requests/{request_id}/review"
            page.route(review_url, fail_once)
            fragment = page.locator(f'[data-review-url="/requests/{request_id}/review"]')
            expander = fragment.locator("..")
            summary = expander.locator(":scope > summary")
            summary.click()
            fragment.get_by_text("Close and reopen to retry", exact=False).wait_for()
            fallback = fragment.get_by_role("link", name="dedicated request view")
            if fallback.get_attribute("href") != f"/requests/{request_id}":
                pytest.fail("failed expansion lost its dedicated review route", pytrace=False)
            if fragment.get_attribute("aria-busy") is not None:
                pytest.fail("failed expansion remained marked busy", pytrace=False)

            summary.click()
            summary.click()
            review = fragment.locator(".request-review")
            review.wait_for(state="visible")
            _assert_bound_context(
                review,
                request_id=request_id,
                state="pending_approval",
                alias="fastmail",
                tool_name="send_email",
                arguments=email_arguments,
            )
            if attempts != 2:
                pytest.fail("failed expansion did not retry exactly once", pytrace=False)
            context.close()
            browser.close()

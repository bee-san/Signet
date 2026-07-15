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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from playwright.sync_api import ConsoleMessage, Locator, Page, Request, Route, sync_playwright

from signet.demo import (
    DEMO_GRACEFUL_SHUTDOWN_SECONDS,
    DEMO_NAMESPACE,
    DEMO_USER_ID,
    build_demo,
    credential_value,
    initialize_demo,
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
def _served_demo(tmp_path: Path) -> Iterator[LiveDemo]:
    private_parent = tmp_path / "browser-acceptance"
    private_parent.mkdir(mode=0o700)
    os.chmod(private_parent, 0o700)
    root = private_parent / "state"
    initialize_demo(root)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        pytest.fail("browser demo state directory is not private", pytrace=False)

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
    for label in (
        "Request",
        "State",
        "Created",
        "Expires",
        "Version",
        "Payload hash",
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
    pytest.fail("expanded request context omitted a bound value", pytrace=False)


def _context_value(review: Locator, label: str) -> str:
    return _normalized_text(_context_definition(review, label))


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
    expected_values = {
        "Request": request_id,
        "State": state.replace("_", " "),
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

    if re.fullmatch(r"[1-9][0-9]*", _context_value(review, "Version")) is None:
        pytest.fail("expanded request context included an invalid version", pytrace=False)
    payload_hash = _context_value(review, "Payload hash")
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
            "button, input:not([type='hidden']), textarea, summary, a[href]"
          );
          const undersized = Array.from(controls).filter((element) => {
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            const visible =
              style.display !== "none" &&
              style.visibility !== "hidden" &&
              rect.width > 0 &&
              rect.height > 0;
            return visible && (rect.width < 43.5 || rect.height < 43.5);
          }).length;
          return { horizontalOverflow, undersized };
        }
        """
    )
    if metrics != {"horizontalOverflow": False, "undersized": 0}:
        pytest.fail("browser layout overflowed or exposed an undersized control", pytrace=False)


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
        state = page.locator(f"#decision-{request_id} .state")
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
                page.locator(f"#decision-{approved_id} > details > summary")
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
                "browser workflow emitted a page, console, HTTP, or network error", pytrace=False
            )
        if signals.post_requests < 3 or not signals.exact_post_origins:
            pytest.fail(
                "browser form POSTs did not carry the exact same-origin Origin", pytrace=False
            )


def test_fake_demo_browser_cancel_omits_shared_decision_rationale(tmp_path: Path) -> None:
    with _served_demo(tmp_path) as demo:
        request_id, _other_request_id, _email_arguments = _enqueue_requests(demo)
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

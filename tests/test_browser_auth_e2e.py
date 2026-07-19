from __future__ import annotations

import base64
import json
import re
import socket
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx
import pyotp
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from playwright.sync_api import Page, expect, sync_playwright

from signet.auth import (
    ActionBinding,
    Argon2PasswordVerifier,
    PasswordAuthenticator,
    ProofCapability,
    SessionManager,
    SessionPrincipal,
    SQLiteAttemptLimiter,
    SQLiteAuthenticationTransactions,
    SQLitePasswordCredentialRepository,
    SQLiteSessionRepository,
    TotpLoginProof,
    WebAuthnLoginProof,
)
from signet.authenticator_management import AuthenticatorManager
from signet.browser_auth import BootstrapService, BrowserAuthController
from signet.credential_broker import CredentialError, Secret, SecretReference
from signet.db import Database
from signet.totp import SQLiteTotpCredentialRepository, TotpVerifier
from signet.totp_enrollment import TotpEnrollmentService
from signet.web import (
    CsrfManager,
    LoginOptions,
    QueuePage,
    WebBackend,
    WebSettings,
    WebUnauthorized,
    create_web_app,
)
from signet.webauthn import (
    AssertionInspection,
    ProviderVerification,
    SQLiteWebAuthnRepository,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
)
from signet.webauthn_registration import (
    PasskeyRegistrationService,
    RegistrationResult,
)

NOW = 1_800_000_000
USER_ID = "owner@example.test"
PASSWORD = "correct horse battery staple"


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class BrowserSecretStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def create(self, factor_id: str) -> str:
        existing_codes = {pyotp.TOTP(value).at(NOW) for value in self.values.values()}
        while True:
            value = pyotp.random_base32()
            if pyotp.TOTP(value).at(NOW) not in existing_codes:
                break
        self.values[("BrowserE2E", factor_id)] = value
        return f"keychain://BrowserE2E/{factor_id}"

    def delete(self, secret_reference: str) -> None:
        reference = SecretReference.parse(secret_reference)
        self.values.pop((reference.service, reference.account), None)

    def get(self, reference: SecretReference) -> Secret:
        try:
            return Secret(self.values[(reference.service, reference.account)])
        except KeyError as exc:
            raise CredentialError("test secret is unavailable") from exc


class BrowserRegistrationProvider:
    test_only = True

    def verify(
        self,
        credential: Mapping[str, Any],
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> RegistrationResult:
        client_data = json.loads(
            _decode(str(credential["response"]["clientDataJSON"])).decode("utf-8")
        )
        response = cast(Mapping[str, Any], credential["response"])
        transports = response.get("transports", [])
        assert isinstance(transports, list)
        assert all(isinstance(item, str) for item in transports)
        assert _decode(client_data["challenge"]) == expected_challenge
        assert client_data["origin"] == expected_origin
        assert expected_rp_id == "localhost"
        credential_id = str(credential["id"])
        assert credential_id == str(credential["rawId"])
        return RegistrationResult(
            credential_id=credential_id,
            public_key=b"browser-e2e-public-key",
            sign_count=0,
            device_type="multi_device",
            backed_up=True,
            transports=tuple(cast(list[str], transports)),
            discoverable=True,
        )


class BrowserAssertionProvider:
    test_only = True

    def _client_data(self, assertion: Any) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            json.loads(_decode(str(assertion["response"]["clientDataJSON"])).decode("utf-8")),
        )

    def inspect(self, assertion: Any) -> AssertionInspection:
        client_data = self._client_data(assertion)
        user_handle = assertion["response"].get("userHandle")
        return AssertionInspection(
            credential_id=str(assertion["id"]),
            user_handle=_decode(str(user_handle)) if user_handle is not None else None,
            challenge=_decode(str(client_data["challenge"])),
            origin=str(client_data["origin"]),
            outer_type=str(assertion["type"]),
            client_type=str(client_data["type"]),
            cross_origin=bool(client_data.get("crossOrigin", False)),
        )

    def verify(
        self,
        assertion: Any,
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
        credential_public_key: bytes,
        credential_current_sign_count: int,
    ) -> ProviderVerification:
        inspected = self.inspect(assertion)
        assert inspected.challenge == expected_challenge
        assert inspected.origin == expected_origin
        assert expected_rp_id == "localhost"
        assert credential_public_key == b"browser-e2e-public-key"
        return ProviderVerification(
            credential_id=inspected.credential_id,
            new_sign_count=credential_current_sign_count + 1,
            user_present=True,
            user_verified=True,
            device_type="multi_device",
            backed_up=True,
        )


class BrowserBackend:
    def __init__(
        self,
        database: Database,
        *,
        sessions: SessionManager,
        passwords: PasswordAuthenticator,
        totp: TotpVerifier,
        webauthn_repository: SQLiteWebAuthnRepository,
        webauthn_issuer: WebAuthnChallengeIssuer,
        webauthn_verifier: WebAuthnAssertionVerifier,
        transactions: SQLiteAuthenticationTransactions,
    ) -> None:
        self.sessions = sessions
        self.passwords = passwords
        self.totp = totp
        self.webauthn_repository = webauthn_repository
        self.webauthn_issuer = webauthn_issuer
        self.webauthn_verifier = webauthn_verifier
        self.transactions = transactions

    def authenticate(self, token: str | None, *, now: int) -> SessionPrincipal:
        return self.sessions.authenticate(token, now=now)

    def logout(self, token: str | None, *, now: int) -> None:
        self.sessions.logout(token, now=now)

    def list_queue(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
        cursor: str | None = None,
    ) -> QueuePage:
        del principal, now, cursor
        return QueuePage((), False, None)

    def password_totp_login(
        self,
        user_id: str,
        password: str,
        totp_proof: str,
        *,
        source: str,
        previous_token: str | None,
        now: int,
    ) -> str:
        del previous_token
        preauth_token: str | None = None
        try:
            password_user = self.passwords.authenticate(
                user_id,
                password,
                source_id=source,
                now=now,
            )
            if password_user.user_id != USER_ID:
                raise WebUnauthorized("invalid credentials")
            preauth_token = self.sessions.create_session(
                USER_ID,
                auth_method="preauth:password",
                now=now,
            )
            preauth = self.sessions.authenticate(preauth_token, now=now)
            proof = self.totp.verify(
                USER_ID,
                totp_proof,
                binding=ActionBinding("login"),
                source_id=source,
                session_id=preauth.session_id,
                http_method="POST",
                now=now,
            )
            return self.transactions.complete_totp_login(
                password_user,
                cast(TotpLoginProof, proof),
                now=now,
            )
        except Exception as exc:
            if isinstance(exc, WebUnauthorized):
                raise
            raise WebUnauthorized("invalid credentials") from None
        finally:
            if preauth_token is not None:
                self.sessions.logout(preauth_token, now=now)

    def begin_passkey_login(
        self,
        user_id: str,
        *,
        source: str,
        http_method: str,
        now: int,
    ) -> LoginOptions:
        del source
        if user_id != USER_ID or not self.webauthn_repository.credentials_for_user(user_id):
            raise WebUnauthorized("invalid credentials")
        token = self.sessions.create_session(
            USER_ID,
            auth_method="preauth:webauthn",
            now=now,
        )
        principal = self.sessions.authenticate(token, now=now)
        issued = self.webauthn_issuer.issue(
            USER_ID,
            ActionBinding("login"),
            session_id=principal.session_id,
            http_method=http_method,
            now=now,
        )
        return LoginOptions(
            challenge_id=issued.challenge_id,
            public_key=json.loads(issued.options_json),
        )

    def complete_passkey_login(
        self,
        challenge_id: str,
        assertion: Any,
        *,
        source: str,
        http_method: str,
        previous_token: str | None,
        now: int,
    ) -> str:
        del source, previous_token
        challenge = self.webauthn_repository.find_challenge(challenge_id)
        if challenge is None or challenge.user_id != USER_ID:
            raise WebUnauthorized("invalid credentials")
        try:
            proof = self.webauthn_verifier.verify(
                assertion,
                challenge_id=challenge_id,
                user_id=challenge.user_id,
                binding=ActionBinding("login"),
                session_id=challenge.session_id,
                http_method=http_method,
                now=now,
            )
            return self.transactions.complete_webauthn_login(
                cast(WebAuthnLoginProof, proof),
                now=now,
            )
        except Exception:
            raise WebUnauthorized("invalid credentials") from None


@dataclass(frozen=True)
class LiveBrowserAuth:
    origin: str
    backend: BrowserBackend
    database: Database
    bootstrap_capability: str
    clock: list[int]


def _certificate(tmp_path: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "localhost.pem"
    key_path = tmp_path / "localhost-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _available_port() -> int:
    reservation = socket.socket()
    try:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])
    finally:
        reservation.close()


@contextmanager
def _served_browser_auth(tmp_path: Path) -> Iterator[LiveBrowserAuth]:
    database = Database(tmp_path / "browser-auth-e2e.db")
    database.initialize()
    port = _available_port()
    origin = f"https://localhost:{port}"
    capabilities = ProofCapability(b"browser-e2e-proof-capability-key" * 2)
    signing_key = b"browser-e2e-session-signing-key" * 2
    sessions = SessionManager(SQLiteSessionRepository(database), signing_key=signing_key)
    limiter = SQLiteAttemptLimiter(database)
    secret_store = BrowserSecretStore()
    webauthn_repository = SQLiteWebAuthnRepository(database)
    assertion_provider = BrowserAssertionProvider()
    webauthn_issuer = WebAuthnChallengeIssuer(
        webauthn_repository,
        rp_id="localhost",
        origin=origin,
    )
    webauthn_verifier = WebAuthnAssertionVerifier(
        webauthn_repository,
        rp_id="localhost",
        origin=origin,
        provider=assertion_provider,
        capabilities=capabilities,
        allow_test_provider=True,
    )
    totp = TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        secret_store,
        limiter,
        capabilities=capabilities,
    )
    transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=signing_key,
        capabilities=capabilities,
    )
    backend = BrowserBackend(
        database,
        sessions=sessions,
        passwords=PasswordAuthenticator(
            SQLitePasswordCredentialRepository(database),
            limiter,
            capabilities=capabilities,
            verifier=Argon2PasswordVerifier(),
        ),
        totp=totp,
        webauthn_repository=webauthn_repository,
        webauthn_issuer=webauthn_issuer,
        webauthn_verifier=webauthn_verifier,
        transactions=transactions,
    )
    registrations = PasskeyRegistrationService(
        database,
        rp_id="localhost",
        origin=origin,
        provider=BrowserRegistrationProvider(),
    )
    bootstrap = BootstrapService(database, owner_user_id=USER_ID)
    bootstrap_capability = bootstrap.issue_capability(now=NOW)
    browser_auth = BrowserAuthController(
        bootstrap=bootstrap,
        registrations=registrations,
        manager=AuthenticatorManager(
            database,
            capabilities=capabilities,
            provisioner=secret_store,
        ),
        totp_verifier=totp,
        webauthn_issuer=webauthn_issuer,
        webauthn_verifier=webauthn_verifier,
        webauthn_repository=webauthn_repository,
        totp_enrollments=TotpEnrollmentService(
            database,
            provisioner=secret_store,
            secret_store=secret_store,
        ),
    )
    clock = [NOW]
    app = create_web_app(
        cast(WebBackend, backend),
        settings=WebSettings(public_origin=origin, allowed_hosts=("localhost",)),
        csrf=CsrfManager(b"browser-e2e-csrf-signing-key" * 2),
        browser_auth=browser_auth,
        clock=lambda: clock[0],
    )
    cert_path, key_path = _certificate(tmp_path)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    with httpx.Client(verify=False, trust_env=False, timeout=0.5) as client:
        while time.monotonic() < deadline:
            try:
                if client.get(f"{origin}/healthz").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            pytest.fail("browser auth test server did not start", pytrace=False)
    try:
        yield LiveBrowserAuth(
            origin=origin,
            backend=backend,
            database=database,
            bootstrap_capability=bootstrap_capability,
            clock=clock,
        )
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        if thread.is_alive():
            pytest.fail("browser auth test server did not stop", pytrace=False)


WEBAUTHN_STUB = r"""
(() => {
  const encode = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const decode = (value) => {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/")
      + "===".slice((value.length + 3) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  };
  const bytes = (value) => new TextEncoder().encode(value);
  const clientData = (type, challenge) => bytes(JSON.stringify({
    type,
    challenge: encode(challenge),
    origin: window.location.origin,
    crossOrigin: false,
  })).buffer;
  let next = Number(localStorage.getItem("browser-e2e-next-passkey") || "1");
  window.__selectedPasskey = null;
  Object.defineProperty(navigator, "credentials", {value: {
    create: async ({publicKey}) => {
      if (localStorage.getItem("browser-e2e-cancel-next-create") === "true") {
        localStorage.removeItem("browser-e2e-cancel-next-create");
        throw new DOMException("fake passkey ceremony cancelled", "AbortError");
      }
      const id = `browser-passkey-${next++}`;
      const rawId = bytes(id);
      localStorage.setItem("browser-e2e-next-passkey", String(next));
      localStorage.setItem(`browser-e2e-handle-${encode(rawId)}`, encode(publicKey.user.id));
      const response = {
        clientDataJSON: clientData("webauthn.create", publicKey.challenge),
        attestationObject: bytes("attestation"),
      };
      if (!id.endsWith("2")) {
        response.getTransports = () => ["internal"];
      }
      return {
        id: encode(rawId), rawId, type: "public-key", authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({}),
        response,
      };
    },
    get: async ({publicKey}) => {
      const offered = publicKey.allowCredentials;
      const selected = window.__selectedPasskey
        ? offered.find((item) => encode(item.id) === window.__selectedPasskey)
        : offered[0];
      if (!selected) throw new Error("selected fake passkey was not offered");
      const id = encode(selected.id);
      return {
        id, rawId: selected.id, type: "public-key", authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({}),
        response: {
          clientDataJSON: clientData("webauthn.get", publicKey.challenge),
          authenticatorData: bytes("authenticator-data"),
          signature: bytes("signature"),
          userHandle: decode(localStorage.getItem(`browser-e2e-handle-${id}`)),
        },
      };
    },
  }, configurable: true});
})();
"""


CEREMONY_STORAGE_FAILURE_STUB = r"""
(() => {
  for (const method of ["getItem", "setItem", "removeItem"]) {
    const original = Storage.prototype[method];
    Storage.prototype[method] = function(key, ...args) {
      if (String(key).startsWith("signet-")) {
        throw new DOMException("fake ceremony storage failure", "QuotaExceededError");
      }
      return original.call(this, key, ...args);
    };
  }
})();
"""


def _totp_key(page: Page) -> str:
    qr_code = page.locator("[data-totp-qr]").filter(visible=True)
    expect(qr_code).to_have_attribute("src", re.compile(r"^data:image/svg\+xml"))
    key = page.locator("[data-totp-key]").filter(visible=True).inner_text().strip()
    assert re.fullmatch(r"[A-Z2-7]{32}", key)
    return key


def _enroll_setup_totp(page: Page, label: str) -> str:
    page.locator('[data-totp-start][data-flow="setup"] input[name="label"]').fill(label)
    page.locator('[data-totp-start][data-flow="setup"] button').click()
    page.locator('[data-totp-enrollment] input[name="proof"]').wait_for()
    key = _totp_key(page)
    page.locator('[data-totp-enrollment] input[name="proof"]').fill(pyotp.TOTP(key).at(NOW))
    page.locator("[data-totp-enrollment] button").click()
    expect(page.locator("#passkey p[role=status]")).to_contain_text(label)
    return key


def _enroll_setup_passkey(page: Page, label: str) -> None:
    page.locator("[data-setup-passkey] input[name=label]").fill(label)
    page.locator("[data-setup-passkey] button").click()
    expect(page.locator("#passkey p[role=status]")).to_contain_text(label)


def _login_totp(page: Page, origin: str, key: str) -> None:
    page.goto(f"{origin}/login")
    page.get_by_text("Password and authenticator", exact=True).click()
    form = page.locator('form[action="/login/password"]')
    form.locator('input[name="user_id"]').fill(USER_ID)
    form.locator('input[name="password"]').fill(PASSWORD)
    form.locator('input[name="totp_proof"]').fill(pyotp.TOTP(key).at(NOW))
    form.get_by_role("button", name="Sign in").click()
    expect(page).to_have_url(f"{origin}/")


def _logout(page: Page) -> None:
    page.get_by_role("button", name="Sign out").click()
    expect(page).to_have_url(re.compile(r"/login$"))


def _login_passkey(page: Page, origin: str, credential_id: str) -> None:
    page.goto(f"{origin}/login")
    page.evaluate("value => { window.__selectedPasskey = value; }", credential_id)
    page.locator("[data-passkey-login] input[name=user_id]").fill(USER_ID)
    page.locator("[data-passkey-login] button").click()
    expect(page).to_have_url(f"{origin}/")


def _active_factors(database: Database) -> dict[str, tuple[str, str]]:
    with database.read() as connection:
        rows = connection.execute(
            """
            SELECT label, credential_id, kind FROM auth_factors
            WHERE state = 'active' AND kind IN ('totp', 'webauthn')
            ORDER BY created_at, factor_id
            """
        ).fetchall()
    return {str(row["label"]): (str(row["credential_id"]), str(row["kind"])) for row in rows}


def _remove_with_passkey(page: Page, target: str, credential_id: str) -> None:
    card = page.locator(".authenticator-card").filter(
        has=page.get_by_role("heading", name=target, exact=True)
    )
    card.get_by_text("Remove", exact=True).click()
    page.evaluate("value => { window.__selectedPasskey = value; }", credential_id)
    card.get_by_role("button", name="Confirm removal with passkey").click()


def test_setup_totp_ceremony_resumes_after_reload_without_browser_secret_storage(
    tmp_path: Path,
) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            start = page.locator('[data-totp-start][data-flow="setup"]')
            start.locator('input[name="label"]').fill("Reload-safe TOTP")
            start.get_by_role("button", name="Set up TOTP").click()
            original_key = _totp_key(page)

            page.reload()

            expect(page.locator("[data-totp-enrollment]:not([hidden])")).to_be_visible()
            assert _totp_key(page) == original_key
            stored = page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
            assert original_key not in json.dumps(stored)
            assert "otpauth://" not in json.dumps(stored)
        finally:
            context.close()
            browser.close()


def test_setup_totp_continues_when_ceremony_storage_is_unavailable(
    tmp_path: Path,
) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        context.add_init_script(CEREMONY_STORAGE_FAILURE_STUB)
        page = context.new_page()
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            start = page.locator('[data-totp-start][data-flow="setup"]')
            start.locator('input[name="label"]').fill("Non-resumable TOTP")
            start.get_by_role("button", name="Set up TOTP").click()

            key = _totp_key(page)
            page.locator('[data-totp-enrollment] input[name="proof"]').fill(pyotp.TOTP(key).at(NOW))
            page.locator("[data-totp-enrollment] button").click()

            expect(page.get_by_text("Added: Non-resumable TOTP")).to_be_visible()
        finally:
            context.close()
            browser.close()


def test_setup_totp_resume_handle_survives_retryable_rate_limit(tmp_path: Path) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            start = page.locator('[data-totp-start][data-flow="setup"]')
            start.locator('input[name="label"]').fill("Rate-limited TOTP")
            start.get_by_role("button", name="Set up TOTP").click()
            original_key = _totp_key(page)

            page.route(
                "**/setup/totp/resume",
                lambda route: route.fulfill(
                    status=429,
                    headers={"Retry-After": "1"},
                    content_type="application/json",
                    body='{"error":{"message":"Please retry."}}',
                ),
            )
            page.reload()

            expect(page.locator("[data-auth-status]")).to_contain_text("Please retry")
            assert page.evaluate("() => localStorage.getItem('signet-setup-ceremony-v1')")

            page.unroute("**/setup/totp/resume")
            page.reload()
            assert _totp_key(page) == original_key
        finally:
            context.close()
            browser.close()


def test_setup_totp_completion_preserves_concurrent_passkey_resume_handle(tmp_path: Path) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        totp_page = context.new_page()
        try:
            totp_page.goto(f"{live.origin}/setup")
            totp_page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            totp_page.get_by_role("button", name="Unlock owner setup").click()
            start = totp_page.locator('[data-totp-start][data-flow="setup"]')
            start.locator('input[name="label"]').fill("Concurrent TOTP")
            start.get_by_role("button", name="Set up TOTP").click()
            totp_key = _totp_key(totp_page)

            passkey_state = totp_page.evaluate(
                """async () => {
                  const response = await fetch('/setup/passkeys/options', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({label: 'Concurrent passkey'}),
                  });
                  if (!response.ok) throw new Error(`options failed: ${response.status}`);
                  const issued = await response.json();
                  const state = {kind: 'passkey', challenge_id: issued.challenge_id};
                  localStorage.setItem('signet-setup-ceremony-v1', JSON.stringify(state));
                  return state;
                }"""
            )
            assert passkey_state["kind"] == "passkey"

            totp_page.route(
                "**/setup/passkeys/resume",
                lambda route: route.fulfill(
                    status=429,
                    headers={"Retry-After": "1"},
                    content_type="application/json",
                    body='{"error":{"message":"Please retry."}}',
                ),
            )
            totp_page.locator('[data-totp-enrollment] input[name="proof"]').fill(
                pyotp.TOTP(totp_key).at(NOW)
            )
            totp_page.locator("[data-totp-enrollment] button").click()

            expect(totp_page.get_by_text("Added: Concurrent TOTP")).to_be_visible()
            assert (
                totp_page.evaluate(
                    "() => JSON.parse(localStorage.getItem('signet-setup-ceremony-v1'))"
                )
                == passkey_state
            )
        finally:
            context.close()
            browser.close()


def test_setup_totp_resume_treats_verified_response_loss_as_success(tmp_path: Path) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            start = page.locator('[data-totp-start][data-flow="setup"]')
            start.locator('input[name="label"]').fill("Response-loss TOTP")
            start.get_by_role("button", name="Set up TOTP").click()
            key = _totp_key(page)

            def drop_completed_response(route: Any) -> None:
                assert route.fetch().ok
                route.abort()

            page.route("**/setup/totp/verify", drop_completed_response)
            page.locator('[data-totp-enrollment] input[name="proof"]').fill(pyotp.TOTP(key).at(NOW))
            page.locator("[data-totp-enrollment] button").click()

            expect(page.locator("[data-auth-status]")).to_contain_text("Failed to fetch")
            assert page.evaluate("() => localStorage.getItem('signet-setup-ceremony-v1')")

            page.unroute("**/setup/totp/verify")
            page.reload()
            expect(page.locator("[data-auth-status]")).to_contain_text("Setup TOTP already added")
            expect(page.get_by_text("Added: Response-loss TOTP")).to_be_visible()
            assert page.evaluate("() => localStorage.getItem('signet-setup-ceremony-v1')") is None
        finally:
            context.close()
            browser.close()


def test_setup_passkey_ceremony_resumes_after_reload(
    tmp_path: Path,
) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        context.add_init_script(WEBAUTHN_STUB)
        page = context.new_page()
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            page.get_by_label("Passkey name").fill("Reload-safe passkey")
            page.evaluate("() => localStorage.setItem('browser-e2e-cancel-next-create', 'true')")
            page.get_by_role("button", name="Create passkey").click()
            expect(page.locator("[data-auth-status]")).to_contain_text("cancelled")
            state = page.evaluate(
                "() => JSON.parse(localStorage.getItem('signet-setup-ceremony-v1'))"
            )
            assert isinstance(state, dict)
            assert set(state) == {"kind", "challenge_id"}
            assert state["kind"] == "passkey"

            page.reload()

            expect(page.get_by_text("Added: Reload-safe passkey")).to_be_visible()
            assert page.evaluate("() => localStorage.getItem('signet-setup-ceremony-v1')") is None
        finally:
            context.close()
            browser.close()


def test_setup_passkey_resume_treats_verified_response_loss_as_success(tmp_path: Path) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        context.add_init_script(WEBAUTHN_STUB)
        page = context.new_page()
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            page.get_by_label("Passkey name").fill("Response-loss passkey")

            def drop_completed_response(route: Any) -> None:
                assert route.fetch().ok
                route.abort()

            page.route("**/setup/passkeys/complete", drop_completed_response)
            page.get_by_role("button", name="Create passkey").click()

            expect(page.locator("[data-auth-status]")).to_contain_text("Failed to fetch")
            assert page.evaluate("() => localStorage.getItem('signet-setup-ceremony-v1')")

            page.unroute("**/setup/passkeys/complete")
            page.reload()
            expect(page.locator("[data-auth-status]")).to_contain_text(
                "Setup passkey already added"
            )
            expect(page.get_by_text("Added: Response-loss passkey")).to_be_visible()
            assert page.evaluate("() => localStorage.getItem('signet-setup-ceremony-v1')") is None
        finally:
            context.close()
            browser.close()


def test_totp_only_management_is_accessible_and_resumes_without_provider_effects(
    tmp_path: Path,
) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        context.add_init_script(WEBAUTHN_STUB)
        page = context.new_page()
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            page.get_by_label("Password", exact=True).fill(PASSWORD)
            page.get_by_label("Confirm password").fill(PASSWORD)
            page.get_by_role("button", name="Save password").click()
            primary = _enroll_setup_totp(page, "Primary TOTP")
            page.get_by_role("button", name="Finish setup").click()
            _login_totp(page, live.origin, primary)
            page.goto(f"{live.origin}/authenticators")

            form = page.locator('[data-totp-start][data-flow="management"]')
            proof_details = form.locator("details")
            expect(proof_details).to_have_attribute("open", "")
            expect(
                form.get_by_label("Current code from the existing authenticator")
            ).to_be_visible()
            form.get_by_label("Authenticator name").fill("Secondary TOTP")
            invalid = "111111" if pyotp.TOTP(primary).at(NOW) == "000000" else "000000"
            proof_input = form.get_by_label("Current code from the existing authenticator")
            proof_input.fill(invalid)
            proof_input.press("Enter")

            status = page.locator("[data-auth-status]")
            expect(status).to_contain_text("invalid")
            expect(status).to_have_attribute("role", "alert")
            expect(status).to_be_focused()
            assert set(_active_factors(live.database)) == {"Primary TOTP"}

            live.clock[0] += 30
            form.get_by_label("Current code from the existing authenticator").fill(
                pyotp.TOTP(primary).at(live.clock[0])
            )
            form.get_by_role("button", name="Set up TOTP").click()
            secondary = _totp_key(page)
            with page.expect_response("**/authenticators/enroll/resume") as resumed:
                page.reload()
            assert resumed.value.status == 200, resumed.value.text()
            assert _totp_key(page) == secondary

            def drop_finalization_response(route: Any) -> None:
                assert route.fetch().ok
                route.abort()

            page.route("**/authenticators/enroll/finalize", drop_finalization_response)
            page.locator('[data-totp-verify][data-flow="management"] input[name="proof"]').fill(
                pyotp.TOTP(secondary).at(live.clock[0])
            )
            page.get_by_role("button", name="Verify new TOTP").click()
            expect(page.locator("[data-auth-status]")).to_contain_text("Failed")
            assert set(_active_factors(live.database)) == {"Primary TOTP", "Secondary TOTP"}
            page.unroute("**/authenticators/enroll/finalize")
            page.reload()
            expect(page.get_by_role("heading", name="Session expired")).to_be_visible()
            _login_totp(page, live.origin, secondary)
            with page.expect_response("**/authenticators/enroll/status") as recovered:
                page.goto(f"{live.origin}/authenticators")
            assert recovered.value.status == 200, recovered.value.text()
            assert recovered.value.json()["status"] == "completed"
            expect(page.locator("[data-auth-status]")).to_contain_text("already added")
            assert (
                page.evaluate("() => localStorage.getItem('signet-management-ceremony-v1')") is None
            )

            page.goto(f"{live.origin}/authenticators")
            live.clock[0] += 30
            passkey_form = page.locator("[data-add-passkey]")
            passkey_form.get_by_label("Passkey name").fill("Reload-safe managed passkey")
            passkey_form.get_by_label("Existing TOTP authenticator").select_option(
                label="Secondary TOTP"
            )
            passkey_form.get_by_label("Current code").fill(pyotp.TOTP(secondary).at(live.clock[0]))
            page.evaluate("() => localStorage.setItem('browser-e2e-cancel-next-create', 'true')")
            passkey_form.get_by_role("button", name="Create new passkey").click()
            expect(page.locator("[data-auth-status]")).to_contain_text("cancelled")

            page.route("**/authenticators/enroll/finalize", lambda route: route.abort())
            with page.expect_response("**/authenticators/enroll/resume") as resumed_passkey:
                page.reload()
            assert resumed_passkey.value.status == 200, resumed_passkey.value.text()
            expect(page.locator("[data-auth-status]")).to_contain_text("Failed")
            page.unroute("**/authenticators/enroll/finalize")
            with page.expect_response("**/authenticators/enroll/resume") as finalized_passkey:
                page.reload()
            assert finalized_passkey.value.status == 200, finalized_passkey.value.text()

            expect(page).to_have_url(re.compile(r"/login\?authenticators=updated$"))
            assert set(_active_factors(live.database)) == {
                "Primary TOTP",
                "Secondary TOTP",
                "Reload-safe managed passkey",
            }
        finally:
            context.close()
            browser.close()


def test_browser_bootstrap_multiple_authenticators_replacement_and_safe_removal(
    tmp_path: Path,
) -> None:
    with _served_browser_auth(tmp_path) as live, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        context.add_init_script(WEBAUTHN_STUB)
        page = context.new_page()
        external_requests: list[str] = []
        page.on(
            "request",
            lambda request: (
                external_requests.append(request.url)
                if not request.url.startswith(live.origin)
                else None
            ),
        )
        try:
            page.goto(f"{live.origin}/setup")
            page.get_by_label("One-time bootstrap capability").fill(live.bootstrap_capability)
            page.get_by_role("button", name="Unlock owner setup").click()
            page.get_by_label("Password", exact=True).fill(PASSWORD)
            page.get_by_label("Confirm password").fill(PASSWORD)
            page.get_by_role("button", name="Save password").click()
            first_totp = _enroll_setup_totp(page, "Primary TOTP")
            second_totp = _enroll_setup_totp(page, "Travel TOTP")
            _enroll_setup_passkey(page, "Laptop passkey")
            _enroll_setup_passkey(page, "Phone passkey")
            expect(page.get_by_role("button", name="Finish setup")).to_be_enabled()
            page.get_by_role("button", name="Finish setup").click()
            expect(page).to_have_url(re.compile(r"/login\?setup=complete$"))

            factors = _active_factors(live.database)
            assert set(factors) == {
                "Primary TOTP",
                "Travel TOTP",
                "Laptop passkey",
                "Phone passkey",
            }
            assert first_totp != second_totp
            assert factors["Laptop passkey"][0] != factors["Phone passkey"][0]
            with live.database.read() as connection:
                chrome_style_transports = connection.execute(
                    "SELECT transports_json FROM auth_credentials WHERE credential_id = ?",
                    (factors["Laptop passkey"][0],),
                ).fetchone()["transports_json"]
                safari_style_transports = connection.execute(
                    "SELECT transports_json FROM auth_credentials WHERE credential_id = ?",
                    (factors["Phone passkey"][0],),
                ).fetchone()["transports_json"]
            assert chrome_style_transports == '["internal"]'
            assert safari_style_transports == "[]"

            _login_totp(page, live.origin, first_totp)
            _logout(page)
            _login_totp(page, live.origin, second_totp)
            _logout(page)
            _login_passkey(page, live.origin, factors["Laptop passkey"][0])
            _logout(page)
            _login_passkey(page, live.origin, factors["Phone passkey"][0])

            page.goto(f"{live.origin}/authenticators")
            page.locator('[data-totp-start][data-flow="management"] input[name="label"]').fill(
                "Replacement TOTP"
            )
            page.locator('[data-totp-start][data-flow="management"] button').click()
            replacement = _totp_key(page)
            page.locator('[data-totp-enrollment] input[name="proof"]').fill(
                pyotp.TOTP(replacement).at(NOW)
            )
            page.locator("[data-totp-enrollment] button").click()
            expect(page).to_have_url(re.compile(r"/login\?authenticators=updated$"))
            _login_totp(page, live.origin, replacement)

            laptop_id = factors["Laptop passkey"][0]
            phone_id = factors["Phone passkey"][0]
            _logout(page)
            for removable_label in (
                "Primary TOTP",
                "Travel TOTP",
                "Replacement TOTP",
                "Phone passkey",
            ):
                _login_passkey(page, live.origin, phone_id)
                page.goto(f"{live.origin}/authenticators")
                _remove_with_passkey(page, removable_label, laptop_id)
                expect(page).to_have_url(re.compile(r"/login\?authenticators=updated$"))

            _login_passkey(page, live.origin, laptop_id)
            page.goto(f"{live.origin}/authenticators")
            _remove_with_passkey(page, "Laptop passkey", laptop_id)
            expect(page.locator("body")).to_contain_text("final active authenticator")
            assert set(_active_factors(live.database)) == {"Laptop passkey"}
            assert external_requests == []
        finally:
            context.close()
            browser.close()

(() => {
  "use strict";

  const encode = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const decode = (value) => {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  };

  const creationOptions = (value) => ({
    ...value,
    challenge: decode(value.challenge),
    user: {...value.user, id: decode(value.user.id)},
    excludeCredentials: (value.excludeCredentials || []).map((item) => ({...item, id: decode(item.id)})),
  });

  const requestOptions = (value) => ({
    ...value,
    challenge: decode(value.challenge),
    allowCredentials: (value.allowCredentials || []).map((item) => ({...item, id: decode(item.id)})),
  });

  const registrationJSON = (credential) => ({
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encode(credential.response.clientDataJSON),
      attestationObject: encode(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
  });

  const assertionJSON = (credential) => ({
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encode(credential.response.clientDataJSON),
      authenticatorData: encode(credential.response.authenticatorData),
      signature: encode(credential.response.signature),
      userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
    },
  });

  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const announce = (message, failed = false) => {
    const region = document.querySelector("[data-auth-status]");
    if (!region) return;
    region.textContent = message;
    region.dataset.failed = failed ? "true" : "false";
  };

  const post = async (url, payload) => {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf(), "Accept": "application/json"},
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error?.message || "Authenticator request failed.");
    return body;
  };

  const register = async (optionsURL, completeURL, label) => {
    const issued = await post(optionsURL, {label});
    const credential = await navigator.credentials.create({publicKey: creationOptions(issued.publicKey)});
    if (!credential) throw new Error("Passkey creation was cancelled.");
    return post(completeURL, {challenge_id: issued.challenge_id, credential: registrationJSON(credential)});
  };

  const confirmWithPasskey = async (intent) => {
    const issued = await post("/authenticators/confirm/passkey/options", intent);
    const credential = await navigator.credentials.get({publicKey: requestOptions(issued.publicKey)});
    if (!credential) throw new Error("Passkey confirmation was cancelled.");
    return post("/authenticators/confirm/passkey/complete", {
      ...intent,
      challenge_id: issued.challenge_id,
      assertion: assertionJSON(credential),
    });
  };

  document.querySelector("[data-setup-passkey]")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button");
    button.disabled = true;
    announce("Waiting for your browser to create the passkey.");
    try {
      await register("/setup/passkeys/options", "/setup/passkeys/complete", new FormData(form).get("label"));
      announce("Passkey added. Reloading setup review.");
      window.location.hash = "review";
      window.location.reload();
    } catch (error) {
      announce(error.message || "Passkey setup failed.", true);
      button.disabled = false;
    }
  });

  document.querySelector("[data-add-passkey]")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button");
    button.disabled = true;
    announce("Waiting for your browser to create the new passkey.");
    try {
      const pending = await register(
        "/authenticators/passkeys/options",
        "/authenticators/passkeys/complete",
        new FormData(form).get("label"),
      );
      const intent = {action: "add_passkey", operation_id: pending.operation_id, registration_id: pending.registration_id};
      const panel = document.querySelector("[data-pending-passkey]");
      panel.hidden = false;
      panel.querySelectorAll('[data-intent-field]').forEach((field) => { field.value = intent[field.name] || ""; });
      const passkeyButton = panel.querySelector("[data-confirm-new-passkey]");
      passkeyButton.dataset.intent = JSON.stringify(intent);
      announce("New passkey created. Confirm this exact addition with an existing authenticator.");
    } catch (error) {
      announce(error.message || "Passkey setup failed.", true);
      button.disabled = false;
    }
  });

  document.querySelectorAll("[data-totp-start]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      const flow = form.dataset.flow;
      button.disabled = true;
      announce("Creating a one-time TOTP enrollment.");
      try {
        const issued = await post(
          flow === "setup" ? "/setup/totp/start" : "/authenticators/totp/start",
          {label: new FormData(form).get("label")},
        );
        const panel = form.parentElement.querySelector("[data-totp-enrollment]");
        panel.hidden = false;
        panel.dataset.enrollmentId = issued.enrollment_id;
        const qrCode = panel.querySelector("[data-totp-qr]");
        qrCode.src = issued.qr_code_data_uri;
        qrCode.hidden = false;
        panel.querySelector("[data-totp-key]").textContent = issued.manual_key;
        announce("TOTP key ready. Enter the current code from the new authenticator.");
      } catch (error) {
        announce(error.message || "TOTP setup failed.", true);
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-totp-verify]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      const flow = form.dataset.flow;
      const panel = form.closest("[data-totp-enrollment]");
      button.disabled = true;
      announce("Verifying the new TOTP authenticator.");
      try {
        const pending = await post(
          flow === "setup" ? "/setup/totp/verify" : "/authenticators/totp/verify",
          {enrollment_id: panel.dataset.enrollmentId, proof: new FormData(form).get("proof")},
        );
        const qrCode = panel.querySelector("[data-totp-qr]");
        qrCode.removeAttribute("src");
        qrCode.hidden = true;
        panel.querySelector("[data-totp-key]").textContent = "";
        if (flow === "setup") {
          announce("TOTP added. Reloading setup review.");
          window.location.hash = "review";
          window.location.reload();
          return;
        }
        panel.hidden = true;
        const intent = {action: "add_totp", operation_id: pending.operation_id, registration_id: pending.registration_id};
        const confirmation = document.querySelector("[data-pending-totp]");
        confirmation.hidden = false;
        confirmation.querySelectorAll('[data-intent-field]').forEach((field) => { field.value = intent[field.name] || ""; });
        confirmation.querySelector("[data-confirm-new-totp]").dataset.intent = JSON.stringify(intent);
        announce("New TOTP verified. Confirm this exact addition with an existing authenticator.");
      } catch (error) {
        announce(error.message || "TOTP verification failed.", true);
        button.disabled = false;
      }
    });
  });

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-passkey-intent]");
    const pendingButton = event.target.closest("[data-confirm-new-passkey]");
    const pendingTotpButton = event.target.closest("[data-confirm-new-totp]");
    if (!button && !pendingButton && !pendingTotpButton) return;
    const selected = button || pendingButton || pendingTotpButton;
    selected.disabled = true;
    announce("Waiting for confirmation from your existing passkey.");
    try {
      const intent = JSON.parse(selected.dataset.intent);
      if (intent.action === "rename") {
        intent.label = selected.closest("details")?.querySelector("[data-factor-label]")?.value || intent.label;
      }
      const result = await confirmWithPasskey(intent);
      announce("Authenticator updated. Returning to sign in.");
      window.location.assign(result.redirect_url);
    } catch (error) {
      announce(error.message || "Passkey confirmation failed.", true);
      selected.disabled = false;
    }
  });
})();

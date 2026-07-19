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
    region.setAttribute("role", failed ? "alert" : "status");
    region.setAttribute("aria-live", failed ? "assertive" : "polite");
    if (failed) region.focus();
  };

  const post = async (url, payload) => {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf(), "Accept": "application/json"},
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(body.error?.message || "Authenticator request failed.");
      error.discardCeremony =
        response.status >= 400 && response.status < 500 && response.status !== 429;
      throw error;
    }
    return body;
  };

  const completeSetupPasskey = async (issued) => {
    const credential = await navigator.credentials.create({publicKey: creationOptions(issued.publicKey)});
    if (!credential) throw new Error("Passkey creation was cancelled.");
    return post("/setup/passkeys/complete", {
      challenge_id: issued.challenge_id,
      credential: registrationJSON(credential),
    });
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

  const operationId = () => `browser-operation-${crypto.randomUUID()}`;
  const setupCeremonyKey = "signet-setup-ceremony-v1";
  const managementCeremonyKey = "signet-management-ceremony-v1";

  const persistCeremony = (key, value) => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (_) {
      // Ceremony persistence is optional; the active request can still complete safely.
    }
  };

  const sameCeremony = (current, expected) => {
    if (!current || current.kind !== expected.kind) return false;
    if (expected.kind === "passkey") return current.challenge_id === expected.challenge_id;
    if (expected.kind === "totp") return current.enrollment_id === expected.enrollment_id;
    return false;
  };

  const discardCeremony = (key, expected = null) => {
    try {
      if (expected) {
        const current = JSON.parse(localStorage.getItem(key) || "null");
        if (!sameCeremony(current, expected)) return;
      }
      localStorage.removeItem(key);
    } catch (_) {
      // Unavailable storage cannot retain a usable resume handle.
    }
  };

  const rememberSetupTotp = (enrollmentId) => {
    persistCeremony(setupCeremonyKey, {kind: "totp", enrollment_id: enrollmentId});
  };

  const rememberSetupPasskey = (challengeId) => {
    persistCeremony(setupCeremonyKey, {kind: "passkey", challenge_id: challengeId});
  };

  const clearSetupCeremony = (expected = null) => discardCeremony(setupCeremonyKey, expected);

  const rememberManagementTotp = (enrollmentId) => {
    persistCeremony(managementCeremonyKey, {kind: "totp", enrollment_id: enrollmentId});
  };

  const rememberManagementPasskey = (challengeId) => {
    persistCeremony(managementCeremonyKey, {kind: "passkey", challenge_id: challengeId});
  };

  const clearManagementCeremony = (expected = null) => discardCeremony(managementCeremonyKey, expected);

  const showTotpEnrollment = (form, issued) => {
    const panel = form.parentElement.querySelector("[data-totp-enrollment]");
    const startButton = form.querySelector('button[type="submit"]');
    if (startButton) startButton.disabled = true;
    panel.hidden = false;
    panel.dataset.enrollmentId = issued.enrollment_id;
    panel.dataset.authorizationId = issued.authorization_id || "";
    panel.dataset.operationId = issued.operation_id || "";
    const qrCode = panel.querySelector("[data-totp-qr]");
    qrCode.src = issued.qr_code_data_uri;
    qrCode.hidden = false;
    panel.querySelector("[data-totp-key]").textContent = issued.manual_key;
    return panel;
  };

  const authorizeEnrollment = async (intent, form) => {
    const data = new FormData(form);
    const proof = String(data.get("totp_proof") || "").trim();
    if (proof) {
      return post("/authenticators/enroll/totp", {
        ...intent,
        totp_proof: proof,
        totp_credential_id: data.get("totp_credential_id") || null,
      });
    }
    return confirmWithPasskey(intent);
  };

  const completePasskeyEnrollment = async (issued) => {
    if (issued.kind !== "passkey") throw new Error("Passkey enrollment authorization was invalid.");
    const credential = await navigator.credentials.create({publicKey: creationOptions(issued.publicKey)});
    if (!credential) throw new Error("Passkey creation was cancelled.");
    return post("/authenticators/passkeys/complete", {
      challenge_id: issued.challenge_id,
      credential: registrationJSON(credential),
    });
  };

  const finalizeEnrollment = (action, pending) => post("/authenticators/enroll/finalize", {
    action,
    operation_id: pending.operation_id,
    registration_id: pending.registration_id,
    authorization_id: pending.authorization_id,
  });

  document.querySelector("[data-setup-passkey]")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button");
    button.disabled = true;
    announce("Waiting for your browser to create the passkey.");
    try {
      const issued = await post("/setup/passkeys/options", {label: new FormData(form).get("label")});
      rememberSetupPasskey(issued.challenge_id);
      await completeSetupPasskey(issued);
      clearSetupCeremony({kind: "passkey", challenge_id: issued.challenge_id});
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
    announce("Confirm with an existing authenticator before creating the new passkey.");
    try {
      const intent = {
        action: "add_passkey",
        label: new FormData(form).get("label"),
        operation_id: operationId(),
      };
      const issued = await authorizeEnrollment(intent, form);
      rememberManagementPasskey(issued.challenge_id);
      announce("Authorization accepted. Waiting for your browser to create the new passkey.");
      const pending = await completePasskeyEnrollment(issued);
      const result = await finalizeEnrollment("add_passkey", pending);
      clearManagementCeremony({kind: "passkey", challenge_id: issued.challenge_id});
      announce("Passkey added. Returning to sign in.");
      window.location.assign(result.redirect_url);
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
      announce(flow === "setup" ? "Creating a one-time TOTP enrollment." : "Confirm with an existing authenticator before creating the TOTP secret.");
      try {
        const label = new FormData(form).get("label");
        const issued = flow === "setup"
          ? await post("/setup/totp/start", {label})
          : await authorizeEnrollment({action: "add_totp", label, operation_id: operationId()}, form);
        if (flow !== "setup" && issued.kind !== "totp") throw new Error("TOTP enrollment authorization was invalid.");
        if (flow === "setup") rememberSetupTotp(issued.enrollment_id);
        else rememberManagementTotp(issued.enrollment_id);
        showTotpEnrollment(form, issued);
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
          clearSetupCeremony({kind: "totp", enrollment_id: panel.dataset.enrollmentId});
          announce("TOTP added. Reloading setup review.");
          window.location.hash = "review";
          window.location.reload();
          return;
        }
        panel.hidden = true;
        if (pending.authorization_id !== panel.dataset.authorizationId || pending.operation_id !== panel.dataset.operationId) {
          throw new Error("TOTP enrollment authorization changed unexpectedly.");
        }
        const result = await finalizeEnrollment("add_totp", pending);
        clearManagementCeremony({kind: "totp", enrollment_id: panel.dataset.enrollmentId});
        announce("TOTP added. Returning to sign in.");
        window.location.assign(result.redirect_url);
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

  const resumeSetupCeremony = async () => {
    if (window.location.pathname !== "/setup") return;
    let state;
    try {
      state = JSON.parse(localStorage.getItem(setupCeremonyKey) || "null");
    } catch (_) {
      clearSetupCeremony();
      return;
    }
    if (!state || typeof state !== "object") return;
    if (state.kind === "passkey") {
      if (typeof state.challenge_id !== "string") {
        clearSetupCeremony();
        return;
      }
      try {
        const issued = await post("/setup/passkeys/resume", {challenge_id: state.challenge_id});
        if (issued.status === "registered") {
          clearSetupCeremony(state);
          announce("Setup passkey already added.");
          return;
        }
        announce("Passkey setup resumed. Waiting for your browser.");
        await completeSetupPasskey(issued);
        clearSetupCeremony(state);
        announce("Passkey added. Reloading setup review.");
        window.location.hash = "review";
        window.location.reload();
      } catch (error) {
        if (error.discardCeremony) clearSetupCeremony(state);
        announce(error.message || "The saved passkey setup can no longer be resumed.", true);
      }
      return;
    }
    if (state.kind !== "totp" || typeof state.enrollment_id !== "string") return;
    const form = document.querySelector('[data-totp-start][data-flow="setup"]');
    if (!form) {
      clearSetupCeremony();
      return;
    }
    try {
      const issued = await post("/setup/totp/resume", {enrollment_id: state.enrollment_id});
      if (issued.status === "registered") {
        clearSetupCeremony(state);
        announce("Setup TOTP already added.");
        return;
      }
      showTotpEnrollment(form, issued);
      announce("TOTP setup resumed. Enter the current code from the new authenticator.");
    } catch (error) {
      if (error.discardCeremony) clearSetupCeremony(state);
      announce(error.message || "The saved TOTP setup can no longer be resumed.", true);
    }
  };

  const resumeManagementCeremony = async () => {
    if (window.location.pathname !== "/authenticators") return;
    let state;
    try {
      state = JSON.parse(localStorage.getItem(managementCeremonyKey) || "null");
    } catch (_) {
      clearManagementCeremony();
      return;
    }
    if (!state || typeof state !== "object") return;
    const registrationId =
      state.kind === "passkey"
        ? state.challenge_id
        : state.kind === "totp"
          ? state.enrollment_id
          : null;
    if (typeof registrationId !== "string") {
      clearManagementCeremony();
      return;
    }
    try {
      const enrollment = await post("/authenticators/enroll/status", {
        kind: state.kind,
        registration_id: registrationId,
      });
      if (enrollment.status === "completed") {
        clearManagementCeremony(state);
        announce("Authenticator already added.");
        return;
      }
    } catch (error) {
      if (error.discardCeremony) clearManagementCeremony(state);
      announce(error.message || "Authenticator enrollment status is unavailable.", true);
      return;
    }
    if (state.kind === "passkey") {
      if (typeof state.challenge_id !== "string") {
        clearManagementCeremony();
        return;
      }
      try {
        const issued = await post("/authenticators/enroll/resume", {
          kind: "passkey",
          challenge_id: state.challenge_id,
        });
        if (issued.status === "ready_to_finalize") {
          const result = await finalizeEnrollment("add_passkey", issued);
          clearManagementCeremony(state);
          announce("Passkey added. Returning to sign in.");
          window.location.assign(result.redirect_url);
          return;
        }
        announce("Passkey setup resumed. Waiting for your browser.");
        const pending = await completePasskeyEnrollment(issued);
        const result = await finalizeEnrollment("add_passkey", pending);
        clearManagementCeremony(state);
        announce("Passkey added. Returning to sign in.");
        window.location.assign(result.redirect_url);
      } catch (error) {
        if (error.discardCeremony) clearManagementCeremony(state);
        announce(error.message || "The saved passkey setup can no longer be resumed.", true);
      }
      return;
    }
    if (state.kind !== "totp" || typeof state.enrollment_id !== "string") return;
    const form = document.querySelector('[data-totp-start][data-flow="management"]');
    if (!form) {
      clearManagementCeremony();
      return;
    }
    try {
      const issued = await post("/authenticators/enroll/resume", {
        kind: "totp",
        enrollment_id: state.enrollment_id,
      });
      if (issued.status === "ready_to_finalize") {
        const result = await finalizeEnrollment("add_totp", issued);
        clearManagementCeremony(state);
        announce("TOTP added. Returning to sign in.");
        window.location.assign(result.redirect_url);
        return;
      }
      showTotpEnrollment(form, issued);
      announce("TOTP setup resumed. Enter the current code from the new authenticator.");
    } catch (error) {
      if (error.discardCeremony) clearManagementCeremony(state);
      announce(error.message || "The saved TOTP setup can no longer be resumed.", true);
    }
  };

  void resumeSetupCeremony();
  void resumeManagementCeremony();
})();

"use strict";

document.documentElement.classList.replace("no-js", "js");

const toast = document.querySelector(".toast");

function showMessage(message) {
  if (!toast) return;
  toast.textContent = message;
  toast.hidden = false;
}

function decodeBase64url(value) {
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const binary = atob((value + padding).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function preparePublicKey(publicKey) {
  const prepared = { ...publicKey, challenge: decodeBase64url(publicKey.challenge) };
  if (Array.isArray(publicKey.allowCredentials)) {
    prepared.allowCredentials = publicKey.allowCredentials.map((item) => ({
      ...item,
      id: decodeBase64url(item.id)
    }));
  }
  return prepared;
}

function assertionJson(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encodeBase64url(credential.response.authenticatorData),
      clientDataJSON: encodeBase64url(credential.response.clientDataJSON),
      signature: encodeBase64url(credential.response.signature),
      userHandle: credential.response.userHandle ? encodeBase64url(credential.response.userHandle) : null
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

function isDecisionAction(action) {
  return action === "approve" || action === "deny";
}

function selectedDecisionReason(root, action) {
  if (action === "approve" && root.dataset.gatewayInternal !== "true") {
    return root.querySelector("[data-approval-reason]")?.value || "";
  }
  if (action === "deny") return root.querySelector("[data-denial-reason]")?.value || "";
  return "";
}

function decisionReasonRequired(root, action) {
  if (action === "deny") return true;
  return action === "approve" && root.dataset.gatewayInternal !== "true";
}

async function postJson(url, body, csrf) {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body)
  });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value?.error?.message || "Request failed");
  return value;
}

const login = document.querySelector("[data-passkey-login]");
if (login) {
  login.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const csrf = login.dataset.csrf;
      const userId = login.elements.user_id.value;
      const options = await postJson("/login/passkey/options", { user_id: userId }, csrf);
      const credential = await navigator.credentials.get({ publicKey: preparePublicKey(options.public_key) });
      await postJson("/login/passkey/complete", {
        challenge_id: options.challenge_id,
        assertion: assertionJson(credential)
      }, csrf);
      window.location.assign("/");
    } catch (error) {
      showMessage(error.message);
    }
  });
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest?.("[data-passkey-action]");
  if (!button) return;
  const root = button.closest("[data-request-id]");
  try {
    if (!root) throw new Error("Request context is unavailable");
    const action = button.dataset.passkeyAction;
    const requestId = root.dataset.requestId;
    const payloadHash = root.querySelector("input[name='expected_payload_hash']")?.value;
    const expectedVersion = Number(root.querySelector("input[name='expected_version']")?.value);
    const editArguments = action === "edit" ? root.querySelector("[data-edit-json]")?.value : null;
    const decisionNote = selectedDecisionReason(root, action) || null;
    if (decisionReasonRequired(root, action) && !decisionNote) {
      throw new Error("Choose a reason before approving or denying");
    }
    if (!payloadHash || !Number.isInteger(expectedVersion)) {
      throw new Error("Request binding is unavailable");
    }
    const options = await postJson(`/requests/${requestId}/actions/passkey/options`, {
      action,
      expected_version: expectedVersion,
      expected_payload_hash: payloadHash,
      prospective_arguments_json: editArguments,
      decision_note: decisionNote
    }, root.dataset.csrf);
    const credential = await navigator.credentials.get({ publicKey: preparePublicKey(options.public_key) });
    const completed = await postJson(`/requests/${requestId}/actions/passkey/complete`, {
      challenge_id: options.challenge_id,
      assertion: assertionJson(credential)
    }, root.dataset.csrf);
    window.location.assign(completed.redirect_url || `/requests/${requestId}`);
  } catch (error) {
    showMessage(error.message);
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest?.("[data-decision-form]");
  if (!form) return;
  const root = form.closest("[data-request-id]");
  const action = event.submitter?.value;
  if (!root) return;
  const selectedReason = selectedDecisionReason(root, action);
  if (decisionReasonRequired(root, action) && !selectedReason) {
    event.preventDefault();
    showMessage("Choose a reason before approving or denying");
    root.querySelector(action === "approve" ? "[data-approval-reason]" : "[data-denial-reason]")?.focus();
    return;
  }
});

document.querySelectorAll(".request-expander").forEach((expander) => {
  expander.addEventListener("toggle", async () => {
    const fragment = expander.querySelector("[data-review-fragment]");
    if (!expander.open || !fragment || fragment.dataset.reviewLoaded === "true") return;
    const loading = fragment.querySelector(".review-loading");
    const fallback = fragment.querySelector(".review-fallback");
    const historical = fragment.dataset.reviewUrl?.startsWith("/audit/events/");
    if (loading) {
      loading.textContent = historical ? "Loading exact event context" : "Loading request context";
    }
    fallback?.classList.remove("review-fallback-visible");
    fragment.setAttribute("aria-busy", "true");
    try {
      const response = await fetch(fragment.dataset.reviewUrl, {
        credentials: "same-origin",
        headers: { "Accept": "text/html" }
      });
      if (!response.ok) throw new Error("Request context could not be loaded");
      fragment.innerHTML = await response.text();
      fragment.dataset.reviewLoaded = "true";
    } catch (error) {
      if (loading) loading.textContent = "Request context could not be loaded. Close and reopen to retry.";
      fallback?.classList.add("review-fallback-visible");
      showMessage(error.message);
    } finally {
      fragment.removeAttribute("aria-busy");
    }
  });
});

if (window.location.hash.startsWith("#decision-")) {
  const requestId = window.location.hash.slice("#decision-".length);
  const target = document.getElementById(window.location.hash.slice(1))
    || document.querySelector(`[data-decision-request-id="${CSS.escape(requestId)}"]`);
  const expander = target?.querySelector(".request-expander");
  if (expander) expander.open = true;
}

const pushButton = document.querySelector("[data-enable-push]");
if (pushButton && "serviceWorker" in navigator && "PushManager" in window) {
  pushButton.addEventListener("click", async () => {
    try {
      const registration = await navigator.serviceWorker.register("/service-worker.js", { scope: "/" });
      const permission = await Notification.requestPermission();
      if (permission !== "granted") return;
      const key = document.body.dataset.vapidPublicKey;
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: decodeBase64url(key)
      });
      const json = subscription.toJSON();
      await postJson("/push/subscriptions", {
        endpoint: json.endpoint,
        p256dh: json.keys.p256dh,
        auth: json.keys.auth,
        device_label: navigator.platform || "Browser",
        categories: []
      }, pushButton.dataset.csrf);
      showMessage("Alerts enabled");
    } catch (error) {
      showMessage(error.message);
    }
  });
}

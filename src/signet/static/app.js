"use strict";

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

document.querySelectorAll("[data-passkey-action]").forEach((button) => {
  button.addEventListener("click", async () => {
    const root = button.closest("[data-request-id]");
    try {
      const action = button.dataset.passkeyAction;
      const requestId = root.dataset.requestId;
      const payloadHash = document.querySelector("input[name='expected_payload_hash']").value;
      const expectedVersion = Number(document.querySelector("input[name='expected_version']").value);
      const editArguments = action === "edit" ? document.querySelector("#edit-json")?.value : null;
      const options = await postJson(`/requests/${requestId}/actions/passkey/options`, {
        action,
        expected_version: expectedVersion,
        expected_payload_hash: payloadHash,
        prospective_arguments_json: editArguments
      }, root.dataset.csrf);
      const credential = await navigator.credentials.get({ publicKey: preparePublicKey(options.public_key) });
      await postJson(`/requests/${requestId}/actions/passkey/complete`, {
        challenge_id: options.challenge_id,
        assertion: assertionJson(credential)
      }, root.dataset.csrf);
      window.location.reload();
    } catch (error) {
      showMessage(error.message);
    }
  });
});

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

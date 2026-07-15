"use strict";

self.addEventListener("push", (event) => {
  let payload = { title: "Signet", body: "Approval queue updated", url: "/" };
  try {
    const candidate = event.data.json();
    if (candidate && candidate.title === "Signet") payload = candidate;
  } catch (_) {
    // Keep the privacy-safe fallback.
  }
  const url = typeof payload.url === "string" && payload.url.startsWith("/") && !payload.url.startsWith("//")
    ? payload.url
    : "/";
  event.waitUntil(self.registration.showNotification("Signet", {
    body: payload.body,
    icon: "/static/icons/signet-1254.png",
    badge: "/static/icons/signet-1254.png",
    data: { url },
    tag: typeof payload.tag === "string" ? payload.tag : "signet-update"
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data.url || "/"));
});

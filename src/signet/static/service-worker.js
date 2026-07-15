"use strict";

self.addEventListener("push", (event) => {
  event.waitUntil(self.registration.showNotification("Signet", {
    body: "Approval queue updated",
    icon: "/static/icons/signet-1254.png",
    badge: "/static/icons/signet-1254.png",
    data: { url: "/" },
    tag: "signet-update"
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data.url || "/"));
});

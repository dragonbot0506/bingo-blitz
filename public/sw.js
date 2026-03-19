self.addEventListener('push', function(event) {
  let data = { title: 'PIngo', body: 'Something happened!' };
  try {
    data = event.data.json();
  } catch (e) {}

  // Use type-specific tags:
  // - bingo: single tag so only the latest bingo notification shows
  // - task: unique tag per notification so they stack
  // - default: unique tag
  let tag;
  if (data.type === 'bingo') {
    tag = 'pingo-bingo';
  } else {
    tag = 'pingo-' + Date.now();
  }

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      vibrate: [200, 100, 200],
      tag: tag,
      renotify: true,
      data: data
    })
  );
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      // Focus an existing window if available
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      return clients.openWindow('/');
    })
  );
});

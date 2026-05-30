const CACHE = 'my-vault-v4';

const APP_SHELL = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.json',
  './icon.svg'
];

// ── Install: pre-cache app shell ──────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: purge old caches ────────────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Notification click: focus or open app ────────────────────────
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      const existing = list.find(c => c.url.includes(self.location.origin));
      if (existing) return existing.focus();
      return clients.openWindow('./');
    })
  );
});

// ── Periodic Sync: daily expense reminder ────────────────────────
self.addEventListener('periodicsync', e => {
  if (e.tag === 'expense-reminder') {
    e.waitUntil(
      self.registration.showNotification('My Vault 💸', {
        body: "Don't forget to log today's expenses!",
        icon: './icon.svg',
        badge: './icon.svg',
        tag: 'daily-reminder',
        renotify: true,
      })
    );
  }
});

// ── Fetch ─────────────────────────────────────────────────────────
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // App shell files (HTML/CSS/JS) → NETWORK FIRST
  // Always get the freshest code. Fall back to cache only if offline.
  if (url.origin === location.origin) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          // Store fresh copy in cache for offline use
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // CDN resources (fonts, Chart.js, Lucide, jsPDF) → CACHE FIRST
  // These rarely change — serve instantly from cache.
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      });
    })
  );
});

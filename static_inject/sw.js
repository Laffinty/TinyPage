/**
 * TinyPage Service Worker
 * Provides offline reading capability via Cache API.
 */
const CACHE_NAME = 'tinypage-v1';
const STATIC_ASSETS = [
  '/',
  '/search.html',
  '/search.js',
  '/manifest.json',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const { request } = e;
  // Only handle GET requests for same-origin HTML/JSON/JS
  if (request.method !== 'GET' || !request.url.startsWith(self.location.origin)) {
    return;
  }
  e.respondWith(
    caches.match(request).then((cached) => {
      if (cached) {
        // Stale-while-revalidate: return cached, then update
        fetch(request)
          .then((res) => {
            if (res.ok) caches.open(CACHE_NAME).then((c) => c.put(request, res));
          })
          .catch(() => {});
        return cached;
      }
      return fetch(request)
        .then((res) => {
          if (!res.ok) return res;
          const clone = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(request, clone));
          return res;
        })
        .catch(() => new Response('Offline', { status: 503 }));
    })
  );
});

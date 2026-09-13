// Cache everything on first visit, then never need the network again.
// An app about bad connectivity that refuses to open on a bad connection would
// be a poor joke.
const V = 'lastmile-v1';
const FILES = ['./', './index.html', './app.js', './lastmile.js', './manifest.webmanifest'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(V).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== V).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// Cache first. The app is self-contained, so the network is never the better answer.
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});

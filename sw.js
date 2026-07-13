// Service Worker minimal — sert uniquement à permettre au navigateur de détecter
// une nouvelle version du fichier index.html et à proposer un rechargement propre.
// Ne met rien en cache pour offline (volontairement) afin de toujours servir
// la dernière version disponible sur le réseau.

const SW_VERSION = '2026.07.13-23';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// Laisse passer toutes les requêtes réseau normalement (pas de cache offline)
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});

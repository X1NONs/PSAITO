const V = "psaito-v3";
// rutas RELATIVAS al sw.js: funciona en root de dominio y en GitHub Pages
// (/PSAITO/sw.js -> base /PSAITO/)
const SHELL = [
  "./", "./index.html", "./runtime.html",
  "./modules/offsets.mjs", "./modules/exploit.js",
  "./modules/offsets13x.js",
  "./modules/bridge.js", "./modules/menu.js",
];
// prefijo de la base (p.ej. "/PSAITO/" o "/")
const BASE = new URL(self.location).pathname.replace(/[^/]*$/, "");
const NO_CACHE = [BASE + "payloads/", BASE + "log/"];

self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(V)
      .then(c => c.addAll(SHELL.map(p => new URL(p, self.location).href)))
      .catch(() => {})
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const u = new URL(e.request.url);
  if (u.origin !== location.origin) return;
  // payloads y logs SIEMPRE a red: edicion inmediata / sin telemetria cacheada
  if (NO_CACHE.some(p => u.pathname.startsWith(p)))
    return;
  e.respondWith(
    caches.match(e.request).then(cached => {
      const net = fetch(e.request).then(r => {
        if (r.ok) {
          const cl = r.clone();
          caches.open(V).then(c => c.put(e.request, cl));
        }
        return r;
      }).catch(() => null);
      return cached || net;
    })
  );
});

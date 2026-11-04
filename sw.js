// Hukuk Platformu — çevrimdışı destek (service worker)
// Site dosyaları önbelleğe alınır; sunucu (API) istekleri her zaman internetten gider.
const CACHE = "hukuk-v37";
const FILES = ["./", "./index.html", "./manifest.webmanifest", "./icon.svg", "./icon-192.png", "./icon-512.png", "./icon-maskable-512.png"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE && k !== "hp-ozet").map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin) return; // API ve dış kaynaklar: dokunma
  // Önce internet (her zaman en yeni sürüm), olmazsa önbellek
  e.respondWith(fetch(e.request).then(r => { const c = r.clone(); caches.open(CACHE).then(x => x.put(e.request, c)); return r; })
    .catch(() => caches.match(e.request).then(r => r || caches.match("./index.html"))));
});

// Bildirimler: sunucu içeriksiz "dürtme" gönderir; metin telefondaki yerel özetten (hp-ozet) oluşturulur.
self.addEventListener("push", e => {
  e.waitUntil((async () => {
    let d = null;
    try { const c = await caches.open("hp-ozet"); const r = await c.match(self.location.origin + "/__hp_ozet"); if (r) d = await r.json(); } catch {}
    const now = Date.now(), tr = new Date(now + 3 * 3600e3), bugun = tr.toISOString().slice(0, 10), saat = tr.getUTCHours();
    const near = d ? (d.plan || []).filter(x => x.t <= now + 5 * 60e3 && x.t > now - 35 * 60e3) : [];   // sunucu en geç 30 dk içinde dürter
    let title = "Hukuk Platformu", body = "", tag = "hp-hatirlatma";
    if (near.length) body = near.map(x => x.m).join("\n");
    else if (d && saat === 8) {
      tag = "hp-sabah"; const pz = tr.getUTCDay() === 1, lines = [];
      const ev = (d.ev || []).filter(x => x.tarih === bugun), gor = (d.gor || []).filter(x => x.son <= bugun);
      if (d.p && d.p.sabah) {
        title = "Günün özeti";
        lines.push(ev.length ? `Bugün ${ev.length} kayıt: ` + ev.map(x => (x.saat ? x.saat + " " : "") + x.tip + (x.baslik ? " — " + x.baslik : "")).join(", ") : "Bugün kayıtlı duruşma yok.");
        if (gor.length) lines.push(`${gor.length} görevin son günü bugün veya geçti.`);
      }
      if (pz && d.p && d.p.haftalik) {
        const son = new Date(now + 3 * 3600e3 + 7 * 86400e3).toISOString().slice(0, 10);
        const hafta = (d.ev || []).filter(x => x.tarih >= bugun && x.tarih < son);
        if (!lines.length) title = "Haftalık plan";
        lines.push(`Bu hafta ${hafta.filter(x => x.tip === "Duruşma").length} duruşma, ${hafta.filter(x => x.tip === "Süre sonu").length} süre sonu var.`);
        if (d.pasif) lines.push(`${d.pasif} dosya uzun süredir işlem görmedi.`);
      }
      body = lines.join("\n");
    }
    if (!body) body = "Yaklaşan işleriniz var. Ajandanızı kontrol edin.";
    await self.registration.showNotification(title, { body, tag, renotify: true, icon: "icon-192.png", badge: "icon-192.png", data: { url: "./#/panel" } });
  })());
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "./#/panel", self.location.href).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(cs => {
    for (const c of cs) if (c.url.startsWith(self.location.origin)) { c.navigate(url).catch(() => {}); return c.focus(); }
    return self.clients.openWindow(url);
  }));
});

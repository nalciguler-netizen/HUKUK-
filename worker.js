// Hukuk Platformu — Cloudflare Worker arka ucu
// Hak sahibi: Yurdagül Güler. Tüm hakları saklıdır.
import { connect } from "cloudflare:sockets";
//
// Gerekli bağlantılar (Worker > Settings > Bindings):
//   DB  : D1 veritabanı (schema.sql ile kurulur)
//   AI  : Workers AI
// Değişkenler (Settings > Variables and Secrets):
//   APP_URL        : sitenin adresi, ör. https://nalciguler-netizen.github.io/HUKUK/
//   APP_NAME       : Hukuk Platformu
//   GMAIL_USER         : e-postaları gönderecek Gmail adresi (ör. yolhava.destek@gmail.com)
//   GMAIL_APP_PASSWORD : (Secret) o Gmail hesabının 16 haneli "uygulama şifresi"
//   SUPPORT_EMAIL      : kullanıcılara gösterilen destek adresi
//   ALLOWED_ORIGIN : isteğe bağlı; boşsa APP_URL'nin kökü kullanılır

const PBKDF2_ITER = 50000;         // ücretsiz plan CPU sınırı için; hash ile birlikte saklanır, sonradan artırılabilir
const SESSION_DAYS = 30;
const TRIAL_HOURS = 24 * 7;           // yeni hesaplara 7 gün Optimus denemesi
const RESET_MINUTES = 30;
// Sırayla denenir. Düşünen (reasoning) modeller yavaş ve boş yanıt verebildiği için doğrudan yanıt veren modeller önde.
const AI_MODELS = [
  { id: "@cf/mistralai/mistral-small-3.1-24b-instruct", opts: { max_tokens: 1200 } },
  { id: "@cf/meta/llama-4-scout-17b-16e-instruct", opts: { max_tokens: 1200 } },
  { id: "@cf/google/gemma-4-26b-a4b-it", opts: { max_completion_tokens: 3000, chat_template_kwargs: { enable_thinking: false } } },
];

// Paket sınırları (günlük)
const PLANS = {
  basic:   { label: "Basic",   price: 0,    search: 10,   ai: 3,   maxText: 12000, files: false, refs: 0,
             tasks: ["ozet"] },
  optimus: { label: "Optimus", price: 700,  search: 200,  ai: 50,  maxText: 40000, files: true, refs: 5,
             tasks: ["ozet", "sozlesme", "sozlesme_revize", "dilekce", "ceviri", "degisiklik", "dava_analiz", "dilekce_yaz"] },
  maximus: { label: "Maximus", price: 1200, search: 1000, ai: 200, maxText: 80000, files: true, refs: 10,
             tasks: ["ozet", "sozlesme", "sozlesme_revize", "dilekce", "ceviri", "karsilastir", "degisiklik", "dava_analiz", "dilekce_yaz"] },
};

// Resmî karar bankaları (kamuya açık arama arayüzleri)
const SOURCES = {
  yargitay: { label: "Yargıtay", base: "https://karararama.yargitay.gov.tr", search: "/aramadetaylist" },
  emsal:    { label: "UYAP Emsal", base: "https://emsal.uyap.gov.tr", search: "/aramalist" },
  danistay: { label: "Danıştay", base: "https://karararama.danistay.gov.tr", search: "/aramadetaylist" },
};

const UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36";

// ---------- yardımcılar ----------
const now = () => Math.floor(Date.now() / 1000);
const today = () => new Date(Date.now() + 3 * 3600e3).toISOString().slice(0, 10); // Türkiye saati
const enc = new TextEncoder();

function b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join(""); }
function randomToken(bytes = 32) { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return hex(a); }
async function sha256(s) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(s))); }

async function hashPassword(password, saltB64, iter) {
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
  return b64(bits);
}
function newSalt() { const a = new Uint8Array(16); crypto.getRandomValues(a); return b64(a); }
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

const trLower = s => String(s || "").replace(/İ/g, "i").replace(/I/g, "ı").toLowerCase();
// Birden fazla ifade: "kıdem tazminatı + fazla mesai, tanık" veya "a - b" (tire iki yanında boşlukla)
function splitPhrases(q) {
  const parts = String(q || "").split(/\s*[+,]\s*|\s+[-\u2013]\s+/).map(x => x.trim().replace(/^"|"$/g, "")).filter(x => x.length >= 2);
  return parts.slice(0, 4);
}

function corsHeaders(req, env) {
  const origin = req.headers.get("Origin") || "";
  let allowed = (env.ALLOWED_ORIGIN || "").trim();
  if (!allowed && env.APP_URL) { try { allowed = new URL(env.APP_URL).origin; } catch {} }
  const ok = !allowed || origin === allowed;
  return {
    "Access-Control-Allow-Origin": ok ? (origin || "*") : allowed,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json; charset=utf-8", ...cors },
  });
}
async function body(req) {
  try { return await req.json(); } catch { throw new HttpError(400, "Geçersiz istek gövdesi."); }
}
function cleanEmail(e) {
  const v = String(e || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v) || v.length > 200) throw new HttpError(400, "Geçerli bir e-posta adresi girin.");
  return v;
}
function checkPassword(p) {
  p = String(p || "");
  if (p.length < 8) throw new HttpError(400, "Şifre en az 8 karakter olmalı.");
  if (p.length > 200) throw new HttpError(400, "Şifre çok uzun.");
  return p;
}

function effectivePlan(u) {
  const t = now();
  if (u.plan !== "basic" && u.plan_until && u.plan_until > t) return u.plan;
  if (u.trial_until && u.trial_until > t) return "optimus";
  return "basic";
}
function publicUser(u) {
  const plan = effectivePlan(u);
  return {
    email: u.email, name: u.name, plan, planLabel: PLANS[plan].label,
    trialUntil: u.trial_until, planUntil: u.plan_until, isAdmin: !!u.is_admin,
  };
}

async function currentUser(req, env) {
  const h = req.headers.get("Authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  if (!token) throw new HttpError(401, "Giriş yapmanız gerekiyor.");
  const row = await env.DB.prepare(
    "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?"
  ).bind(await sha256(token), now()).first();
  if (!row) throw new HttpError(401, "Oturumunuzun süresi doldu, yeniden giriş yapın.");
  return row;
}

async function createSession(env, userId) {
  const token = randomToken();
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)")
    .bind(await sha256(token), userId, now() + SESSION_DAYS * 86400).run();
  return token;
}

async function useQuota(env, user, kind, commit = true) {
  const plan = effectivePlan(user);
  const limit = PLANS[plan][kind];
  const day = today();
  const row = await env.DB.prepare("SELECT n FROM usage WHERE user_id=? AND day=? AND kind=?")
    .bind(user.id, day, kind).first();
  const used = row ? row.n : 0;
  if (used >= limit) {
    throw new HttpError(429, `${PLANS[plan].label} paketinin günlük ${kind === "ai" ? "yapay zekâ" : "arama"} hakkı (${limit}) doldu. Yarın yenilenir veya paketinizi yükseltebilirsiniz.`);
  }
  if (commit) await env.DB.prepare(
    "INSERT INTO usage (user_id, day, kind, n) VALUES (?,?,?,1) ON CONFLICT(user_id, day, kind) DO UPDATE SET n = n + 1"
  ).bind(user.id, day, kind).run();
  return { used: commit ? used + 1 : used, limit };
}

// ---------- resmî kaynak erişimi ----------
function decodeEntities(v) {
  return v.replace(/&nbsp;/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'").replace(/&#(\d+);/g, (_, d) => String.fromCharCode(+d))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/&amp;/g, "&");
}
const JS_LINE = /^\s*(\/\/|\/\*|var |let |const |function\b|\$\(|jQuery|options\[|return |if ?\(|else\b|\}\)?;?\s*$|\{\s*$|window\.|document\.|[A-Za-z_$][\w$.]*\s*=\s*[^=].*;\s*$|[A-Za-z_$][\w$.]*\(.*\);\s*$)/;
// Resmî sitelerden gelen HTML'i düz metne çevirir. Danıştay belgeyi tam sayfa olarak ve
// etiketleri bir kez daha kodlanmış (&lt;script&gt;) gönderdiği için işlem birkaç tur tekrarlanır.
function cleanHtml(raw) {
  let v = String(raw || "");
  // Karar metni bir program satırının içinde gömülü gelebilir: stringToHTML("...metin...")
  for (let round = 0; round < 2; round++) {
    const m = v.match(/stringToHTML\(\s*(["'`])((?:\\[\s\S]|(?!\1)[\s\S]){200,}?)\1\s*\)/);
    if (m) {
      const inner = m[2].replace(/\\n/g, "\n").replace(/\\t/g, " ").replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\(["'`\\/])/g, "$1");
      v = inner; break;
    }
    const d = decodeEntities(v); if (d === v) break; v = d;
  }
  for (let round = 0; round < 3; round++) {
    v = v.replace(/<(style|script|head|title|noscript|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ")
         .replace(/<!--[\s\S]*?-->/g, " ")
         .replace(/<[^>]*id=["']?hidden[A-Za-z]*["']?[^>]*>[\s\S]*?<\/[a-z]+>/gi, " ");   // gizli yardımcı alanlar
    v = v.replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|tr|li|h\d|table)>/gi, "\n").replace(/<[^>]+>/g, " ");
    const before = v;
    v = decodeEntities(v);
    if (v === before && !/<\/?[a-z][^>]*>/i.test(v)) break;   // çözülecek bir şey kalmadı
  }
  // Etiketsiz kalmış CSS kuralları (".highlight { ... }") ve program satırları
  v = v.replace(/^\s*(?:[.#]?[a-z][\w\-]*\s*(?:,\s*[.#]?[a-z][\w\-]*\s*)*)\{[^{}]*\}\s*/gim, "");
  v = v.split("\n").filter(line => !JS_LINE.test(line)).join("\n");
  v = v.replace(/[ \t]+/g, " ").replace(/\n[ \t]+/g, "\n").replace(/\n{3,}/g, "\n\n");
  return v.trim();
}

async function officialFetch(url, init) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 25000);
  try {
    const res = await fetch(url, {
      ...init,
      signal: ctrl.signal,
      headers: {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json; charset=UTF-8",
        ...(init && init.headers),
      },
    });
    if (res.status === 429) throw new HttpError(503, "Resmî karar bankası şu an yoğun; 1-2 dakika sonra yeniden deneyin.");
    if (!res.ok) throw new HttpError(502, `Resmî kaynak yanıt vermedi (HTTP ${res.status}).`);
    const text = await res.text();
    try { return JSON.parse(text); } catch { return text; }
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(502, "Resmî karar bankasına şu anda ulaşılamıyor. Biraz sonra tekrar deneyin.");
  } finally { clearTimeout(timer); }
}

function metaError(data) {
  const m = data && typeof data === "object" ? data.metadata : null;
  return m && m.FMTY === "ERROR" ? String(m.FMTE || "Resmî kaynak hata döndürdü.") : null;
}

async function searchOfficial(sourceKey, query, page) {
  const s = SOURCES[sourceKey];
  if (!s) throw new HttpError(400, "Bilinmeyen kaynak.");
  const q = String(query || "").trim();
  if (q.length < 2) throw new HttpError(400, "En az 2 karakterlik bir arama ifadesi girin.");
  if (q.length > 300) throw new HttpError(400, "Arama ifadesi çok uzun.");
  const p = Math.max(1, Math.min(parseInt(page) || 1, 50));
  const common = {
    esasYil: "", esasIlkSiraNo: "", esasSonSiraNo: "", kararYil: "", kararIlkSiraNo: "", kararSonSiraNo: "",
    baslangicTarihi: "", bitisTarihi: "", siralama: "3", siralamaDirection: "desc", pageSize: 20, pageNumber: p,
  };
  const post = async (path, data) => {
    const r = await officialFetch(s.base + path, {
      method: "POST", body: JSON.stringify({ data }), headers: { Referer: s.base + "/" },
    });
    const err = metaError(r);
    if (err) throw new HttpError(502, err);
    return r;
  };

  const phrases = splitPhrases(q);
  const multi = phrases.length > 1;
  // Resmî sitelerde tam ifade tırnakla aranır; ifadeler boşlukla birleştirilir (sitelerin "ve" araması).
  const qq = multi ? phrases.map(x => /\s/.test(x) ? `"${x}"` : x).join(" ") : q;
  let res;
  if (sourceKey === "yargitay") {
    try {
      res = await post(s.search, { arananKelime: qq, birimYrgKurulDaire: "", ...common });
    } catch (e) {
      // Yargıtay sitesi bulut bağlantılarını reddedebiliyor; Yargıtay kararları UYAP Emsal'de de yayımlanır.
      const alt = await searchOfficial("emsal", q, p);   // emsal kendi içinde çoklu ifadeyi işler
      // UYAP Emsal tüm mahkemeleri verir; Yargıtay seçildiğinde bölge adliye ve ilk derece kararlarını ayıkla.
      const only = alt.items.filter(it => !/bölge adliye|mahkemesi/i.test(it.daire));
      const items = only.length ? only : alt.items;
      return { ...alt, items, requested: "yargitay",
        note: only.length
          ? "Yargıtay karar arama sitesine şu an ulaşılamadı; Yargıtay kararları UYAP Emsal'den getirildi."
          : "Yargıtay karar arama sitesine ulaşılamadı ve bu sayfada UYAP Emsal'de Yargıtay kararı bulunamadı; tüm mahkemelerin kararları gösteriliyor." };
    }
  } else if (sourceKey === "danistay") {
    // Danıştay iki arama biçimi sunar: önce basit kelime araması, olmazsa ayrıntılı arama.
    const words = multi ? phrases : q.startsWith('"') && q.endsWith('"') ? [q.slice(1, -1)] : q.split(/\s+/).filter(Boolean);
    try {
      res = await post("/aramalist", { andKelimeler: words, orKelimeler: [], notAndKelimeler: [], notOrKelimeler: [], pageSize: 20, pageNumber: p });
    } catch {
      res = await post(s.search, { aranan: qq, arananKelime: qq, daire: "", ...common });
    }
  } else {
    res = await post(s.search, { aranan: qq, arananKelime: qq, pageSize: 20, pageNumber: p });
  }
  const inner = res && res.data && typeof res.data === "object" ? res.data : {};
  const rows = Array.isArray(inner.data) ? inner.data : [];
  return {
    source: sourceKey, sourceLabel: s.label, page: p, phrases: multi ? phrases : undefined,
    note: multi ? `Aranan ifadeler: ${phrases.map(x => "“" + x + "”").join(" + ")}. Resmî site sonuçları ifadelerin hepsini içermeyebilir; kararı açınca ifadeler renkli gösterilir.` : undefined,
    total: Number(inner.recordsTotal || inner.recordsFiltered || rows.length) || 0,
    items: rows.map(r => ({
      id: String(r.id || r.kararId || r.dokumanId || ""),
      daire: String(r.daire || r.birim || r.birimAdi || s.label),
      esas: String(r.esasNo || r.esas || ""),
      karar: String(r.kararNo || r.karar || ""),
      tarih: String(r.kararTarihi || r.tarih || ""),
    })).filter(r => r.id),
  };
}

// Resmî siteden metin alınamazsa aynı kararı esas + karar numarasıyla 11M arşivde bul.
async function archiveByNumbers(env, sourceKey, hint) {
  const h = hint || {};
  const esas = String(h.esas || "").trim(), karar = String(h.karar || "").trim();
  if (!/^\d{4}\/\d{1,7}$/.test(esas) || !/^\d{4}\/\d{1,7}$/.test(karar)) return null;
  const cfg = { yargitay: "yargitay", emsal: "emsal", danistay: "danistay" }[sourceKey];
  if (!cfg) return null;
  for (const ds of ARCHIVE_MIRRORS) {
    try {
      const j = await hfGet("filter", { dataset: ds, config: cfg, split: "train", offset: "0", length: "1",
        where: `"esas_no"='${esas}' AND "karar_no"='${karar}'` });
      const it = j.rows && j.rows[0];
      if (it && it.row && it.row.text) return archRow(cfg, it, ds);
      return null;   // arşivde yok (ör. arşivden yeni bir karar)
    } catch (e) { if (e && e.timeout) return null; }
  }
  return null;
}

async function getDecision(env, sourceKey, id, hint) {
  try { return await getDecisionOfficial(env, sourceKey, id, hint); }
  catch (e) {
    const row = await archiveByNumbers(env, sourceKey, hint).catch(() => null);
    const s = SOURCES[sourceKey];
    const kw = sourceKey === "danistay" ? `&arananKelime=${encodeURIComponent(String((hint && hint.q) || "").slice(0, 200))}` : "";
    const officialUrl = s ? `${s.base}/getDokuman?id=${encodeURIComponent(String(id || ""))}${kw}` : "";
    if (!row) { const err = new HttpError(e.status || 502, e.message); err.officialUrl = officialUrl; throw err; }
    return { source: sourceKey, doc_id: String(id), title: row.daire, daire: row.daire, esas: row.esas, karar: row.karar,
      tarih: row.tarih, text: String(row.text), fetched_at: now(), officialUrl, cached: false,
      note: "Resmî siteden metin alınamadı; karar 11M arşivden getirildi." };
  }
}

async function getDecisionOfficial(env, sourceKey, id, hint) {
  const s = SOURCES[sourceKey];
  if (!s) throw new HttpError(400, "Bilinmeyen kaynak.");
  const docId = String(id || "").trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(docId)) throw new HttpError(400, "Geçersiz karar kimliği.");
  const cached = await env.DB.prepare("SELECT * FROM decisions WHERE source=? AND doc_id=?").bind(sourceKey, docId).first();
  if (cached) return { ...cached, text: cleanHtml(cached.text), officialUrl: `${s.base}/getDokuman?id=${docId}`, cached: true };

  // Danıştay, belge isteğinde aranan kelimeyi de zorunlu tutuyor (metinde vurgulamak için).
  const kw = sourceKey === "danistay" ? `&arananKelime=${encodeURIComponent(String((hint && hint.q) || "").slice(0, 200))}` : "";
  const res = await officialFetch(`${s.base}/getDokuman?id=${encodeURIComponent(docId)}${kw}`, {
    method: "GET", headers: { Referer: s.base + "/" },
  });
  const err = metaError(res);
  if (err) throw new HttpError(502, err);
  let raw = res;
  if (raw && typeof raw === "object") raw = raw.data ?? raw.content ?? raw.text ?? "";
  if (raw && typeof raw === "object") raw = raw.data ?? raw.content ?? raw.text ?? "";
  const text = cleanHtml(raw);
  if (text.length < 200) throw new HttpError(502, "Karar tam metni resmî kaynaktan alınamadı.");
  const h = hint || {};
  const rec = {
    source: sourceKey, doc_id: docId,
    title: `${h.daire || s.label}${h.esas ? " · E. " + h.esas : ""}${h.karar ? " · K. " + h.karar : ""}`.slice(0, 300),
    daire: String(h.daire || "").slice(0, 200), esas: String(h.esas || "").slice(0, 50),
    karar: String(h.karar || "").slice(0, 50), tarih: String(h.tarih || "").slice(0, 30),
    text, fetched_at: now(),
  };
  await env.DB.prepare(
    "INSERT OR IGNORE INTO decisions (source, doc_id, title, daire, esas, karar, tarih, text, fetched_at) VALUES (?,?,?,?,?,?,?,?,?)"
  ).bind(rec.source, rec.doc_id, rec.title, rec.daire, rec.esas, rec.karar, rec.tarih, rec.text, rec.fetched_at).run();
  return { ...rec, officialUrl: `${s.base}/getDokuman?id=${docId}`, cached: false };
}


// ---------- 11 milyon kararlık arşiv (Hugging Face veri seti; yedeği GitHub "veri-11m" sürümünde) ----------
// Arama, veri setinin kamuya açık arama servisi üzerinden yapılır; ayna kaldırılırsa sıradakine geçilir.
const ARCHIVE_MIRRORS = ["esnucil/turkish-court-decisions", "geginhug/turkish-court-decisions", "Alptekinege/turkish-court-decisions",
  "Gyrevortex/turkish-court-decisions", "mrfg/turkish-court-decisions", "serdarsrts/turkish-court-decisions-duplicate"];
const ARCHIVE_CONFIGS = { yargitay: "Yargıtay", emsal: "UYAP Emsal", danistay: "Danıştay", aym_bb: "AYM Bireysel Başvuru", aym_norm: "AYM Norm Denetimi" };
const HF = "https://datasets-server.huggingface.co";

async function hfGet(path, params) {
  const url = `${HF}/${path}?` + new URLSearchParams(params).toString();
  // Aynı arama tekrarlanınca 1 gün boyunca Cloudflare önbelleğinden anında döner.
  const cache = caches.default; const key = new Request(url);
  const hit = await cache.match(key); if (hit) return hit.json();
  const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), 20000);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { Accept: "application/json" } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || `HTTP ${r.status}`); e.status = r.status; throw e; }
    try { await cache.put(key, new Response(JSON.stringify(j), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=86400" } })); } catch {}
    return j;
  } catch (e) { if (e.name === "AbortError") { const t = new Error("zaman aşımı"); t.timeout = true; throw t; } throw e; }
  finally { clearTimeout(timer); }
}
const archRow = (cfg, it, dataset) => {
  const r = it.row || {};
  return {
    id: `${cfg}.${it.row_idx}`,
    daire: String(r.court || ARCHIVE_CONFIGS[cfg]).trim(),
    esas: String(r.esas_no || ""), karar: String(r.karar_no || ""),
    tarih: String(r.karar_tarihi || r.year || ""), text: r.text, dataset,
  };
};

async function searchArchive(env, query, page, cfg) {
  const q = String(query || "").trim();
  if (q.length < 2) throw new HttpError(400, "En az 2 karakterlik bir arama ifadesi girin.");
  if (q.length > 300) throw new HttpError(400, "Arama ifadesi çok uzun.");
  if (!ARCHIVE_CONFIGS[cfg]) cfg = "yargitay";
  const p = Math.max(1, Math.min(parseInt(page) || 1, 50));
  // Esas/karar numarası gibi görünüyorsa (2020/123) doğrudan filtreyle ara.
  const num = q.match(/^(\d{4})\s*\/\s*(\d{1,6})$/);
  let lastErr = "";
  for (const ds of ARCHIVE_MIRRORS) {
    try {
      const params = { dataset: ds, config: cfg, split: "train", offset: String((p - 1) * 20), length: "20" };
      const phrases = num ? [] : splitPhrases(q);
      if (phrases.length > 1) {
        // Çoklu ifade: 50 sonuç alınır, metninde ifadelerin HEPSİ geçenler bırakılır (kesin filtre).
        const jm = await hfGet("search", { ...params, offset: String((p - 1) * 50), length: "50", query: phrases.join(" ") });
        const need = phrases.map(trLower);
        const hits = (jm.rows || []).filter(it => { const t = trLower(it.row && it.row.text); return need.every(w => t.includes(w)); });
        const items = hits.map(it => { const x = archRow(cfg, it, ds); delete x.text; return x; });
        const scanned = Math.min(50, (jm.rows || []).length);
        return { source: "arsiv", sourceLabel: `11M Arşiv · ${ARCHIVE_CONFIGS[cfg]}`, config: cfg, page: p, phrases,
          total: items.length, items, more: scanned >= 50,
          note: `${phrases.map(x => "“" + x + "”").join(" + ")} ifadelerinin hepsini içeren kararlar: en ilgili ${scanned} sonuç içinden ${items.length} karar.` };
      }
      const j = num
        ? await hfGet("filter", { ...params, where: `"esas_no"='${num[1]}/${num[2]}' OR "karar_no"='${num[1]}/${num[2]}'` })
        : await hfGet("search", { ...params, query: q });
      const items = (j.rows || []).map(it => { const x = archRow(cfg, it, ds); delete x.text; return x; });
      return { source: "arsiv", sourceLabel: `11M Arşiv · ${ARCHIVE_CONFIGS[cfg]}`, config: cfg, page: p,
        total: Number(j.num_rows_total || items.length) || 0, items,
        note: j.partial ? "Arşivin bu bölümünde arama kısmi dizin üzerinden yapıldı; bazı sonuçlar görünmeyebilir." : undefined };
    } catch (e) {
      lastErr = String(e && e.message || e).slice(0, 120);
      if (e && e.timeout) break;   // yavaşlık tüm kopyalarda aynıdır; diğerlerini beklemeye gerek yok
    }
  }
  throw new HttpError(502, `11M arşiv araması şu an yanıt vermedi (${lastErr}). UYAP Emsal kaynağını deneyin.`);
}

async function getArchiveDecision(env, id, hint) {
  const m = String(id || "").match(/^([a-z_]+)\.(\d{1,9})$/);
  if (!m || !ARCHIVE_CONFIGS[m[1]]) throw new HttpError(400, "Geçersiz arşiv kimliği.");
  const cached = await env.DB.prepare("SELECT * FROM decisions WHERE source='arsiv' AND doc_id=?").bind(id).first();
  if (cached) return { ...cached, officialUrl: "", cached: true };
  const order = hint && hint.dataset && ARCHIVE_MIRRORS.includes(hint.dataset) ? [hint.dataset, ...ARCHIVE_MIRRORS.filter(x => x !== hint.dataset)] : ARCHIVE_MIRRORS;
  let row = null;
  for (const ds of order) {
    try {
      const j = await hfGet("rows", { dataset: ds, config: m[1], split: "train", offset: m[2], length: "1" });
      if (j.rows && j.rows[0]) { row = archRow(m[1], j.rows[0], ds); break; }
    } catch {}
  }
  if (!row || !row.text) throw new HttpError(502, "Karar metni arşivden alınamadı, biraz sonra tekrar deneyin.");
  const rec = { source: "arsiv", doc_id: id,
    title: `${row.daire}${row.esas ? " · E. " + row.esas : ""}${row.karar ? " · K. " + row.karar : ""}`.slice(0, 300),
    daire: row.daire.slice(0, 200), esas: row.esas.slice(0, 50), karar: row.karar.slice(0, 50), tarih: row.tarih.slice(0, 30),
    text: String(row.text), fetched_at: now() };
  await env.DB.prepare(
    "INSERT OR IGNORE INTO decisions (source, doc_id, title, daire, esas, karar, tarih, text, fetched_at) VALUES (?,?,?,?,?,?,?,?,?)"
  ).bind(rec.source, rec.doc_id, rec.title, rec.daire, rec.esas, rec.karar, rec.tarih, rec.text, rec.fetched_at).run();
  return { ...rec, officialUrl: "", cached: false };
}

// ---------- yapay zekâ ----------
const AI_RULES =
  "Sen Türk hukuku alanında çalışan bir metin analiz asistanısın. Kurallar: " +
  "(1) YALNIZCA kullanıcının verdiği metne dayan. " +
  "(2) Kendi hafızandan ASLA karar numarası, esas/karar no, tarih, kanun maddesi numarası veya içtihat uydurma; metinde yoksa 'metinde belirtilmemiş' de. " +
  "(3) Emin olmadığın yerde bunu açıkça yaz. " +
  "(4) Yanıtı Türkçe, düzenli başlıklar ve maddelerle ver. " +
  "(5) Sonunda tek satırla 'Bu çıktı hukuki danışmanlık değildir; bir avukat tarafından kontrol edilmelidir.' yaz.";

const AI_TASKS = {
  ozet: "Aşağıdaki mahkeme kararını bir avukat için özetle. Şu başlıkları sırayla ve kısa tut:\n" +
    "1. Künye: mahkeme/daire, esas no, karar no, tarih (yalnızca metinde geçenler).\n" +
    "2. Taraflar ve dava türü (adlar maskelenmişse öyle bırak).\n" +
    "3. Olay ve talep: davacının iddiası ve talebi, davalının savunması (2-4 cümle).\n" +
    "4. Yargılama süreci: ilk derece kararı, istinaf/temyiz aşamaları ve kimin neye itiraz ettiği.\n" +
    "5. Mahkemenin gerekçesi: kararı belirleyen hukuki değerlendirme; en önemli cümleyi metinden tırnak içinde aynen aktar.\n" +
    "6. Hüküm: onama / bozma / kaldırma / ret / kabul vb. ve gerekçesi tek cümleyle; oy birliği mi çokluk mu.\n" +
    "7. Dayanılan mevzuat: yalnızca metinde açıkça geçen kanun ve maddeler.\n" +
    "8. İçtihat değeri: bu karardan çıkan genel ilke tek cümleyle ve hangi tür davalarda emsal olabileceği.\n" +
    "Gereksiz tekrar yapma, metinde olmayan bilgi ekleme.",
  sozlesme: "Aşağıdaki sözleşmeyi incele: taraflar ve konu, temel yükümlülükler, riskli/tek taraflı maddeler (madde alıntısıyla), eksik görünen hükümler, müzakere önerileri. Risk seviyesini Yüksek/Orta/Düşük olarak belirt.",
  dilekce: "Aşağıda verilen olay ve taleplere göre bir dilekçe TASLAĞI iskeleti hazırla: başlık, taraflar (boş alanlar [ ] ile), konu, açıklamalar (olaylar sırasıyla), hukuki nedenler (yalnızca kullanıcının metninde geçen kanun/karar atıflarını kullan; yoksa '[ilgili mevzuat avukat tarafından eklenecek]' yaz), deliller, sonuç ve istem.",
  ceviri: "Aşağıdaki hukuki metni hedef dile çevir. Hukuki terimleri doğru karşılıklarıyla kullan; emin olmadığın terimin yanına parantez içinde Türkçe aslını yaz.",
  karsilastir: "Aşağıdaki metinlerdeki kararları karşılaştır: benzerlikler, farklılıklar, hangi olgunun sonucu değiştirdiği.",
  sozlesme_revize: "Aşağıda bir sözleşme ve ona yapılmış risk analizi var. Analizdeki önerileri uygulayarak sözleşmenin DÜZELTİLMİŞ TAM METNİNİ yaz:\n" +
    "- Orijinal madde numaralarını ve sırasını koru; değişmeyen maddeleri kelimesi kelimesine aynen bırak.\n" +
    "- Yalnızca analizde riskli veya eksik bulunan noktaları değiştir; eksik hükümleri uygun yere yeni madde olarak ekle.\n" +
    "- Tutar, tarih, oran, süre gibi tarafların belirlemesi gereken değerleri uydurma; [ ] ile boş bırak.\n" +
    "- Kanun maddesi numarası veya karar atfı ekleme.\n" +
    "- Önce yalnızca düzeltilmiş sözleşme metnini yaz. Metin bittikten sonra '--- YAPILAN DEĞİŞİKLİKLER ---' başlığı altında her değişikliği tek satırla ve gerekçesiyle listele.",
  dava_analiz: "Aşağıda bir avukatın davası (olay, talep, deliller) ile avukatın seçtiği mahkeme kararlarının künyeleri, bilgisayarca çıkarılmış sonuçları (onama/bozma vb.) ve gerekçe/hüküm kısımları var. DAVA ANALİZİ yaz:\n" +
    "1. İçtihat tablosu: seçilen kararlar ne yönde (verilen sayımları kullan; kendin sayı uydurma), en güçlü kaynak hangisi (İBK/Genel Kurul > daire > bölge adliye), kararlar ne kadar güncel.\n" +
    "2. Olayla benzerlik: her karar için olaya benzeyen ve ayrışan yön; karara künyesiyle atıf yap.\n" +
    "3. Lehe noktalar ve aleyhe noktalar (karşı tarafın muhtemel savunması dahil).\n" +
    "4. İspat: hangi vakıa kimin tarafından, hangi delille ispatlanmalı; eksik görünen deliller.\n" +
    "5. Usul kontrolü: süre, görev/yetki, dava şartları (ör. arabuluculuk) gibi kontrol edilmesi gereken noktalar — yalnızca soru olarak belirt, kesin hüküm kurma.\n" +
    "6. Değerlendirme: davanın güçlü ve zayıf yanlarını nitel olarak özetle (güçlü / orta / zayıf). YÜZDE veya kazanma olasılığı rakamı VERME.\n" +
    "Yalnızca verilen künyelere atıf yap; listede olmayan karar, esas/karar numarası veya kanun maddesi yazma.",
  dilekce_yaz: "Aşağıdaki bilgilerle bir DAVA DİLEKÇESİ TASLAĞI yaz. Taraf ve mahkeme bilgilerini AŞAĞIDAKİ YER TUTUCULARLA aynen yaz (bunlar telefonda gerçek bilgilerle doldurulacak):\n" +
    "{{MAHKEME}} — mahkeme adı (başlıkta, 'NE' ekiyle: {{MAHKEME}}'NE); {{DAVACI}} — davacı; {{DAVACI_VEKILI}} — davacı vekili; {{DAVALI}} — davalı(lar); {{DAVA_DEGERI}} — dava değeri; {{TARIH}} — tarih.\n" +
    "Biçim: {{MAHKEME}}'NE başlığı; DAVACI : {{DAVACI}}; VEKİLİ : {{DAVACI_VEKILI}}; DAVALI : {{DAVALI}}; DAVA DEĞERİ : {{DAVA_DEGERI}} (gerekiyorsa); KONU (verilen konuyu kullanarak tek paragraf); AÇIKLAMALAR (numaralı paragraflar, olaylar tarih sırasıyla); HUKUKİ DEĞERLENDİRME VE EMSAL KARARLAR; HUKUKİ NEDENLER; HUKUKİ DELİLLER; SONUÇ VE İSTEM (numaralı talepler); {{TARIH}} ve 'Davacı Vekili {{DAVACI_VEKILI}}' imza alanı.\n" +
    "Kurallar:\n" +
    "- Emsal karar olarak YALNIZCA 'SEÇİLEN KARARLAR' listesindeki künyeleri kullan; her atıfta künyeyi aynen yaz (daire, E., K., tarih) ve kararın olaya nasıl uyduğunu bir-iki cümleyle açıkla. Listede olmayan karar yazma.\n" +
    "- Kanun maddesini yalnızca kullanıcının metninde veya seçilen kararların metninde geçiyorsa yaz; yoksa '[ilgili mevzuat avukat tarafından eklenecek]' yaz.\n" +
    "- Olayda geçmeyen ada, tarihe, tutara, ada-parsel bilgisine ihtiyaç olursa [ ] ile boş bırak; uydurma.\n" +
    "- Dava analizi verilmişse onun lehe noktalarını öne çıkar, aleyhe noktalara karşı açıklama yap.\n" +
    "- Resmî, açık ve ölçülü dilekçe dili kullan; abartılı ifade kullanma.",
  degisiklik: "Aşağıda bir mevzuat hükmünün ESKİ ve YENİ metni ile bilgisayarın otomatik çıkardığı kelime farkları var. Şu başlıklarla yaz:\n" +
    "1. Değişikliğin özü: 1-2 cümle.\n" +
    "2. Değişen noktalar: her biri için 'eski → yeni' ve hukuki anlamı (hak, yükümlülük, süre, miktar, oran, kapsam veya yaptırım genişledi mi, daraldı mı, kaldırıldı mı).\n" +
    "3. Etkilenenler: kimin lehine, kimin aleyhine olabileceği; yalnızca metinden çıkarılabiliyorsa yaz.\n" +
    "4. Uygulamada dikkat: metinde yürürlük tarihi veya geçiş hükmü varsa belirt, yoksa 'metinde belirtilmemiş' de. Hüküm ceza veya yaptırım içeriyorsa lehe kanun değerlendirmesinin avukat tarafından yapılması gerektiğini hatırlat.\n" +
    "Yalnızca verilen iki metne ve fark listesine dayan; listede olmayan bir değişiklik uydurma.",
};

// Uzun çıktı gereken görevlerde yanıt sınırı yükseltilir.
const TASK_TOKENS = { dilekce_yaz: 2600, sozlesme_revize: 3000, dava_analiz: 1800 };
const modelOpts = (opts, task) => {
  const t = TASK_TOKENS[task]; if (!t) return opts;
  return opts.max_tokens ? { ...opts, max_tokens: t } : { ...opts, max_completion_tokens: Math.max(t, opts.max_completion_tokens || 0) };
};

function buildAI(task, text, extra, maxText) {
  const instruction = AI_TASKS[task];
  if (!instruction) throw new HttpError(400, "Bilinmeyen işlem.");
  let t = String(text || "").trim();
  if (t.length < 30) throw new HttpError(400, "Lütfen analiz edilecek metni girin (en az 30 karakter).");
  let note = "";
  if (t.length > maxText) {
    // Kararlarda gerekçe ve hüküm sondadır: başın %35'i + sonun %65'i alınır, ortadaki kısım atlanır.
    const head = Math.floor(maxText * 0.35), tail = maxText - head;
    t = t.slice(0, head) + "\n\n[... metnin orta kısmı uzunluk nedeniyle atlandı ...]\n\n" + t.slice(-tail);
    note = `Not: Metin uzun olduğu için başı ve sonu (gerekçe/hüküm) işlendi, orta kısmın bir bölümü atlandı (paket sınırı ${maxText.toLocaleString("tr-TR")} karakter).`;
  }
  const target = task === "ceviri" ? `\nHedef dil: ${String(extra || "İngilizce").slice(0, 40)}` : "";
  const messages = [
    { role: "system", content: AI_RULES },
    { role: "user", content: `${instruction}${target}\n\n--- METİN ---\n${t}` },
  ];
  return { messages, note };
}

// Maliyet ölçümü: her yapay zekâ işleminin boyutu Cloudflare günlüklerine (Observability) yazılır.
function logAI(model, task, messages, outChars, usage) {
  const inChars = messages.reduce((n, m) => n + String(m.content || "").length, 0);
  console.log(JSON.stringify({ ai: model.split("/").pop(), task, inChars, outChars, usage: usage || undefined }));
}

async function runAI(env, task, text, extra, maxText) {
  const { messages, note } = buildAI(task, text, extra, maxText);
  if (!env.AI) throw new HttpError(500, "Yapay zekâ bağlantısı (AI) tanımlı değil.");
  let lastErr = "";
  for (const { id: model, opts } of AI_MODELS) {
    try {
      const out = await env.AI.run(model, { messages, temperature: 0.2, ...modelOpts(opts, task) });
      const c = out && Array.isArray(out.choices) && out.choices[0];
      let answer = (out && out.response) || (c && ((c.message && c.message.content) || c.text)) || "";
      answer = String(answer).replace(/<think>[\s\S]*?<\/think>/g, "").trim();
      if (answer) { logAI(model, task, messages, answer.length, out && out.usage); return { answer, note }; }
      lastErr = "boş yanıt";
    } catch (e) { lastErr = String(e && e.message || e).slice(0, 200); console.error("AI", model, lastErr); }
  }
  throw new HttpError(502, "Yapay zekâ servisi şu an yanıt vermedi, biraz sonra tekrar deneyin. (" + lastErr + ")");
}


// Canlı yanıt: yapay zekânın yazdığı metin üretildikçe parça parça gönderilir.
async function streamAI(env, task, text, extra, maxText) {
  const { messages, note } = buildAI(task, text, extra, maxText);
  if (!env.AI) throw new HttpError(500, "Yapay zekâ bağlantısı (AI) tanımlı değil.");
  const dec = new TextDecoder();
  const pick = j => (j && (j.response ?? (j.choices && j.choices[0] && ((j.choices[0].delta && j.choices[0].delta.content) ?? j.choices[0].text)))) || "";
  let lastErr = "";
  for (const { id: model, opts } of AI_MODELS) {
    try {
      const src = await env.AI.run(model, { messages, temperature: 0.2, stream: true, ...modelOpts(opts, task) });
      if (!src || typeof src.getReader !== "function") throw new Error("akış desteklenmiyor");
      const reader = src.getReader();
      let buf = "", first = "", done = false;
      const parse = (chunkText, out) => {
        buf += chunkText; let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
          if (!line.startsWith("data:")) continue;
          const data = line.slice(5).trim();
          if (data === "[DONE]") { done = true; continue; }
          try { out.push(pick(JSON.parse(data))); } catch {}
        }
      };
      // İlk anlamlı parçayı bekle: model hiç yanıt vermezse sıradakine geç
      while (!first && !done) {
        const r = await reader.read(); if (r.done) break;
        const out = []; parse(dec.decode(r.value, { stream: true }), out); first += out.join("");
      }
      if (!first) { lastErr = "boş yanıt"; continue; }
      const enc2 = new TextEncoder();
      let outChars = first.length;
      const finish = c => { logAI(model, task, messages, outChars); c.close(); };
      const stream = new ReadableStream({
        start(c) { c.enqueue(enc2.encode(first)); },
        async pull(c) {
          // Bir parça metin bulana ya da akış bitene kadar oku (boş parçada durursa akış takılır).
          for (;;) {
            if (done) { finish(c); return; }
            const r = await reader.read();
            if (r.done) { finish(c); return; }
            const out = []; parse(dec.decode(r.value, { stream: true }), out);
            const t = out.join(""); if (t) { outChars += t.length; c.enqueue(enc2.encode(t)); return; }
          }
        },
        cancel() { try { reader.cancel(); } catch {} },
      });
      return { stream, note, model };
    } catch (e) { lastErr = String(e && e.message || e).slice(0, 200); console.error("AI stream", model, lastErr); }
  }
  throw new HttpError(502, "Yapay zekâ servisi şu an yanıt vermedi, biraz sonra tekrar deneyin. (" + lastErr + ")");
}

// ---------- e-posta (Gmail üzerinden, ek hesap gerektirmez) ----------
const mailReady = env => !!(env.GMAIL_USER && env.GMAIL_APP_PASSWORD);
const supportEmail = env => env.SUPPORT_EMAIL || env.GMAIL_USER || "yolhava.destek@gmail.com";
const b64utf8 = str => { const bytes = enc.encode(str); let bin = ""; for (const x of bytes) bin += String.fromCharCode(x); return btoa(bin); };

// Gmail SMTP (465, şifreli bağlantı). connectFn testte değiştirilebilsin diye parametre.
async function smtpSend(env, to, subject, html, connectFn = connect) {
  const user = String(env.GMAIL_USER).trim(), pass = String(env.GMAIL_APP_PASSWORD).replace(/\s+/g, "");
  const name = env.APP_NAME || "Hukuk Platformu";
  const sock = connectFn({ hostname: "smtp.gmail.com", port: 465 }, { secureTransport: "on" });
  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const readReply = async () => {
    // Çok satırlı yanıtlar "250-..." ile sürer, "250 ..." ile biter.
    for (;;) {
      const lines = buf.split("\r\n");
      for (let i = 0; i < lines.length - 1; i++) {
        if (/^\d{3} /.test(lines[i])) { buf = lines.slice(i + 1).join("\r\n"); return { code: +lines[i].slice(0, 3), text: lines.slice(0, i + 1).join(" ") }; }
      }
      const { value, done } = await reader.read();
      if (done) throw new Error("SMTP bağlantısı kapandı");
      buf += dec.decode(value, { stream: true });
    }
  };
  const cmd = async (line, okCodes) => {
    if (line !== null) await writer.write(enc.encode(line + "\r\n"));
    const r = await readReply();
    if (!okCodes.includes(r.code)) throw new Error(`SMTP ${r.code}: ${r.text.slice(0, 160)}`);
    return r;
  };
  try {
    await cmd(null, [220]);
    await cmd("EHLO hukuk-platformu", [250]);
    await cmd("AUTH LOGIN", [334]);
    await cmd(btoa(user), [334]);
    await cmd(btoa(pass), [235]);
    await cmd(`MAIL FROM:<${user}>`, [250]);
    await cmd(`RCPT TO:<${to}>`, [250, 251]);
    await cmd("DATA", [354]);
    const body64 = b64utf8(html).replace(/.{1,76}/g, "$&\r\n");
    const msg = [
      `From: =?UTF-8?B?${b64utf8(name)}?= <${user}>`,
      `To: <${to}>`,
      `Reply-To: <${supportEmail(env)}>`,
      `Subject: =?UTF-8?B?${b64utf8(subject)}?=`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${randomToken(12)}@hukuk-platformu>`,
      "MIME-Version: 1.0",
      "Content-Type: text/html; charset=UTF-8",
      "Content-Transfer-Encoding: base64",
      "",
      body64,
    ].join("\r\n");
    await cmd(msg + "\r\n.", [250]);
    try { await cmd("QUIT", [221]); } catch {}
    return true;
  } finally {
    try { reader.releaseLock(); writer.releaseLock(); await sock.close(); } catch {}
  }
}

async function sendMail(env, to, subject, html) {
  if (!mailReady(env)) return false;
  try { return await smtpSend(env, to, subject, html); }
  catch (e) { console.error("MAIL", String(e && e.message || e)); return false; }
}

function mailTemplate(env, title, inner) {
  const name = env.APP_NAME || "Hukuk Platformu";
  return `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#1d2433">
  <div style="background:#14213d;color:#fff;padding:16px 20px;border-radius:10px 10px 0 0;font-size:18px;font-weight:bold">⚖ ${name}</div>
  <div style="border:1px solid #e3e1da;border-top:0;padding:20px;border-radius:0 0 10px 10px">
  <h2 style="margin:0 0 12px;font-size:18px">${title}</h2>${inner}
  <p style="color:#5d6678;font-size:13px;margin-top:20px">Sorularınız için: ${supportEmail(env)}</p></div></div>`;
}

// ---------- Dilekçe Asistanı yardımcıları ----------
async function planQueries(env, tur, olay, talep) {
  const messages = [
    { role: "system", content: "Türk hukuku için karar arama ifadeleri üreten bir asistansın. Yalnızca istenen biçimde yanıt ver." },
    { role: "user", content: `Aşağıdaki dava için Yargıtay/Danıştay karar arama motorunda kullanılacak 3 kısa arama ifadesi yaz. Her ifade 2-5 kelime olsun, hukuki terim kullansın (ör. "fazla mesai ispat yükü"). Kişi adı, tarih, tutar yazma. Her satıra bir ifade yaz; başka hiçbir şey yazma.\n\nDava türü: ${tur || "-"}\nTalep: ${talep || "-"}\nOlay: ${olay}` },
  ];
  for (const { id: model, opts } of AI_MODELS) {
    try {
      const o = { ...opts }; if (o.max_tokens) o.max_tokens = 120; else o.max_completion_tokens = 400;
      const out = await env.AI.run(model, { messages, temperature: 0.1, ...o });
      const c = out && Array.isArray(out.choices) && out.choices[0];
      const text = String((out && out.response) || (c && ((c.message && c.message.content) || c.text)) || "").replace(/<think>[\s\S]*?<\/think>/g, "");
      const qs = text.split("\n").map(l => l.replace(/^[\s\d.)\-*•"“]+|["”\s]+$/g, "").trim())
        .filter(l => l.length >= 4 && l.length <= 80 && !/[:]$/.test(l)).slice(0, 3);
      logAI(model, "dilekce_plan", messages, text.length);
      if (qs.length) return qs;
    } catch (e) { console.error("AI plan", model, String(e && e.message || e).slice(0, 120)); }
  }
  return [];
}

// Dava türüne göre kararlarda geçen resmî terim (yapay zekâ terim bulamazsa yedek)
const TUR_TERIM = [
  [/ortaklığın gider|izale|şuyu|şüyu/, "ortaklığın giderilmesi"],
  [/mal rejimi|katılma alacağı|katkı payı alacağı/, "mal rejiminin tasfiyesi"],
  [/(kardeş|mirasçı|paydaş|hissedar|miras)[^.]{0,80}(paylaş|bölüş|satış)|(paylaş|bölüş)[^.]{0,80}(kardeş|mirasçı|paydaş|miras)/, "ortaklığın giderilmesi"],
  [/boşan/, "boşanma"], [/nafaka/, "nafaka"], [/velayet/, "velayet"],
  [/kira tespit|kira bedelinin tespit/, "kira tespiti"], [/tahliye/, "tahliye"], [/işe iade/, "işe iade"], [/kıdem/, "kıdem tazminatı"],
  [/itirazın iptal/, "itirazın iptali"], [/menfi tespit/, "menfi tespit"], [/muris muvaza|mirastan mal kaçır/, "muris muvazaası"], [/tapu iptal/, "tapu iptali"],
];
const terimFromText = t => { const l = trLower(t); for (const [re, x] of TUR_TERIM) if (re.test(l)) return x; return ""; };
async function aiText(env, messages, maxTokens) {
  for (const { id: model, opts } of AI_MODELS) {
    try {
      const o = { ...opts }; if (o.max_tokens) o.max_tokens = maxTokens; else o.max_completion_tokens = Math.max(maxTokens * 3, 600);
      const out = await env.AI.run(model, { messages, temperature: 0.1, ...o });
      const c = out && Array.isArray(out.choices) && out.choices[0];
      const text = String((out && out.response) || (c && ((c.message && c.message.content) || c.text)) || "").replace(/<think>[\s\S]*?<\/think>/g, "").trim();
      if (text) { logAI(model, "dilekce_ara", messages, text.length); return text; }
    } catch (e) { console.error("AI", model, String(e && e.message || e).slice(0, 120)); }
  }
  return "";
}
async function planSearch(env, tur, konu, olay, talep) {
  const text = await aiText(env, [
    { role: "system", content: "Türk yargı kararları veritabanında emsal karar aratan bir hukuk asistanısın. Yalnızca istenen biçimde yanıt verirsin." },
    { role: "user", content: `Aşağıdaki davanın hukuki adını ve emsal karar arama ifadelerini yaz.
TERİM: Davanın Yargıtay kararlarında geçen resmî adı (2-4 kelime). Örnekler: "ortaklığın giderilmesi" (izale-i şuyu, mirasçılar/kardeşler arasında ortak malın paylaşılması), "kıdem tazminatı", "kira tespiti", "tapu iptali ve tescil", "itirazın iptali", "muris muvazaası", "işe iade", "boşanma".
ARAMA: Bu davaya özgü 3 farklı arama ifadesi (her biri 2-5 kelime, hukuki terimlerle; ör. "ortaklığın giderilmesi satış", "ortaklığın giderilmesi aynen taksim", "paydaş muhdesat").
Kişi adı, tarih, tutar yazma. Biçim tam olarak şöyle olsun:
TERİM: ...
ARAMA: ...
ARAMA: ...
ARAMA: ...

Dava türü: ${tur || "-"}
Konu: ${konu || "-"}
Talep: ${talep || "-"}
Olay: ${olay}` },
  ], 160);
  const clean = l => l.replace(/^[\s\-*•"“]+|["”.\s]+$/g, "").trim();
  let terim = clean(((/TER[İI]M\s*:\s*(.+)/i.exec(text) || [])[1] || ""));
  const queries = [...text.matchAll(/ARAMA\s*:\s*(.+)/gi)].map(m => clean(m[1])).filter(x => x.length >= 4 && x.length <= 80).slice(0, 3);
  if (!terim || terim.split(/\s+/).length > 5) terim = terimFromText(`${tur} ${konu} ${olay}`) || terim;
  const fb = terimFromText(`${tur} ${konu} ${olay}`);
  if (fb && !trLower(terim).includes(trLower(fb))) terim = fb;          // açık terim eşleşmesi önceliklidir (ör. izale-i şuyu)
  return { terim, queries: queries.length ? queries : (terim ? [terim] : []) };
}
// Arşivden metinli satırlar (birkaç ayna denenir)
async function archiveRows(cfg, q, length) {
  for (const ds of ARCHIVE_MIRRORS) {
    try {
      const j = await hfGet("search", { dataset: ds, config: cfg, split: "train", offset: "0", length: String(length), query: q });
      return (j.rows || []).map(it => ({ ...archRow(cfg, it, ds), source: "arsiv" }));
    } catch (e) { if (e && e.timeout) break; }
  }
  return [];
}
const wordStems = s => [...new Set(trLower(s).split(/[^a-zçğıöşü0-9]+/).filter(w => w.length >= 4).map(w => w.slice(0, 6)))];
async function smartSearch(env, tur, p0, ctxt, max) {
  const cfg = /idari|vergi/i.test(tur) ? "danistay" : "yargitay";
  const qs = p0.queries.slice(0, 3);
  // 1) arşiv (paralel) — 2) resmî kaynak: terimle ara, ilk 6 kararın metnini al
  const archP = Promise.allSettled(qs.map(q => archiveRows(cfg, q, 30)));
  const offSrc = cfg === "danistay" ? "danistay" : "emsal";
  const offP = (async () => {
    try {
      const r = await searchOfficial(offSrc, p0.terim ? (/\s/.test(p0.terim) ? `"${p0.terim}"` : p0.terim) : qs[0], 1);
      const items = (r.items || []).filter(it => offSrc !== "emsal" || !/bölge adliye|ilk derece/i.test(it.daire)).slice(0, 6);
      const got = await Promise.allSettled(items.map(it => getDecision(env, offSrc, it.id, { ...it, q: p0.terim || qs[0] })));
      return got.map((g, i) => g.status === "fulfilled" && g.value && g.value.text ? { ...items[i], text: g.value.text, source: offSrc } : null).filter(Boolean);
    } catch { return []; }
  })();
  const [archS, off] = await Promise.all([archP, offP]);
  const seen = new Set(); const all = [];
  for (const c of [...off, ...archS.flatMap(x => x.status === "fulfilled" ? x.value : [])]) {
    const k = (c.esas && c.karar) ? `${trLower(c.daire)}|${c.esas}|${c.karar}` : c.source + c.id;
    if (seen.has(k) || !c.text) continue; seen.add(k); all.push(c);
  }
  // 3) puanlama: hukuki terim (zorunlu), arama kelimeleri, mahkeme düzeyi, güncellik
  const terim = trLower(p0.terim || "");
  const stems = wordStems(qs.join(" ") + " " + (ctxt.konu || ""));
  const scored = all.map(c => {
    const t = String(c.text); const low = trLower(t.length > 9000 ? t.slice(0, 3000) + " " + t.slice(-6000) : t);
    const hasTerm = terim ? low.includes(terim) : false;
    const termCount = terim ? Math.min(10, low.split(terim).length - 1) : 0;
    const hits = stems.filter(w => low.includes(w)).length;
    const lv = courtLevel(c.daire, t); const year = +((/(\d{4})/.exec(String(c.tarih || "")) || [])[1]) || 0;
    const score = (hasTerm ? 50 : 0) + termCount * 3 + hits * 4 + lv.rank * 2 + (year >= 2020 ? 4 : year >= 2015 ? 2 : 0);
    return { c, low, hasTerm, score, lv, year };
  });
  const withTerm = scored.filter(x => x.hasTerm);
  // Terimi içeren kararlar her zaman önce; yeterli değilse puana göre diğerleri eklenir
  const byScore = (a, b) => b.score - a.score;
  const pool = (withTerm.length >= 5 ? withTerm.sort(byScore) : [...withTerm.sort(byScore), ...scored.filter(x => !x.hasTerm).sort(byScore)]).slice(0, 15);
  // 4) yapay zekâ seçimi
  const brief = (x, i) => {
    const t = String(x.c.text); const tail = t.slice(-1400).replace(/\s+/g, " ");
    return `[${i + 1}] ${x.c.daire} E.${x.c.esas || "-"} K.${x.c.karar || "-"} (${x.c.tarih || "-"})\n${tail.slice(0, 650)}`;
  };
  let picks = [];
  if (pool.length) {
    const ans = await aiText(env, [
      { role: "system", content: "Sen Türk hukukunda emsal karar seçen bir asistansın. Yalnızca verilen kararlara bakarsın, uydurmazsın." },
      { role: "user", content: `AVUKATIN DAVASI\nDava türü: ${tur}\nKonu: ${ctxt.konu || "-"}\nTalep: ${ctxt.talep || "-"}\nOlay: ${ctxt.olay.slice(0, 1500)}\n\nAşağıdaki kararlardan bu davaya EMSAL olabilecek, yani aynı hukuki meseleyi içerenleri seç. Konusu farklı olanları (ör. başka dava türü) seçme.\nYanıt biçimi: her satırda "numara | neden ilgili (en fazla 15 kelime)". En ilgiliden başla, en fazla ${Math.min(max + 3, 12)} karar. İlgili karar yoksa yalnızca YOK yaz.\n\n${pool.map(brief).join("\n\n")}` },
    ], 500);
    const used = new Set();
    for (const m of ans.matchAll(/^\s*\[?(\d{1,2})\]?\s*[|:\-–)]\s*(.+)$/gm)) {
      const i = +m[1] - 1; if (i >= 0 && i < pool.length && !used.has(i)) { used.add(i); picks.push({ i, neden: m[2].trim().slice(0, 160) }); }
    }
    if (!picks.length && !/\bYOK\b/.test(ans)) picks = pool.slice(0, max).map((x, i) => ({ i, neden: "" }));   // yapay zekâ yanıt vermezse puan sırası
  }
  // Güvenlik: konuyu (terimi) içeren karar varsa otomatik seçime yalnızca onlar girer; diğerleri "aday" olarak kalır
  if (withTerm.length) picks = picks.filter(p => pool[p.i].hasTerm);
  if (!picks.length && withTerm.length) picks = pool.map((x, i) => ({ i, neden: "" })).filter(p => pool[p.i].hasTerm).slice(0, max);
  const pickedIdx = new Map(picks.map((p, rank) => [p.i, { ...p, rank }]));
  const out = pool.map((x, i) => {
    const pk = pickedIdx.get(i);
    const { text, ...meta } = x.c;
    return { source: x.c.source, item: { id: meta.id, daire: meta.daire, esas: meta.esas, karar: meta.karar, tarih: meta.tarih, dataset: meta.dataset },
      score: x.score, hasTerm: x.hasTerm, level: x.lv.label, outcome: decisionOutcome(text).label,
      ai: pk ? pk.neden : null, rank: pk ? pk.rank : 99, selected: !!pk && pk.rank < max };
  }).sort((a, b) => a.rank - b.rank || b.score - a.score);
  return { scanned: all.length, withTerm: withTerm.length, candidates: out, aiUsed: picks.length > 0 };
}

// Mahkeme düzeyi: yüksek değer = daha güçlü kaynak
function courtLevel(daire, text) {
  const d = trLower(daire), head = trLower(String(text || "").slice(0, 1500));
  if (/içtihatları birleştirme|ictihatlari birlestirme/.test(d + " " + head)) return { rank: 5, label: "İçtihadı Birleştirme" };
  if (/genel kurul/.test(d)) return { rank: 4, label: "Genel Kurul" };
  if (/anayasa mahkemesi|aym/.test(d)) return { rank: 4, label: "Anayasa Mahkemesi" };
  if (/bölge adliye|bölge idare|istinaf/.test(d)) return { rank: 2, label: "Bölge Adliye / İstinaf" };
  if (/daire/.test(d)) return { rank: 3, label: "Yüksek Mahkeme Dairesi" };
  if (/mahkemesi/.test(d)) return { rank: 1, label: "İlk Derece" };
  return { rank: 3, label: "Yüksek Mahkeme" };
}
// Hüküm kısmından sonucu çıkar (son 2.500 karakterde, sona en yakın ifade esas alınır)
const OUTCOMES = [
  ["ihlal_yok", /ihlal\s+edilmediğine/g, "İhlal yok"],
  ["ihlal", /ihlal\s+edildiğine/g, "İhlal"],
  ["bozma", /bozulmasına|bozmaya/g, "Bozma"],
  ["onama", /onanmasına|onamaya/g, "Onama"],
  ["kaldirma", /kaldırılmasına/g, "Kaldırma"],
  ["ret", /reddine|reddedilmesine/g, "Ret"],
  ["kabul", /kabulüne|kabulü ile/g, "Kabul"],
];
function decisionOutcome(text) {
  const tail = trLower(String(text || "").slice(-2500));
  let best = { key: "belirsiz", label: "Belirlenemedi", pos: -1 };
  for (const [key, re, label] of OUTCOMES) {
    for (const m of tail.matchAll(re)) if (m.index > best.pos) best = { key, label, pos: m.index };
  }
  if (best.key === "onama" && /düzeltilerek\s+onanmasına/.test(tail)) best.label = "Düzelterek onama";
  if (best.key === "bozma" && /kısmen/.test(tail.slice(Math.max(0, best.pos - 80), best.pos + 40))) best.label = "Kısmen bozma";
  return { key: best.key, label: best.label };
}
function decisionFacts(d, ref) {
  const text = String(d.text || "");
  const year = +((/(\d{4})/.exec(String(d.tarih || "")) || /(\d{4})\s*\//.exec(String(d.karar || "")) || [])[1]) || null;
  const kunye = [d.daire, d.esas && "E. " + d.esas, d.karar && "K. " + d.karar, d.tarih && "T. " + d.tarih].filter(Boolean).join(", ");
  // Gerekçe ve hüküm sondadır: baştan kısa giriş + sondan 2.200 karakter
  const excerpt = text.length > 3000 ? text.slice(0, 500).trim() + "\n[...]\n" + text.slice(-2200).trim() : text.trim();
  return { ok: true, ref, kunye, daire: d.daire || "", esas: d.esas || "", karar: d.karar || "", tarih: d.tarih || "",
           year, level: courtLevel(d.daire, text), outcome: decisionOutcome(text), excerpt, chars: text.length };
}

// ---------- mevzuat (Mevzuat Bilgi Sistemi) ----------
const MEVZUAT_BASE = "https://www.mevzuat.gov.tr";
const MEVZUAT_TERTIPS = [5, 4, 3, 2, 1];     // hangi tertipte olduğu bilinmiyorsa sırayla denenir
const mevzuatPage = (no, tur, tertip) => `${MEVZUAT_BASE}/mevzuat?MevzuatNo=${no}&MevzuatTur=${tur}&MevzuatTertip=${tertip}`;

// tur: Mevzuat Bilgi Sistemi'nin tür kodu (1 = Kanun; diğerleri kullanıcının yapıştırdığı mevzuat.gov.tr bağlantısından gelir)
async function getMevzuat(no, tur, tertipHint, ctx) {
  const cache = caches.default;
  const key = new Request(`https://cache.hukuk.local/mevzuat/${tur}/${no}`);
  const hit = await cache.match(key);
  if (hit) return hit;
  const tertips = tertipHint ? [tertipHint, ...MEVZUAT_TERTIPS.filter(t => t !== tertipHint)] : MEVZUAT_TERTIPS;
  let lastErr = "";
  for (const tertip of tertips) {
    const src = `${MEVZUAT_BASE}/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=${tur}&MevzuatNo=${no}&MevzuatTertip=${tertip}`;
    let res;
    try {
      res = await fetch(src, { headers: { "User-Agent": UA, "Accept": "text/html", "Accept-Language": "tr-TR,tr;q=0.9" },
                               signal: AbortSignal.timeout(20000) });
    } catch (e) { lastErr = "bağlantı kurulamadı"; continue; }
    if (!res.ok) { lastErr = `HTTP ${res.status}`; if (res.status >= 500) break; continue; }
    const buf = await res.arrayBuffer();
    const probe = new TextDecoder("latin1").decode(buf.slice(0, Math.min(buf.byteLength, 400000)));
    if (buf.byteLength < 1500 || !/madde\s*1\b/i.test(probe)) { lastErr = "metin bulunamadı"; continue; }
    const ct = res.headers.get("Content-Type") || "text/html";
    const out = new Response(buf, { headers: {
      "Content-Type": "text/html; charset=" + ((/charset=([\w-]+)/i.exec(ct) || [])[1] || "utf-8"),
      "Cache-Control": "public, max-age=86400",
      "X-Mevzuat-Url": mevzuatPage(no, tur, tertip),
    } });
    ctx.waitUntil(cache.put(key, out.clone()));
    return out;
  }
  const err = new HttpError(502, lastErr === "metin bulunamadı"
    ? `Bu numarayla bir metin Mevzuat Bilgi Sistemi'nde bulunamadı. Numarayı kontrol edin veya mevzuat.gov.tr'deki bağlantıyı yapıştırın.`
    : `Mevzuat Bilgi Sistemi'ne şu an ulaşılamadı (${lastErr}). Biraz sonra tekrar deneyin.`);
  err.officialUrl = mevzuatPage(no, tur, tertipHint || 5);
  throw err;
}

// ---------- yönlendirme ----------
async function route(req, env, ctx) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");

  if (path === "/api/health") return { ok: true, app: env.APP_NAME || "Hukuk Platformu", time: now() };

  if (path === "/api/plans") return { plans: PLANS };

  if (path === "/api/register" && req.method === "POST") {
    const b = await body(req);
    const email = cleanEmail(b.email);
    const password = checkPassword(b.password);
    const name = String(b.name || "").trim().slice(0, 100);
    if (!b.acceptTerms) throw new HttpError(400, "Devam etmek için Kullanım Koşulları ve KVKK Aydınlatma Metni'ni onaylamalısınız.");
    const exists = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
    if (exists) throw new HttpError(409, "Bu e-posta ile zaten bir hesap var. Giriş yapın veya şifrenizi sıfırlayın.");
    const salt = newSalt();
    const hash = await hashPassword(password, salt, PBKDF2_ITER);
    const t = now();
    const r = await env.DB.prepare(
      "INSERT INTO users (email, name, pass_hash, pass_salt, pass_iter, plan, trial_until, terms_accepted_at, created_at) VALUES (?,?,?,?,?,'basic',?,?,?)"
    ).bind(email, name, hash, salt, PBKDF2_ITER, t + TRIAL_HOURS * 3600, t, t).run();
    const userId = r.meta.last_row_id;
    const token = await createSession(env, userId);
    const user = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(userId).first();
    return { token, user: publicUser(user) };
  }

  if (path === "/api/login" && req.method === "POST") {
    const b = await body(req);
    const email = cleanEmail(b.email);
    const password = String(b.password || "");
    const u = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    const fail = new HttpError(401, "E-posta veya şifre hatalı.");
    if (!u) { await hashPassword(password, newSalt(), PBKDF2_ITER); throw fail; } // zamanlama farkını gizle
    // Şifre tahmin saldırısına karşı: 15 dakikada en fazla 10 hatalı deneme
    const slot = "lf" + Math.floor((Date.now() / 60000) / 15);
    const tries = await env.DB.prepare("SELECT n FROM usage WHERE user_id=? AND day=? AND kind=?").bind(u.id, today(), slot).first();
    if (tries && tries.n >= 10) throw new HttpError(429, "Çok fazla hatalı deneme yapıldı. Güvenliğiniz için 15 dakika sonra tekrar deneyin veya şifrenizi sıfırlayın.");
    const h = await hashPassword(password, u.pass_salt, u.pass_iter);
    if (!safeEqual(h, u.pass_hash)) {
      await env.DB.prepare("INSERT INTO usage (user_id, day, kind, n) VALUES (?,?,?,1) ON CONFLICT(user_id, day, kind) DO UPDATE SET n = n + 1").bind(u.id, today(), slot).run();
      throw fail;
    }
    // Saklama süreleri (KVKK metninde yazdığı gibi): süresi dolan oturumlar, 90 günden eski sayaçlar, kullanılmış sıfırlama bağlantıları
    const cutoff = new Date(Date.now() + 3 * 3600e3 - 90 * 86400e3).toISOString().slice(0, 10);
    ctx.waitUntil(env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now()),
      env.DB.prepare("DELETE FROM usage WHERE day < ?").bind(cutoff),
      env.DB.prepare("DELETE FROM resets WHERE expires_at < ?").bind(now()),
    ]).catch(e => console.error("cleanup", String(e && e.message || e))));
    return { token: await createSession(env, u.id), user: publicUser(u) };
  }

  if (path === "/api/logout" && req.method === "POST") {
    const h = req.headers.get("Authorization") || "";
    if (h.startsWith("Bearer ")) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(h.slice(7).trim())).run();
    return { ok: true };
  }

  if (path === "/api/forgot" && req.method === "POST") {
    const b = await body(req);
    const email = cleanEmail(b.email);
    const manual = `Şifre sıfırlama için lütfen kayıtlı e-posta adresinizi belirterek ${supportEmail(env)} adresine yazın; şifreniz kısa sürede sıfırlanır.`;
    if (!mailReady(env)) throw new HttpError(503, manual);
    const u = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
    const generic = { ok: true, message: "Bu e-posta kayıtlıysa şifre sıfırlama bağlantısı gönderildi. Gelen kutunuzu ve spam (istenmeyen) klasörünü kontrol edin." };
    if (!u) return generic;
    // Aynı hesaba günde en fazla 5 sıfırlama e-postası (kötüye kullanım ve Gmail sınırı için)
    const sent5 = await env.DB.prepare("SELECT n FROM usage WHERE user_id=? AND day=? AND kind='fg'").bind(u.id, today()).first();
    if (sent5 && sent5.n >= 5) return generic;
    await env.DB.prepare("INSERT INTO usage (user_id, day, kind, n) VALUES (?,?,'fg',1) ON CONFLICT(user_id, day, kind) DO UPDATE SET n = n + 1").bind(u.id, today()).run();
    const token = randomToken();
    await env.DB.prepare("INSERT INTO resets (token_hash, user_id, expires_at) VALUES (?,?,?)")
      .bind(await sha256(token), u.id, now() + RESET_MINUTES * 60).run();
    const base = (env.APP_URL || "").replace(/#.*$/, "");
    const link = `${base}#sifirla=${token}`;
    const sent = await sendMail(env, email, `${env.APP_NAME || "Hukuk Platformu"} — şifre sıfırlama`, mailTemplate(env, "Şifre sıfırlama",
      `<p>Merhaba,</p><p>Şifrenizi sıfırlamak için aşağıdaki düğmeye <b>${RESET_MINUTES} dakika içinde</b> dokunun:</p>
       <p style="margin:20px 0"><a href="${link}" style="background:#c9a24b;color:#14213d;padding:12px 18px;border-radius:8px;text-decoration:none;font-weight:bold">Yeni şifre belirle</a></p>
       <p style="font-size:13px;color:#5d6678">Düğme çalışmazsa bu adresi tarayıcınıza yapıştırın:<br>${link}</p>
       <p>Bu isteği siz yapmadıysanız bu e-postayı yok sayabilirsiniz; şifreniz değişmez.</p>`));
    if (!sent) throw new HttpError(503, manual);
    return generic;
  }

  if (path === "/api/reset" && req.method === "POST") {
    const b = await body(req);
    const password = checkPassword(b.password);
    const th = await sha256(String(b.token || ""));
    const r = await env.DB.prepare("SELECT * FROM resets WHERE token_hash=? AND used=0 AND expires_at > ?").bind(th, now()).first();
    if (!r) throw new HttpError(400, "Bağlantı geçersiz veya süresi dolmuş. Yeniden şifre sıfırlama isteyin.");
    const salt = newSalt();
    const hash = await hashPassword(password, salt, PBKDF2_ITER);
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET pass_hash=?, pass_salt=?, pass_iter=? WHERE id=?").bind(hash, salt, PBKDF2_ITER, r.user_id),
      env.DB.prepare("UPDATE resets SET used=1 WHERE token_hash=?").bind(th),
      env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(r.user_id),
    ]);
    return { ok: true, message: "Şifreniz güncellendi. Yeni şifrenizle giriş yapabilirsiniz." };
  }

  // ---- aşağıdakiler giriş gerektirir ----
  const user = await currentUser(req, env);

  if (path === "/api/me") {
    const rows = await env.DB.prepare("SELECT kind, n FROM usage WHERE user_id=? AND day=?").bind(user.id, today()).all();
    const used = Object.fromEntries((rows.results || []).map(r => [r.kind, r.n]));
    const plan = effectivePlan(user);
    return { user: publicUser(user), usage: { search: used.search || 0, ai: used.ai || 0 }, limits: PLANS[plan] };
  }

  if (path === "/api/search" && req.method === "POST") {
    const b = await body(req);
    const src = String(b.source || "yargitay");
    // Arşiv, UYAP aramasının yanında eşlik ederek çalışıyorsa ikinci kez hak düşülmez.
    const quota = b.paired && src === "arsiv" ? await useQuota(env, user, "search", false) : await useQuota(env, user, "search");
    const result = src === "arsiv" ? await searchArchive(env, b.q, b.page, String(b.config || "yargitay"))
                                   : await searchOfficial(src, b.q, b.page);
    return { ...result, quota };
  }

  if (path === "/api/decision" && req.method === "POST") {
    const b = await body(req);
    const src = String(b.source || "");
    return { decision: src === "arsiv" ? await getArchiveDecision(env, b.id, b.hint) : await getDecision(env, src, b.id, b.hint) };
  }

  // ---- Dilekçe Asistanı ----
  // 1) Olaydan arama ifadeleri çıkarır (kısa yapay zekâ çağrısı; günlük hak düşmez, paket kontrolü yapılır)
  if (path === "/api/dilekce/plan" && req.method === "POST") {
    const b = await body(req);
    const plan = effectivePlan(user);
    if (!PLANS[plan].tasks.includes("dilekce_yaz")) throw new HttpError(403, "Dilekçe Asistanı Optimus ve üzeri paketlerde kullanılabilir.");
    await useQuota(env, user, "ai", false);
    const olay = String(b.olay || "").trim().slice(0, 4000);
    if (olay.length < 30) throw new HttpError(400, "Lütfen olayı biraz daha ayrıntılı yazın (en az 30 karakter).");
    return { queries: await planQueries(env, String(b.tur || "").slice(0, 80), olay, String(b.talep || "").slice(0, 1000)) };
  }
  // 1b) Akıllı arama: hukuki terim + arama ifadeleri → arşiv ve resmî kaynak taraması → terim filtresi → puanlama
  //     → yapay zekâ adayları okuyup davaya emsal olabilecekleri seçer (1 yapay zekâ hakkı)
  if (path === "/api/dilekce/ara" && req.method === "POST") {
    const b = await body(req);
    const plan = effectivePlan(user);
    const max = PLANS[plan].refs || 0;
    if (!max) throw new HttpError(403, "Dilekçe Asistanı Optimus ve üzeri paketlerde kullanılabilir.");
    await useQuota(env, user, "ai", false);
    const tur = String(b.tur || "").slice(0, 120), konu = String(b.konu || "").slice(0, 300);
    const olay = String(b.olay || "").trim().slice(0, 4000), talep = String(b.talep || "").slice(0, 1000);
    if (olay.length < 30) throw new HttpError(400, "Lütfen olayı biraz daha ayrıntılı yazın (en az 30 karakter).");
    let p0 = { terim: String(b.terim || "").trim().slice(0, 80), queries: (Array.isArray(b.queries) ? b.queries : []).map(x => String(x).trim().slice(0, 100)).filter(x => x.length >= 3).slice(0, 3) };
    if (!p0.terim || !p0.queries.length) {
      const g = await planSearch(env, tur, konu, olay, talep);
      p0 = { terim: p0.terim || g.terim, queries: p0.queries.length ? p0.queries : g.queries };
    }
    if (!p0.queries.length) p0.queries = [p0.terim || konu || tur.split(" (")[0]].filter(Boolean);
    const r = await smartSearch(env, tur, p0, { olay, talep, konu }, max);
    await useQuota(env, user, "ai");
    return { terim: p0.terim, queries: p0.queries, ...r };
  }
  // 2) Avukatın seçtiği kararların metnini getirir, sonucu (onama/bozma…) ve mahkeme düzeyini bilgisayarla çıkarır
  if (path === "/api/dilekce/kaynak" && req.method === "POST") {
    const b = await body(req);
    const plan = effectivePlan(user);
    const max = PLANS[plan].refs || 0;
    if (!max) throw new HttpError(403, "Dilekçe Asistanı Optimus ve üzeri paketlerde kullanılabilir.");
    const refs = (Array.isArray(b.refs) ? b.refs : []).slice(0, max);
    if (!refs.length) throw new HttpError(400, "En az bir karar seçin.");
    const got = await Promise.allSettled(refs.map(r => String(r.source) === "arsiv"
      ? getArchiveDecision(env, r.id, r.hint) : getDecision(env, String(r.source || ""), r.id, r.hint)));
    const items = got.map((g, i) => g.status === "fulfilled" ? decisionFacts(g.value, refs[i]) : { ok: false, ref: refs[i], error: "Karar metni alınamadı." });
    const ok = items.filter(x => x.ok);
    const count = k => ok.filter(x => x.outcome.key === k).length;
    const ozet = { toplam: ok.length, alinamayan: items.length - ok.length,
      onama: count("onama"), bozma: count("bozma"), kaldirma: count("kaldirma"), kabul: count("kabul"), ret: count("ret"),
      ihlal: count("ihlal"), ihlalYok: count("ihlal_yok"), belirsiz: count("belirsiz"),
      ibkGk: ok.filter(x => x.level.rank >= 4).length, enYeni: ok.reduce((m, x) => Math.max(m, x.year || 0), 0) || null };
    return { items, ozet };
  }

  // Mevzuat Bilgi Sistemi'nden güncel kanun metni (yalnızca mevzuat.gov.tr; açık vekil sunucu değildir).
  // Metin olduğu gibi aktarılır, madde ayrıştırması tarayıcıda yapılır (sunucu işlemci süresi harcanmaz).
  if (path === "/api/mevzuat" && req.method === "POST") {
    const b = await body(req);
    const no = String(b.no || "").trim();
    const tur = String(b.tur || "1").trim();
    const tertip = Number(b.tertip) || 0;
    if (!/^\d{1,7}$/.test(no)) throw new HttpError(400, "Geçerli bir mevzuat numarası girin (ör. 6098).");
    if (!/^\d{1,2}$/.test(tur)) throw new HttpError(400, "Geçersiz mevzuat türü.");
    if (tertip && !(tertip >= 1 && tertip <= 9)) throw new HttpError(400, "Geçersiz tertip.");
    await useQuota(env, user, "search", false);
    const r = await getMevzuat(no, tur, tertip, ctx);
    const quota = await useQuota(env, user, "search");
    const h = new Headers(r.headers);
    h.set("X-Quota-Used", String(quota.used)); h.set("X-Quota-Limit", String(quota.limit));
    return new Response(r.body, { headers: h });
  }

  if (path === "/api/ai-stream" && req.method === "POST") {
    const b = await body(req);
    const plan = effectivePlan(user);
    const task = String(b.task || "");
    if (AI_TASKS[task] && !PLANS[plan].tasks.includes(task)) {
      const need = PLANS.optimus.tasks.includes(task) ? "Optimus" : "Maximus";
      throw new HttpError(403, `Bu araç ${need} ve üzeri paketlerde kullanılabilir.`);
    }
    await useQuota(env, user, "ai", false);
    const r = await streamAI(env, task, b.text, b.extra, PLANS[plan].maxText);
    const quota = await useQuota(env, user, "ai");      // yanıt başladıysa hak düşülür
    return new Response(r.stream, { headers: {
      "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store",
      "X-Note": encodeURIComponent(r.note || ""), "X-Quota-Used": String(quota.used), "X-Quota-Limit": String(quota.limit),
    } });
  }

  if (path === "/api/ai" && req.method === "POST") {
    const b = await body(req);
    const plan = effectivePlan(user);
    const task = String(b.task || "");
    if (AI_TASKS[task] && !PLANS[plan].tasks.includes(task)) {
      const need = PLANS.optimus.tasks.includes(task) ? "Optimus" : "Maximus";
      throw new HttpError(403, `Bu araç ${need} ve üzeri paketlerde kullanılabilir.`);
    }
    await useQuota(env, user, "ai", false);            // önce sadece hak kontrolü
    const r = await runAI(env, String(b.task || ""), b.text, b.extra, PLANS[plan].maxText);
    const quota = await useQuota(env, user, "ai");     // başarılı olunca hak düşülür
    return { ...r, quota };
  }

  if (path === "/api/account/delete" && req.method === "POST") {
    const b = await body(req);
    const h = await hashPassword(String(b.password || ""), user.pass_salt, user.pass_iter);
    if (!safeEqual(h, user.pass_hash)) throw new HttpError(401, "Şifre hatalı.");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(user.id),
      env.DB.prepare("DELETE FROM resets WHERE user_id=?").bind(user.id),
      env.DB.prepare("DELETE FROM usage WHERE user_id=?").bind(user.id),
      env.DB.prepare("DELETE FROM users WHERE id=?").bind(user.id),
    ]);
    return { ok: true, message: "Hesabınız ve kişisel verileriniz silindi." };
  }

  if (path === "/api/account/password" && req.method === "POST") {
    const b = await body(req);
    const cur = await hashPassword(String(b.current || ""), user.pass_salt, user.pass_iter);
    if (!safeEqual(cur, user.pass_hash)) throw new HttpError(401, "Mevcut şifre hatalı.");
    const password = checkPassword(b.password);
    const salt = newSalt();
    await env.DB.prepare("UPDATE users SET pass_hash=?, pass_salt=?, pass_iter=? WHERE id=?")
      .bind(await hashPassword(password, salt, PBKDF2_ITER), salt, PBKDF2_ITER, user.id).run();
    return { ok: true, message: "Şifreniz güncellendi." };
  }

  // Yönetici: unutulan şifreyi geçici şifreyle sıfırlama
  if (path === "/api/admin/reset-password" && req.method === "POST") {
    if (!user.is_admin) throw new HttpError(403, "Yetkiniz yok.");
    const b = await body(req);
    const email = cleanEmail(b.email);
    const target = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
    if (!target) throw new HttpError(404, "Kullanıcı bulunamadı.");
    const abc = "abcdefghjkmnpqrstuvwxyz23456789"; const rnd = new Uint8Array(10); crypto.getRandomValues(rnd);
    const temp = [...rnd].map(x => abc[x % abc.length]).join("");
    const salt = newSalt();
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET pass_hash=?, pass_salt=?, pass_iter=? WHERE id=?").bind(await hashPassword(temp, salt, PBKDF2_ITER), salt, PBKDF2_ITER, target.id),
      env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(target.id),
    ]);
    const base = (env.APP_URL || "").replace(/#.*$/, "");
    const subject = `${env.APP_NAME || "Hukuk Platformu"} — geçici şifreniz`;
    const sent = await sendMail(env, email, subject, mailTemplate(env, "Şifreniz sıfırlandı",
      `<p>Merhaba,</p><p>Talebiniz üzerine şifreniz sıfırlandı. Geçici şifreniz:</p>
       <p style="font-size:22px;font-weight:bold;letter-spacing:2px;background:#f4ead3;padding:12px;border-radius:8px;text-align:center">${temp}</p>
       <p>Bu şifreyle <a href="${base}#/giris">giriş yapın</a>, ardından <b>Hesabım → Şifremi değiştir</b> bölümünden kendi şifrenizi belirleyin.</p>`));
    if (sent) return { ok: true, emailed: true, message: `Geçici şifre ${email} adresine e-postayla gönderildi.` };
    return { ok: true, emailed: false, tempPassword: temp, email, subject,
      message: `Otomatik e-posta henüz kurulu değil. Geçici şifre: ${temp} — açılan e-posta taslağını kullanıcıya gönderin.` };
  }

  // Yönetici: kullanıcının paketini elle ayarlama (ödeme sistemi açılana kadar)
  if (path === "/api/admin/set-plan" && req.method === "POST") {
    if (!user.is_admin) throw new HttpError(403, "Yetkiniz yok.");
    const b = await body(req);
    const email = cleanEmail(b.email);
    const plan = String(b.plan || "");
    if (!PLANS[plan]) throw new HttpError(400, "Geçersiz paket.");
    const days = Math.max(1, Math.min(parseInt(b.days) || 30, 400));
    const r = await env.DB.prepare("UPDATE users SET plan=?, plan_until=? WHERE email=?").bind(plan, now() + days * 86400, email).run();
    if (!r.meta.changes) throw new HttpError(404, "Kullanıcı bulunamadı.");
    return { ok: true, message: `${email} → ${PLANS[plan].label}, ${days} gün.` };
  }

  throw new HttpError(404, "Bulunamadı.");
}

export default {
  async fetch(req, env, ctx) {
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      if (!env.DB) throw new HttpError(500, "Veritabanı bağlantısı (DB) tanımlı değil.");
      const out = await route(req, env, ctx);
      if (out instanceof Response) {
        const h = new Headers(out.headers);
        for (const [k, v] of Object.entries(cors)) h.set(k, v);
        h.set("Access-Control-Expose-Headers", "X-Note, X-Quota-Used, X-Quota-Limit, X-Mevzuat-Url");
        return new Response(out.body, { status: out.status, headers: h });
      }
      return json(out, 200, cors);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      const message = e instanceof HttpError ? e.message : "Beklenmeyen bir hata oluştu.";
      if (!(e instanceof HttpError)) console.error(e && e.stack || e);
      return json({ error: message, ...(e && e.officialUrl ? { officialUrl: e.officialUrl } : {}) }, status, cors);
    }
  },
};

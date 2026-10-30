"""Kurul kararlarını toplar (Hukuk Platformu).
- Sigorta Tahkim Komisyonu: Hakem Kararları Dergisi sayılarını (karardrgsN.pdf) indirir, kararlara ayırır,
  kurul/stk/NNN.json olarak yazar. Daha önce işlenen sayılar atlanır; her ay yeni sayılar eklenir.
- Rekabet Kurulu: karar listesinden PDF'leri indirir, kurul/rekabet/NNNN.json (en çok 25 karar) olarak yazar; her çalışmada sınırlı sayıda (arşiv birkaç çalışmada tamamlanır).
- KVKK: kurul kararları, karar özetleri ve ilke kararları (kurul/kvkk/NNNN.json).
- Uyuşmazlık Mahkemesi: şimdilik yalnızca sayfa yapısını kaydeder (kurul/_kesif/), ayrıştırıcı sonra eklenecek.
Kararlar kamuya açık resmî metinlerdir; kişi bilgileri yayımlayan kurumca gizlenmiştir."""
from __future__ import annotations
import hashlib, html as htmlmod, json, os, re, subprocess, sys, tempfile, time, urllib.request, urllib.error

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "kurul")
UA = {"User-Agent": "Mozilla/5.0 (HukukPlatformu kurul-kararlari; iletisim yolhava.destek@gmail.com)"}
STK_URLS = ["https://www.sigortatahkim.org/content/CmsFiles/karardrgs{n}.pdf",
            "https://sigortatahkim.org/content/CmsFiles/karardrgs{n}.pdf"]
MAX_SAYI = int(os.environ.get("MAX_SAYI", "150"))
YENIDEN = os.environ.get("YENIDEN", "") == "1"   # tüm sayıları baştan işle


def get(url, timeout=60, deneme=3):
    """İndirir; geçici hatalarda (zaman aşımı, 429, 5xx) artan beklemeyle tekrar dener. 404/403 hemen döner."""
    for i in range(deneme):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(), r.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            if e.code in (403, 404) or i == deneme - 1: raise
            time.sleep(15 * (i + 1) if e.code == 429 else 5 * (i + 1))
        except Exception:
            if i == deneme - 1: raise
            time.sleep(5 * (i + 1))


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


NUM = r"(K\s*[-.]?\s*\d{4}\s*[-/]\s*\d+|\d{4}\s*/\s*\d+(?=\s)|\d{4}\s*/\s*[İI]HK\s*[-./]?\s*\d+|[İI]HK\s*[-./]\s*\d+)"
# Karar başlığı: satır tarihle başlar, karar numarasıyla sürer ve "... Kararı" (isteğe bağlı parantezli konu) ile biter.
HDR = re.compile(r"^[ \t\f]*(\d{2}[/.]\d{2}[/.]\d{4})\s+Tarih\w*\s*(?:ve\s+|[-–—]\s*)?" + NUM +
                 r"\s+(?:Sayılı\s+)?((?:Uyuşmazlık\s+)?(?:[İi]tiraz\s+)?(?:Hakem\s+)?(?:Heyeti\s+)?Karar\w*)\.?[ \t]*(\([^)\n]*\)?)?[ \t]*$", re.I | re.M)
TOCNUM = re.compile(r"\d{2}[/.]\d{2}[/.]\d{4}\s+Tarih\w*\s*(?:ve\s+|[-–—]\s*)?" + NUM, re.I)
SEC = re.compile(r"^[\f ]*(I|II|III|IV|V|VI|VII)\.\s+(.+?)(?:\.{3,}.*)?$", re.M)


def norm_no(x):
    x = re.sub(r"\s+", "", x).replace("I", "İ") if "HK" in x.upper() else re.sub(r"\s+", "", x)
    m = re.match(r"K[-.]?(\d{4})[-/](\d+)$", x, re.I) or re.match(r"(\d{4})/(\d+)$", x)
    if m: return f"K-{m.group(1)}/{m.group(2)}"
    m = re.match(r"(\d{4})/İHK[-./]?(\d+)$", x)
    if m: return f"{m.group(1)}/İHK-{m.group(2)}"
    m = re.match(r"İHK[-./](\d+)$", x)
    if m: return f"İHK-{m.group(1)}"
    return x


def fold(s):
    """Arama için sadeleştirme (sunucudaki foldTr ile aynı): Türkçe küçük harf, aksansız."""
    s = str(s or "").replace("İ", "i").replace("I", "ı").lower()
    for a, b in (("ı", "i"), ("ş", "s"), ("ğ", "g"), ("ç", "c"), ("ö", "o"), ("ü", "u"), ("â", "a"), ("à", "a"), ("î", "i"), ("ì", "i"), ("û", "u"), ("ù", "u")):
        s = s.replace(a, b)
    return s


def kategori_kisa(k):
    k = k.upper()
    if "İTİRAZ" in k: return "İtiraz Hakem Heyeti"
    if "KASKO" in k: return "Kasko"
    if "TRAFİK" in k or "ZORUNLU MALİ" in k: return "Trafik"
    if "DİĞER" in k: return "Diğer sigortalar"
    return k.title()[:40]


def stk_bol(t, sayi):
    # İçindekiler: metnin ilk %40'ındaki son nokta-dizili satıra kadar; oradaki karar numaraları geçerli başlık listesidir.
    lim = int(len(t) * 0.4)
    dots = [m.end() for m in re.finditer(r"\.{5,}[^\n]*", t[:lim]) if TOCNUM.search(t, max(0, m.start() - 300), m.start())]
    toc_end = t.find("\n", dots[-1]) if dots else 0
    toc_end = toc_end if toc_end > 0 else 0
    toc = {norm_no(m.group(1)) for m in TOCNUM.finditer(t[:toc_end])}
    items, seen = [], set()
    for m in HDR.finditer(t, toc_end):
        if "....." in m.group(0): continue
        no = norm_no(m.group(2))
        if no in seen or (toc and no not in toc): continue     # yalnızca içindekilerde olan numara, ilk geçtiği yerde
        seen.add(no); items.append((m, no))
    out = []
    for i, (m, no) in enumerate(items):
        end = items[i + 1][0].start() if i + 1 < len(items) else len(t)
        body = t[m.end():end]
        secs = list(SEC.finditer(t, toc_end, m.start()))
        kat = re.sub(r"\s+", " ", secs[-1].group(2)).strip() if secs else ""
        itz = "tiraz" in m.group(3).lower() or "İHK" in no
        body = re.sub(r"\n[\s\f]*\d{1,3}[ \t]*\n", "\n", body)
        body = body.replace("\f", "\n")
        body = re.sub(r"[ \t]+", " ", body)
        body = re.sub(r"\n{3,}", "\n\n", body).strip()
        konu = (m.group(4) or "").strip("() ")
        out.append({"id": "stk-" + no.replace("/", "-").replace("İ", "I"), "kaynak": "stk", "sayi": sayi, "tarih": m.group(1).replace("/", "."),
                    "no": no, "tur": "İtiraz Hakem Heyeti Kararı" if itz else "Hakem Kararı",
                    "kategori": "İtiraz Hakem Heyeti" if itz else kategori_kisa(kat), "konu": konu, "metin": body})
    for x in out:
        x["ara"] = fold(f'{x["no"]} {x["kategori"]} {x["tur"]} {x["konu"]}\n{x["metin"]}')
    return out


def stk():
    d = os.path.join(ROOT, "stk"); os.makedirs(d, exist_ok=True)
    ip = os.path.join(d, "index.json")
    idx = json.load(open(ip, encoding="utf-8")) if os.path.exists(ip) and not YENIDEN else {"kaynak": "Sigorta Tahkim Komisyonu - Hakem Kararları Dergisi", "sayilar": {}}
    son_bulunan, bos_seri = 0, 0
    for n in range(1, MAX_SAYI + 1):
        key = str(n)
        if key in idx["sayilar"] and idx["sayilar"][key].get("adet", 0) > 0 and not YENIDEN:
            son_bulunan = n; bos_seri = 0; continue
        pdf = None; kaynak_url = ""
        for u in STK_URLS:
            url = u.format(n=n)
            try:
                data, ct = get(url)
                if data[:4] == b"%PDF": pdf, kaynak_url = data, url; break
            except urllib.error.HTTPError as e:
                if e.code not in (404, 403): print(f"sayı {n}: {url} HTTP {e.code}")
            except Exception as e:
                print(f"sayı {n}: {url} hata {type(e).__name__}")
        time.sleep(1)
        if not pdf:
            bos_seri += 1
            if n > son_bulunan + 8 and son_bulunan > 0 and bos_seri >= 8: print(f"sayı {n}: 8 sayıdır dergi yok, duruluyor"); break
            continue
        bos_seri = 0; son_bulunan = n
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "d.pdf"); open(p, "wb").write(pdf)
            txt = subprocess.run(["pdftotext", "-layout", p, "-"], capture_output=True, text=True).stdout
        kararlar = stk_bol(txt, n)
        sha = hashlib.sha256(pdf).hexdigest()[:16]
        if kararlar:
            with open(os.path.join(d, f"{n:03d}.json"), "w", encoding="utf-8") as f:
                json.dump(kararlar, f, ensure_ascii=False)
        else:
            save(os.path.join(ROOT, "_kesif", f"stk-{n:03d}.txt"), txt[:20000])
        idx["sayilar"][key] = {"adet": len(kararlar), "dosya": f"{n:03d}.json" if kararlar else "", "url": kaynak_url, "sha": sha, "karakter": len(txt)}
        print(f"sayı {n}: {len(kararlar)} karar")
    idx["guncelleme"] = time.strftime("%Y-%m-%d %H:%M")
    idx["toplam"] = sum(v.get("adet", 0) for v in idx["sayilar"].values())
    with open(ip, "w", encoding="utf-8") as f:
        json.dump(idx, f, ensure_ascii=False, indent=1)
    print("Sigorta Tahkim toplam karar:", idx["toplam"])


REK = "https://www.rekabet.gov.tr"
REK_MAX = int(os.environ.get("REKABET_MAX", "1500"))          # bir çalışmada en fazla indirilecek karar
REK_SURE = int(os.environ.get("REKABET_SURE", str(75 * 60)))  # bir çalışmada en fazla süre (saniye)
PARCA, PARCA_BOYUT, MAX_METIN = 25, 600_000, 60_000           # dosya başına karar / karakter sınırı; tek karar metni sınırı


def rek_liste(html):
    """Kararlar sayfasındaki tabloları ayrıştırır."""
    out = []
    for blok in html.split('<table class="table yantablo1"')[1:]:
        def alan(ad):
            m = re.search(ad + r"\s*:\s*</th>\s*<td[^>]*>\s*([^<]*)<", blok)
            return htmlmod.unescape(m.group(1)).strip() if m else ""
        m = re.search(r'href="(/Karar\?kararId=([0-9a-fA-F-]{36}))"[^>]*>(.*?)</a>', blok, re.S)
        if not m: continue
        out.append({"kid": m.group(2).lower(), "url": REK + m.group(1), "baslik": re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<[^>]+>", "", m.group(3)))).strip(),
                    "yayim": alan("Yayımlanma Tarihi"), "no": alan("Karar Sayısı"), "tarih": alan("Karar Tarihi"), "tur": alan("Karar Türü")})
    son = max([int(x) for x in re.findall(r"/tr/Kararlar\?page=(\d+)", html)] or [1])
    return out, son


def tarih2(t):
    m = re.match(r"(\d{1,2})\.(\d{1,2})\.(\d{4})", t or "")
    return f"{int(m.group(1)):02d}.{int(m.group(2)):02d}.{m.group(3)}" if m else (t or "")


def pdf_metin(data):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "d.pdf"); open(p, "wb").write(data)
        t = subprocess.run(["pdftotext", "-layout", p, "-"], capture_output=True, text=True).stdout
    t = t.replace("\f", "\n")
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n[ \t]*\d{1,3}/\d{1,3}[ \t]*\n", "\n", t)   # "3/25" sayfa numaraları
    return re.sub(r"\n{3,}", "\n\n", t).strip()


def rekabet():
    """Rekabet Kurulu kararları: liste sayfalarından yeni kararlar ve geriye doğru arşiv; her çalışmada sınırlı sayıda."""
    d = os.path.join(ROOT, "rekabet"); os.makedirs(d, exist_ok=True)
    ip, idp = os.path.join(d, "index.json"), os.path.join(d, "_ids.json")
    idx = json.load(open(ip, encoding="utf-8")) if os.path.exists(ip) else {"kaynak": "Rekabet Kurulu kararları (rekabet.gov.tr)", "sayilar": {}, "geri_sayfa": 1, "arsiv_tamam": False}
    ids = set(json.load(open(idp, encoding="utf-8"))) if os.path.exists(idp) else set()
    parca_no = max([int(k) for k in idx["sayilar"]] or [1])
    pp = os.path.join(d, f"{parca_no:04d}.json")
    parca = json.load(open(pp, encoding="utf-8")) if os.path.exists(pp) else []
    t0, yeni, hata = time.time(), 0, 0

    def yaz():
        with open(os.path.join(d, f"{parca_no:04d}.json"), "w", encoding="utf-8") as f:
            json.dump(parca, f, ensure_ascii=False)
        idx["sayilar"][str(parca_no)] = {"adet": len(parca), "dosya": f"{parca_no:04d}.json"}

    def isle(k):
        nonlocal parca, parca_no, yeni, hata
        if k["kid"] in ids: return
        try:
            data, ct = get(k["url"], 60)
            metin = pdf_metin(data) if data[:4] == b"%PDF" else ""
        except Exception as e:
            hata += 1; print("rekabet karar alınamadı:", k["url"], type(e).__name__, e)
            if hata >= 25: raise RuntimeError("rekabet.gov.tr çok sayıda hata veriyor; bu çalışma durduruldu")
            return
        finally:
            time.sleep(0.4)
        if len(metin) > MAX_METIN: metin = metin[:MAX_METIN] + "\n\n(Karar metni uzun olduğu için kısaltıldı; tamamı için resmî PDF'e bakın.)"
        if len(metin) < 200: metin = (metin + "\n\n(Karar metni PDF'te görüntü olarak yer aldığından yalnızca konusu alınabildi.)").strip()
        x = {"id": "rek-" + k["kid"], "kaynak": "rekabet", "sayi": parca_no, "no": k["no"], "tarih": tarih2(k["tarih"]), "tur": "Kurul Kararı",
             "kategori": k["tur"] or "Diğer", "url": k["url"], "yayim": tarih2(k["yayim"]),
             "metin": f"Konu: {k['baslik']}\nKarar sayısı: {k['no']} · Karar tarihi: {tarih2(k['tarih'])} · Karar türü: {k['tur']}\n\n{metin}"}
        # "ara" (arama metni) dosyaya yazılmaz; sunucu içe aktarırken üretir (depo boyutu yarıya iner)
        parca.append(x); ids.add(k["kid"]); yeni += 1
        if len(parca) >= PARCA or sum(len(y["metin"]) for y in parca) > PARCA_BOYUT:
            yaz(); parca_no += 1; parca = []

    def sayfa(n):
        html, _ = get(f"{REK}/tr/Kararlar?page={n}", 60)
        time.sleep(0.5)
        return rek_liste(html.decode("utf-8", "replace"))

    def bitti(): return yeni >= REK_MAX or time.time() - t0 > REK_SURE

    # 1) Yeni kararlar: baştan, tamamı bilinen sayfaya kadar
    son = 1
    for n in range(1, 200):
        if bitti(): break
        try: lst, s2 = sayfa(n)
        except Exception as e: print("rekabet sayfa", n, "hata", type(e).__name__, e); break
        if not lst: break
        son = s2
        tumu_bilinen = all(k["kid"] in ids for k in lst)
        for k in lst:
            if bitti(): break
            isle(k)
        if tumu_bilinen: break
    # 2) Arşiv: kalınan sayfadan geriye doğru (sayfalar yeni kararlarla kaydığı için 2 sayfa örtüşmeli)
    if not idx.get("arsiv_tamam"):
        n = max(1, int(idx.get("geri_sayfa", 1)) - 2)
        while not bitti():
            try: lst, s2 = sayfa(n)
            except Exception as e:
                print("rekabet sayfa", n, "hata", type(e).__name__, e); hs = idx.get("_sayfa_hata", 0) + 1; idx["_sayfa_hata"] = hs
                if hs >= 3: idx["geri_sayfa"] = n = n + 1; idx["_sayfa_hata"] = 0   # aynı sayfa 3 çalışmadır açılmıyorsa atla
                break
            idx["_sayfa_hata"] = 0
            if not lst: idx["arsiv_tamam"] = True; break
            son = max(son, s2)
            for k in lst:
                if bitti(): break
                isle(k)
            if bitti(): break
            idx["geri_sayfa"] = n = n + 1
            if n > son: idx["arsiv_tamam"] = True; break
    if parca: yaz()
    idx["guncelleme"] = time.strftime("%Y-%m-%d %H:%M"); idx["toplam"] = len(ids); idx["son_sayfa"] = son
    with open(ip, "w", encoding="utf-8") as f: json.dump(idx, f, ensure_ascii=False, indent=1)
    with open(idp, "w", encoding="utf-8") as f: json.dump(sorted(ids), f)
    print(f"Rekabet: bu çalışmada {yeni} yeni karar, {hata} hata; toplam {len(ids)}; arşiv sayfası {idx.get('geri_sayfa')}/{son}{' (tamam)' if idx.get('arsiv_tamam') else ''}")


KVKK = "https://www.kvkk.gov.tr"
KVKK_LISTE = [("Kurul Kararı", "/Icerik/5419/kurul-kararlari"), ("Karar Özeti", "/Icerik/5406/kurul-karar-ozetleri"), ("İlke Kararı", "/Icerik/7201/ilke-kararlari")]


def kvkk_liste(html):
    out = []
    for m in re.finditer(r'members__item-meta[^>]*>\s*<h2>(.*?)</h2>\s*<a href="([^"]+)"', html, re.S):
        baslik = re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<[^>]+>", "", m.group(1)))).strip().strip('"“”')
        out.append({"baslik": baslik, "url": htmlmod.unescape(m.group(2)).strip()})
    son = max([int(x) for x in re.findall(r"\?page=(\d+)", html)] or [1])
    return out, son


def html_metin(html):
    """İçerik sayfasından karar metni: script/menü çıkarılır, paragraf ve tablo hücreleri birleştirilir."""
    h = re.sub(r"(?is)<(script|style|nav|header|footer|form)[^>]*>.*?</\1>", " ", html)
    # Ana içerik: KVKK'da "news__detail-article" / "col-lg-8"; kenar çubuğu (col-lg-4, sidebar) çıkarılır
    for bas in ('class="news__detail-article', 'class="content-detail', 'class="col-lg-8', '<main'):
        i = h.find(bas)
        if i >= 0:
            j = min([x for x in (h.find('class="col-lg-4', i), h.find("sidebar-widget", i), h.find("</main>", i)) if x > 0] or [len(h)])
            h = h[i:j]; break
    parcalar = re.findall(r"(?is)<(?:p|li|td|h3|h4)[^>]*>(.*?)</(?:p|li|td|h3|h4)>", h)
    satir = [re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<[^>]+>", " ", x))).strip() for x in parcalar]
    satir = [x for x in satir if len(x) > 2]
    t = "\n".join(satir)
    for kes in ("Bu sayfadaki bilgiler", "Kişisel Verileri Koruma Kurumu ©", "Tüm Hakları Saklıdır"):
        i = t.find(kes)
        if i > 500: t = t[:i]
    return t.strip()


def kvkk():
    """KVKK kurul kararları, karar özetleri ve ilke kararları (HTML sayfası veya Resmî Gazete PDF'i)."""
    d = os.path.join(ROOT, "kvkk"); os.makedirs(d, exist_ok=True)
    ip = os.path.join(d, "index.json")
    idx = json.load(open(ip, encoding="utf-8")) if os.path.exists(ip) else {"kaynak": "Kişisel Verileri Koruma Kurulu kararları (kvkk.gov.tr)", "sayilar": {}}
    ids = set()
    for v in idx["sayilar"].values():
        try: ids.update(x["id"] for x in json.load(open(os.path.join(d, v["dosya"]), encoding="utf-8")))
        except Exception: pass
    parca_no = max([int(k) for k in idx["sayilar"]] or [1])
    pp = os.path.join(d, f"{parca_no:04d}.json")
    parca = json.load(open(pp, encoding="utf-8")) if os.path.exists(pp) else []
    yeni, ornek = 0, False
    def yaz():
        with open(os.path.join(d, f"{parca_no:04d}.json"), "w", encoding="utf-8") as f: json.dump(parca, f, ensure_ascii=False)
        idx["sayilar"][str(parca_no)] = {"adet": len(parca), "dosya": f"{parca_no:04d}.json"}
    for tur, yol in KVKK_LISTE:
        n, son = 1, 1
        while n <= son and n <= 80:
            try:
                html, _ = get(f"{KVKK}{yol}?page={n}", 60); lst, son = kvkk_liste(html.decode("utf-8", "replace"))
            except Exception as e:
                print("kvkk liste", tur, n, "hata", type(e).__name__, e); break
            time.sleep(0.5)
            if not lst: break
            bilinen = 0
            for k in lst:
                m = re.search(r"(\d{1,2}[./]\d{1,2}[./]\d{4})\s*Tarih\w*\s*(?:ve\s*)?(\d{4}/\d+)\s*Sayılı", k["baslik"], re.I)
                no = m.group(2) if m else ""
                kid = "kvkk-" + (re.sub(r"\W+", "-", no) if no else hashlib.sha1(k["url"].encode()).hexdigest()[:12]) + ("-ozet" if tur == "Karar Özeti" else "")
                if kid in ids: bilinen += 1; continue
                try:
                    data, ct = get(k["url"], 60)
                    if data[:4] == b"%PDF": metin = pdf_metin(data)
                    else:
                        hs = data.decode("utf-8", "replace"); metin = html_metin(hs)
                        if not ornek: save(os.path.join(ROOT, "_kesif", "kvkk-detay-ornek.html"), hs[:300000]); ornek = True
                except Exception as e:
                    print("kvkk karar alınamadı:", k["url"], type(e).__name__, e); continue
                finally: time.sleep(0.5)
                if len(metin) > MAX_METIN: metin = metin[:MAX_METIN] + "\n\n(Metin kısaltıldı; tamamı için resmî kaynağa bakın.)"
                x = {"id": kid, "kaynak": "kvkk", "sayi": parca_no, "no": no, "tarih": tarih2(m.group(1).replace("/", ".")) if m else "", "tur": tur,
                     "kategori": tur, "url": k["url"], "metin": f"Konu: {k['baslik']}\n\n{metin}"}
                parca.append(x); ids.add(kid); yeni += 1
                if len(parca) >= PARCA or sum(len(y["metin"]) for y in parca) > PARCA_BOYUT:
                    yaz(); parca_no += 1; parca = []
            if bilinen == len(lst): break      # bu sayfadaki kararların hepsi zaten var: daha eskileri de var
            n += 1
    if parca: yaz()
    idx["guncelleme"] = time.strftime("%Y-%m-%d %H:%M"); idx["toplam"] = len(ids)
    with open(ip, "w", encoding="utf-8") as f: json.dump(idx, f, ensure_ascii=False, indent=1)
    print(f"KVKK: bu çalışmada {yeni} yeni karar; toplam {len(ids)}")


def kesif():
    """Uyuşmazlık Mahkemesi sayfalarının ham hâlini kaydeder (ayrıştırıcı yazılabilsin diye)."""
    hedefler = {
        "uyusmazlik-ana.html": "https://www.uyusmazlik.gov.tr/",
        "uyusmazlik-arama.html": "https://www.uyusmazlik.gov.tr/Home/Arama",
        "uyusmazlik-app.js.txt": "https://www.uyusmazlik.gov.tr/Assets/front/js/app.js",
        "uyusmazlik-fill.js.txt": "https://www.uyusmazlik.gov.tr/Assets/front/js/fill.js",
    }
    rapor = []
    for ad, url in hedefler.items():
        try:
            data, ct = get(url, 40)
            html = data.decode("utf-8", "replace")
            save(os.path.join(ROOT, "_kesif", ad), html[:400000])
            rapor.append(f"{ad}: {len(html)} karakter ({url})")
            links = sorted(set(re.findall(r'href="([^"]*(?:[Kk]arar|Icerik|[Ii]ctihat|[Aa]rama)[^"]*)"', html)))[:400]
            save(os.path.join(ROOT, "_kesif", ad + ".links.txt"), "\n".join(links))
            # listedeki ilk iki içerik bağlantısını da kaydet (karar sayfasının yapısı için)
            if ad.startswith("kvkk-") or ad == "uyusmazlik-kararlar.html":
                base = "https://www.kvkk.gov.tr" if ad.startswith("kvkk-") else "https://www.uyusmazlik.gov.tr"
                num = lambda l: int((re.search(r"/Icerik/(\d+)/", l) or re.search(r"(\d+)", l) or [0, 0])[1])
                cand = sorted([l for l in links if re.search(r"/Icerik/\d+/|[Kk]arar.*\d", l) and l.rstrip("/") != url.rstrip("/")], key=num, reverse=True)[:2]
                for j, l in enumerate(cand):
                    u = l if l.startswith("http") else base + ("" if l.startswith("/") else "/") + l
                    try:
                        d2, ct2 = get(u, 40)
                        save(os.path.join(ROOT, "_kesif", f"{ad[:-5]}-ornek{j + 1}.txt"), f"{u}\n{ct2}\n" + d2[:300000].decode("utf-8", "replace"))
                        rapor.append(f"{ad} örnek {j + 1}: {u} ({ct2})")
                    except Exception as e:
                        rapor.append(f"{ad} örnek {j + 1}: HATA {type(e).__name__} ({u})")
                    time.sleep(1)
        except Exception as e:
            rapor.append(f"{ad}: HATA {type(e).__name__} {e} ({url})")
        time.sleep(1)
    save(os.path.join(ROOT, "_kesif", "rapor.txt"), "\n".join(rapor))
    print("\n".join(rapor))


if __name__ == "__main__":
    stk()
    try: rekabet()
    except Exception as e: print("rekabet hatası:", e)
    try: kvkk()
    except Exception as e: print("kvkk hatası:", e)
    try: kesif()
    except Exception as e: print("keşif hatası:", e)

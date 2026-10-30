"""Kurul kararlarını toplar (Hukuk Platformu).
- Sigorta Tahkim Komisyonu: Hakem Kararları Dergisi sayılarını (karardrgsN.pdf) indirir, kararlara ayırır,
  kurul/stk/NNN.json olarak yazar. Daha önce işlenen sayılar atlanır; her ay yeni sayılar eklenir.
- Rekabet Kurulu ve KVKK: şimdilik yalnızca sayfa yapısını kaydeder (kurul/_kesif/), ayrıştırıcı sonra eklenecek.
Kararlar kamuya açık resmî metinlerdir; kişi bilgileri yayımlayan kurumca gizlenmiştir."""
from __future__ import annotations
import hashlib, json, os, re, subprocess, sys, tempfile, time, urllib.request, urllib.error

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "kurul")
UA = {"User-Agent": "Mozilla/5.0 (HukukPlatformu kurul-kararlari; iletisim yolhava.destek@gmail.com)"}
STK_URLS = ["https://www.sigortatahkim.org/content/CmsFiles/karardrgs{n}.pdf",
            "https://sigortatahkim.org/content/CmsFiles/karardrgs{n}.pdf"]
MAX_SAYI = int(os.environ.get("MAX_SAYI", "150"))
YENIDEN = os.environ.get("YENIDEN", "") == "1"   # tüm sayıları baştan işle


def get(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), r.headers.get("Content-Type", "")


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


HDR = re.compile(r"^[\s\f]*(\d{2}[/.]\d{2}[/.]\d{4})\s+Tarih\w*\s+(?:ve\s+)?(K-\d{4}/\d+|\d{4}/İHK-\d+)\s+Sayılı\s+(?:Uyuşmazlık\s+)?(Hakem Kararı|İtiraz Hakem Heyeti Kararı)\s*$", re.I | re.M)
SEC = re.compile(r"^[\f ]*(I|II|III|IV|V|VI|VII)\.\s+(.+?)(?:\.{3,}.*)?$", re.M)


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
    items = list(HDR.finditer(t))
    out = []
    toc_end = t.find("\n", t.rfind(".....", 0, items[0].start())) if items else 0
    for i, m in enumerate(items):
        end = items[i + 1].start() if i + 1 < len(items) else len(t)
        body = t[m.end():end]
        secs = list(SEC.finditer(t, max(0, toc_end), m.start()))
        kat = re.sub(r"\s+", " ", secs[-1].group(2)).strip() if secs else ""
        itz = "tiraz" in m.group(3).lower()
        body = re.sub(r"\n[\s\f]*\d{1,3}[ \t]*\n", "\n", body)
        body = body.replace("\f", "\n")
        body = re.sub(r"[ \t]+", " ", body)
        body = re.sub(r"\n{3,}", "\n\n", body).strip()
        no = m.group(2)
        out.append({"id": "stk-" + no.replace("/", "-").replace("İ", "I"), "kaynak": "stk", "sayi": sayi, "tarih": m.group(1).replace("/", "."),
                    "no": no, "tur": "İtiraz Hakem Heyeti Kararı" if itz else "Hakem Kararı",
                    "kategori": "İtiraz Hakem Heyeti" if itz else kategori_kisa(kat), "metin": body})
    # aynı numara iki kez geçerse (ör. düzeltme) sonuncusu kalır
    uniq = {}
    for x in out:
        x["ara"] = fold(f'{x["no"]} {x["kategori"]} {x["tur"]}\n{x["metin"]}')
        uniq[x["id"]] = x
    return list(uniq.values())


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
            save(os.path.join(ROOT, "_kesif", f"stk-{n:03d}.txt"), txt[:6000])
        idx["sayilar"][key] = {"adet": len(kararlar), "dosya": f"{n:03d}.json" if kararlar else "", "url": kaynak_url, "sha": sha, "karakter": len(txt)}
        print(f"sayı {n}: {len(kararlar)} karar")
    idx["guncelleme"] = time.strftime("%Y-%m-%d %H:%M")
    idx["toplam"] = sum(v.get("adet", 0) for v in idx["sayilar"].values())
    with open(ip, "w", encoding="utf-8") as f:
        json.dump(idx, f, ensure_ascii=False, indent=1)
    print("Sigorta Tahkim toplam karar:", idx["toplam"])


def kesif():
    """Rekabet ve KVKK sayfalarının ham hâlini kaydeder (ayrıştırıcı yazılabilsin diye)."""
    hedefler = {
        "rekabet-ana.html": "https://www.rekabet.gov.tr/",
        "rekabet-kararlar.html": "https://www.rekabet.gov.tr/tr/Kararlar",
        "kvkk-ana.html": "https://www.kvkk.gov.tr/",
        "kvkk-duyurular.html": "https://www.kvkk.gov.tr/Icerik/2015/Duyurular",
    }
    rapor = []
    for ad, url in hedefler.items():
        try:
            data, ct = get(url, 40)
            html = data.decode("utf-8", "replace")
            save(os.path.join(ROOT, "_kesif", ad), html[:400000])
            rapor.append(f"{ad}: {len(html)} karakter ({url})")
            links = sorted(set(re.findall(r'href="([^"]*(?:[Kk]arar|Icerik)[^"]*)"', html)))[:400]
            save(os.path.join(ROOT, "_kesif", ad + ".links.txt"), "\n".join(links))
            # karar listesinden ilk karar bağlantısını da kaydet
            if ad == "rekabet-kararlar.html":
                k = [l for l in links if "kararId" in l or "/Karar" in l]
                if k:
                    u = k[0] if k[0].startswith("http") else "https://www.rekabet.gov.tr" + k[0]
                    d2, ct2 = get(u, 40)
                    save(os.path.join(ROOT, "_kesif", "rekabet-ornek-karar.bin.txt"), f"{u}\n{ct2}\n" + d2[:200000].decode("utf-8", "replace"))
                    rapor.append(f"rekabet örnek karar: {u} ({ct2})")
        except Exception as e:
            rapor.append(f"{ad}: HATA {type(e).__name__} {e} ({url})")
        time.sleep(1)
    save(os.path.join(ROOT, "_kesif", "rapor.txt"), "\n".join(rapor))
    print("\n".join(rapor))


if __name__ == "__main__":
    stk()
    try: kesif()
    except Exception as e: print("keşif hatası:", e)

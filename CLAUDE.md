# Hukuk Platformu — CLAUDE.md

## Amaç
Avukatlar ve hukukçular için Türkçe yapay zekâ destekli hukuk platformu. Özellikler:
- Karar arama: Yargıtay, UYAP Emsal, Danıştay, AYM ve 11M arşiv
- Dilekçe Asistanı: 15 dilekçe türü; evrak yüklenince analiz ediliyor
- Sözleşme analizi: genel sözleşmeler, navlun, deniz ticareti, tahkim
- Hukuki çeviri: sözlük, kişisel sözlük ve redaksiyon
- Mevzuat: eski ve yeni metin karşılaştırması
- Hesaplama araçları: süre, infaz (yatar) vb.

Web uygulaması olarak çalışıyor; Google Play'de TWA olarak kapalı testte (paket adı com.hukukplatformu.app).

## Altyapı (yalnızca ücretsiz servisler)
- **Site:** GitHub Pages, herkese açık `HUKUK-` deposu. İçinde karıştırılmış `index.html`, `sw.js`, gizlilik sayfaları, LICENSE.
- **Sunucu:** Cloudflare Worker `hukuk-api` (hukuk-api.yolhava-destek.workers.dev). Gizli `hukuk-api` deposundan otomatik yayınlanıyor; dosyalar `worker.js` ve `wrangler.jsonc`.
- **Cloudflare bağlantıları:**
  - D1 `hukuk-db`: kullanıcılar, oturumlar, kullanım
  - Workers AI: llama-3.3-70b; yedekte mistral-small, llama-4-scout, gemma
  - KV `FREN`: acil durdurma (fren)
- **11M karar arşivi:** Hugging Face'teki herkese açık veri seti (6 ayna). Tam yedeği `HUKUK-` deposunda, GitHub Releases altındaki `veri-11m` sürümünde: 30 parquet dosyası ve manifest.json.
- **Resmî kaynaklar:** mevzuat.gov.tr, Yargıtay karararama, UYAP Emsal, Resmî Gazete, Web Archive.
- **E-posta:** Gmail, yolhava.destek@gmail.com üzerinden.
- **Okunur kaynak kod:** gizli depoda `kaynak/index.html`. Sitede yalnızca karıştırılmış hâli (`kaynak/build-obf.mjs` ile) yayınlanır.

## Alınan kararlar
- **Geliştirme:** Tamamen telefondan yapılıyor; dosyalar GitHub'a elle yükleniyor. Güncellemelerde yalnızca değişen dosyalar verilir, test edilmiş tek paket hâlinde.
- **Paketler:**
  - Basic: 0 ₺
  - Optimus: 700 ₺/ay
  - Maximus: 1200 ₺/ay
  - Yıllık ödemede 2 ay bedava; 7 günlük deneme.
- **Ödeme:** Önce yalnızca Google Play Billing. Abone olan hesabı PC'de de kullanabilir. Play kurulumu banka hesabı açılınca yapılacak. Gelir artarsa şahıs şirketine geçilecek; o zamana kadar GVK 20/B istisnası ve hasılat hesabı kullanılacak.
- **Yapay zekâ kullanımı:** Yalnızca kullanıcının verdiği metni ve resmî kaynaktan alınan mevzuat ile kararları işler. Kanun maddesine ve karara atıf, sadece kaynaktan doğrulanmış olanlarla yapılır.
- **Kazanma olasılığı:** Yüzde verilmez. Bunun yerine sayılabilir göstergeler kullanılır: onama/bozma sayıları, mahkeme düzeyi, güncellik.
- **Kişisel veriler:** Taraf, vekil ve tanık adları ile TCKN, IBAN, telefon ve e-posta yapay zekâya gönderilmez. Telefonda maskelenir, yanıtta geri çevrilir.
- **Kullanım frenleri:** IP başına dakika sınırı, günlük toplam sınır ve KV fren anahtarı. Fren açıksa sistem 503 döner.
- **Kod koruması:** Herkese açık depoda LICENSE (tüm hakları saklıdır) bulunur ve index.html karıştırılmış olarak yayınlanır.

## Yapılmaması gerekenler
- Ücretli servis veya API (Claude API, Replicate, Cloudflare R2 vb.) gelir gelmeden seçilmez.
- Yapay zekâ kendi hafızasından kanun maddesi, karar künyesi ya da tarih uyduramaz.
- Bulunamayan veya metni doğrulanamayan mevzuat maddesi listede gösterilmez.
- Okunur kaynak kod ve yapay zekâ talimatları herkese açık depoya konmaz.
- `worker.js` HUKUK- deposuna yüklenmez.
- Çalışan yapı (giriş, plan, kota, arama) yeni özellik için bozulmaz; yeni özellik bu yapı üzerine eklenir.
- Kullanıcıya istenmedikçe ders anlatılmaz. Kurulum adımları tek tek ve kısa verilir.
- Başka uygulamaların dosyaları bu projeye karıştırılmaz.

## Ticari kullanım kuralları
- Tüm ticari haklar **Yurdagül Güler**'e aittir (FSEK). Destek ve iletişim adresi: yolhava.destek@gmail.com.
- Kullanım Koşulları ve KVKK metinleri ticari kullanıma göre yazılır. İçerikleri:
  - Çıktılar hukuki danışmanlık değildir.
  - Mesleki sorumluluk kullanıcıdadır.
  - Gönderilen metinler saklanmaz.
  - Resmî işlerde kullanılacak çeviri için yeminli tercüman gerekir.
- **Eklenecekler:** meslek sırrı (Av. K. m.36), yapay zekâ çıktı sorumluluğu, veri saklama süresi, giriş denemesi sınırı.
- Kullanılan veri ve kaynaklar ticari kullanıma uygun olmalıdır:
  - 11M veri seti CC0 lisanslıdır.
  - Mahkeme kararları ve mevzuat FSEK m.31 kapsamındadır.
  - Üçüncü kişi içeriği izinsiz kopyalanmaz.
- Play Store gereksinimleri (gizlilik politikası, hesap silme sayfası, yaş ve içerik beyanı) her sürümde güncel tutulur.

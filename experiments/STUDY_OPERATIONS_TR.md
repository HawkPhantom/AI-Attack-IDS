**Canlı insan çalışması ve yeni deneyler — uygulama paketi**

Bu paket katılımcı toplandığını veya etik değerlendirme tamamlandığını göstermez. Planlanan kişi kodları veri değildir. API bütçesi/model seçimi henüz kesinleşmediğinden mevcut çalıştırıcı yalnız yerel Ollama kullanır.

**Araştırmacı hazırlığı**

Araştırma sorusu: eş görev ve bütçe altında operatör kökeninin komut/ağ gözlemlerinden ayrımı. Yetkili keşif ve bakım görevleri kullanılır; görev kategorileri kötü niyet etiketleri değildir. Önce kurumunuzun insan araştırması değerlendirmesini ve aşağıdaki onam metnini araştırmacı adı, iletişim adresi, veri saklama süresi ve geri çekilme tarihiyle tamamlayın. Tamamlanmamış yer tutucularla katılımcı başlatmayın.

Katılımcılardan isim, parola, özel sunucu adresi veya kişisel dosya istenmez. Kimlik-kod eşlemesi gerekiyorsa araştırma deposundan ayrı tutulur. Oturumda yalnız sağlanan yerel laboratuvar kullanılır; kişisel SSH anahtarı, kişisel shell ayarı ve dış hedef kullanılmaz. Katılımcının AI yardımı alıp almadığı önceden belirlenir: mevcut `human_live` koşulunda AI yardımı yoktur. AI destekli insan koşulu eklenirse ayrı köken etiketi ve yeni protokol gerekir.

**Katılımcı bilgilendirme ve onam taslağı**

> Bu araştırma, aynı bilgisayar görevlerini yapan insanların, yazılım ajanlarının ve otomasyonun davranışlarını karşılaştırır. İzole bir eğitim laboratuvarında komutlar çalıştıracaksınız. Komutlarınız, laboratuvar çıktıları, zaman bilgileri ve laboratuvar ağ paketleri kaydedilecektir. Çalışma mesleki yeterlilik sınavı değildir. İstediğiniz anda gerekçe göstermeden durabilir, `[tarih]` tarihine kadar `[iletişim]` üzerinden katılımcı kodunuzla geri çekilme talebinde bulunabilirsiniz. Veriler `[saklama süresi]` boyunca `[erişim yetkisi]` ile saklanacaktır. Yayın veri paylaşımının kapsamı `[anonimleştirme ve paylaşılacak alanlar]` olacaktır. Lütfen kişisel bilgi, parola veya gerçek sistem verisi girmeyin. Araştırmacı: `[ad/kurum]`. Katılım süresi: pilotta ölçülerek bildirilecektir. Katılım/ücret koşulları: `[açıklama]`.

Onamın gerçekleştiği araştırmacı tarafından kaydedildikten sonra, git-ignore kapsamındaki `harness/runs/consent/P001.json` dosyası aşağıdaki yapıda oluşturulur. Aşağıdaki `false` değeri şablondur; gerçek onam olmadan değiştirilmez.

```json
{
  "participant_id": "P001",
  "consent_version": "v3-2026-09-23",
  "consented": false,
  "recorded_at": "RESEARCHER_COMPLETES_AFTER_CONSENT",
  "experience_band": "beginner|intermediate|experienced"
}
```

**Çalışmayı başlatma**

Depo kökünde:

```sh
.venv/bin/pip install -r experiments/requirements-study-lock.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python harness/lab/study_v3.py --plan-only
```

Docker ve yerel imajlar `lab-attacker:latest`, `lab-target:latest` gerekir. Çalıştırıcı yalnız `ids-v3-*` adlarıyla sahiplik etiketi taşıyan kendi konteynerlerini yönetir; isim çakışmasında durur. Dışa kapalı ağda her oturum için yeni konteynerler oluşturulur. Katılımcı oturumunda Ollama'ya istek gönderilmez.

60 planlanmış katılımcı slotu için `experiments/human_study_plan.json` hazırdır. Bu sayı bir güç analizi sonucu değildir. Her katılımcının altı görev/ortam kombinasyonu dengeli döndürülür, katılımcının bütün tekrarları tek train/cal/test bölümünde kalır. Çalıştırıcı görev sırasını ortamlar arasında da korur.

Gerçek onam alındıktan sonra araştırmacı, katılımcıya terminali vererek şu komutu çalıştırır:

```sh
.venv/bin/python harness/lab/study_v3.py \
  --consent harness/runs/consent/P001.json \
  --study-plan experiments/human_study_plan.json \
  --tasks discover inventory web_check \
  --envs a b \
  --out harness/runs/human_v3
```

Her ekranda görev ve aynı port/komut bütçesi gösterilir. Katılımcı komutlarını kendisi seçer, çıktıyı görür. `:finish` komut aşamasını bitirir; ardından son JSON istenir. CTRL-C/EOF durmayı kaydeder. Araştırmacı yönlendirmelerini kayıt dışında değiştirmeyin; teknik yardım olduysa ayrı müdahale günlüğünde belirtin. Script veya model tarafından üretilen komutları `human_live` olarak kaydetmeyin.

**Deney koşulları**

`experiments/study_v3.json` tek görev/bütçe kaynağıdır. Başlangıç pilotu iki servis profili ve üç görev içerir. Bağımsız ikinci ajan, upstream `smolagents.ToolCallingAgent` 1.26.0'dır; aynı shell yürütücüsü kullanılır. Native ajan ile upstream ajanın planlama/mesaj biçimi farklıdır ve bu fark framework değişkenidir. Ollama JSON taşıma adaptörü bu depodadır; upstream ajanın planlama döngüsü burada yeniden yazılmaz.

```sh
# Yerel AI + script pilotu
.venv/bin/python harness/lab/study_v3.py --out harness/runs/matched_v3

# Bilinen özelliklere göre kaçınma promptu; tam ağırlık erişimi olmadığı için white-box denmez
.venv/bin/python harness/lab/study_v3.py --out harness/runs/matched_v3 \
  --models gemma4:latest llama3.1:8b --tasks discover --envs a \
  --conditions evasion --no-scripts

# Ağ gecikmesi/kaybı; bütün kaynaklar aynı ağ koşuluna tabi
.venv/bin/python harness/lab/study_v3.py --out harness/runs/matched_v3 \
  --models gemma4:latest llama3.1:8b --tasks discover --envs a \
  --impairment delay_loss

# Aynı AI komutlarının script olarak tekrar yürütülmesi
.venv/bin/python harness/lab/counterfactual_study_v3.py

.venv/bin/python scripts/evaluate_study_v3.py
```

Ağ müdahalesi attacker arayüzünde egress `netem delay 40ms 10ms loss 0.5%` uygular; bağımsız bir WAN/saha testi değildir. Counterfactual eşlerde komut metni sabittir, yürütme zamanı değişir. Boş/başarısız ajanlar tam-payda sonuçlarında tutulur. Yakalama/taşıma hataları ayrı karantinaya alınır ve sayıları raporlanır. Port bütçesine uymayan davranışlar sessizce düzeltilmez; kaydedilir ve analizde ayrıca incelenir.

Scriptlerin görev raporu yoktur; onlara hedef gerçeğinden yapay doğru cevap eklenmez. Paket kapsamı ve AI'nın son raporunun doğruluğu farklı ölçülerdir. AI başarısı raporlanan doğru servisler ve yanlış servisler birlikte değerlendirilerek ölçülür; hiçbir komut üretmeyen ajan başarıyla kaçınmış sayılmaz.

**Ana çalışma öncesi sabitleme**

Pilot sonuçlarına göre görevi değiştirirseniz yeni protokol sürümü kullanın. Katılımcı planı üzerine yazılmaz. Tam çalışma başlamadan hipotez, birincil metrik, karşılaştırmalar, hata/yeniden deneme politikası ve örneklem gerekçesi sabitlenmeli. Kalibrasyon eşikleri yalnız calibration negatiflerinden seçilir. Son bağımsız test model seçmek veya başarısız bir iddiayı düzeltmek için kullanılmaz.

Önerilen ana metrik, %5 calibration FPR hedefinde recall; %1 hedefi, PR-AUC ve ilk k komutta tespit ikincildir. Calibration hedefi gerçek popülasyon garantisi değildir. 0/40 FP için tek taraflı %95 üst sınır yaklaşık %7.22; %1 sınırı için sıfır FP halinde 299 bağımsız negatif gerekir. Tek katılımcının tekrarları bağımsız değildir. 60 katılımcı × 6 görev = 360 oturum, 360 bağımsız insan anlamına gelmez.

Bağımsız son çalışma için ayrı ekip/ortam ve görülmemiş görevler ayırın. Mevcut iki Docker profili bağımsız saha ortamı değildir. API bütçesi sağlandığında sağlayıcı, kesin model sürümü, çağrı/token limiti ve harcama tavanı protokole yazılmadan ücretli koleksiyon başlatılmamalı.

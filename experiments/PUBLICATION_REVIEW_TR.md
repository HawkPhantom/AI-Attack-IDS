**AI-Attack-IDS: dergi makalesine hazırlık değerlendirmesi**

23 Eylül 2026 · İncelenen commit: `df71886`

**Kararım: Projenin iyi bir makaleye dönüşme potansiyeli var; mevcut hali güçlü bir dergiye gönderime hazır değil.** Araştırma altyapısı ve araştırma sorusu kullanılabilir. Ana eksik, daha karmaşık bir sınıflandırıcıdan önce, sınıflandırıcının gerçekten neyi ayırdığını gösterecek deney tasarımı. Mevcut yüksek skorların bir kısmını veri toplama koşulları tek başına açıklayabiliyor. Bu değerlendirme bir kabul olasılığı tahmini değildir.

İnceleme; README, teknik rapor, v2 protokolü ve sonuç JSON'ları, veri yükleyicileri, host/network/intent değerlendirme kodları, toplama kodları ve yerel ham kayıtlar üzerinden yapıldı. İlgili birincil yayınlar ve dergi kapsamları ayrıca kontrol edildi. Bu, sistematik ve eksiksiz bir literatür taraması değildir.

**Doğrulanan güçlü taraflar**

- Altı `model:*` host fold'unda SVC yeniden eğitildi. Kayıtlı sonuçlarla tahmin skorları birebir aynı çıktı; en büyük mutlak fark her fold'da `0.0`.
- Mevcut 9 protokol testi geçti.
- Eşlenmiş 48 oturumun pcap SHA-256 değerleri kayıtlarla eşleşti. Ağ özellikleri pcaptan yeniden hesaplandığında kayıtlı değerlerden fark bulunmadı. Bu kontrol, yakalamanın bütün trafiği içerdiğini kanıtlamaz.
- Eğitimden öğrenilen sözlük/TF-IDF/ölçekleme, ayrılmış calibration verisi, kaynak gruplarını ayırma, grafik kontrolleri ve oturum bazında tahminleri saklama doğru yönde tercihler.
- Canlı insan eksikliğinin, prompt etkisinin ve küçük örneklemin belgelenmesi değerli. Bunların açıkça yazılması, deneyle giderilmelerinin yerini tutmuyor.

**1. En önemli yeni bulgu: ağdaki kusursuz ayrım port bütçesiyle yeniden üretilebiliyor**

Yeni eşlenmiş veride gözlenen farklı hedef TCP port sayıları:

| Sınıf | Oturum | Gözlenen port sayısı değerleri |
|---|---:|---|
| AI | 32 | 0, 6, 7 |
| İnsan komutlarının replay'i | 12 | 1000, 1001 |
| Deterministik script | 4 | 1, 6 |

Toplayıcı AI'ya altı portluk liste veriyor; replay komutları aynı tarama bütçesine tabi değil. [Toplama talimatı](../harness/lab/collect_v2.py), [kayıtlı özellikler](paired_manifest.json).

Bunu kontrol etmek için yalnız `unique_dst_ports` girdisi alan, derinliği 1 olan bir karar ağacı eğittim. Mevcut `network_v2.json` içindeki eğitim/test oturumlarını aynen kullandım; eşik her fold'un yalnız eğitim bölümünden öğrenildi. Model, dört model-dışı, iki ortam-dışı ve iki bağlam-politikası-dışı fold'un tamamında **macro F1=1.00** elde etti. Aynı yaklaşım script testindeki dört oturumun tamamına AI dedi: **script FPR=1.00**. Eşikler yaklaşık 503–503.5 porttu.

Bu çalışma sonradan yapılan bir teşhis analizidir: özelliği toplama politikasını ve veriyi gördükten sonra seçtim. Yeni ve bağımsız bir başarı ölçümü olarak sunulmamalıdır. Yine de tek bir görev-bütçesi göstergesinin mevcut kusursuz skoru yeniden üretebildiğini doğrudan gösteriyor. Sonuçlar ve oturum bazında tahminler [denetim JSON'unda](publication_audit_2026-09-23.json).

**Sonuç:** mevcut ağ F1=1.00, AI kökenine özgü bir imzayı kanıtlamıyor. Bu veri üzerinde zamanlama veya host özelliklerine ihtiyaç duymadan aynı ayrım elde ediliyor. Makalenin ağ katkısı için tüm operatörlerde aynı görev/port bütçesiyle yeni veri gerekir. Yalnız port-sayısı özelliğini silmek yeterli değildir; SYN sayısı, port aralığı ve paket oranları aynı farkı dolaylı taşıyabilir.

**2. İnsan karşılaştırması, sorunun hedeflediği karşılaştırma değil**

Tarihsel host negatifleri gerçek insanların arşivlenmiş MUNI komut kayıtlarından geliyor; eşlenmiş ağ negatifleri bu tür komutların program tarafından yeniden yürütülmesi. İkisini de yeni protokolde canlı insan kararı gibi yorumlayamayız. İnsanlar aynı hedefi, aynı çıktıları ve aynı bütçeyi kullanarak sıradaki komutlarını seçmedi. MUNI ayrıca gerçek suçluların örneklemi değil, siber güvenlik eğitimi katılımcılarının verisi. [MUNI'nin kaynak açıklaması](https://zenodo.org/records/8136017).

Dolayısıyla mevcut host ayrımı; operatör kökeni yanında görev, eğitim seviyesi, veri kaynağı, tarih ve ortam farklarını da öğrenebilir. Ağ replay'inde insanın düşünme ve yazma zamanlaması da yoktur. Daha fazla aynı replay üretmek bu problemi çözmez.

Canlı insan, LLM ajanı, deterministik otomasyon ve gerekirse insanın AI yardımı aldığı oturumlar ayrı tanımlanmalı. Aynı görev ailesinin iyi niyetli yönetim ve yetkili saldırı senaryoları her operatör türünde bulunmalı. AI kullanımı kötü niyet etiketi olarak kullanılmamalı. Mevcut intent F1=0.896 ve AI-only F1=0.785, veri kaynakları/görev etiketleriyle karışmış betimleyici sonuçlar olarak kalmalı.

**3. Host sinyali araştırılmaya değer; düşük yanlış alarm koşulunda henüz güçlü değil**

Tarihsel, evasion dışındaki host AI örneklemi 141 oturum. Model başına 8–49 oturum var. SVC için varsayılan eşikte recall 0.708–1.000; kayıtlı insan FPR'si 0.025–0.050. Ancak calibration verisinden %1 FPR hedefiyle eşik seçildiğinde recall şöyle:

| Dışarıda bırakılan model | Varsayılan recall | %1 FPR hedefli eşikte recall |
|---|---:|---:|
| gemini3pro | 0.857 | 0.357 |
| geminiflash | 0.939 | 0.490 |
| gemma3 | 0.708 | 0.042 |
| gemma4 | 0.783 | 0.391 |
| llama | 0.913 | 0.348 |
| qwen | 1.000 | 0.500 |

Bu eşiklerde 40 test negatifinde yanlış alarm gözlenmemesi, gerçek FPR'nin %1 olduğunu göstermez. Bağımsız Bernoulli gözlemleri ve sabit eşik varsayımıyla 0/40 yanlış alarmın tek taraflı %95 üst sınırı yaklaşık **%7.22**'dir. Sıfır yanlış alarm durumunda üst sınırı %1'in altına indirmek için en az 299 bağımsız test negatifi gerekir. Aynı katılımcının tekrarlarını bağımsız sayarak bu koşul sağlanmış olmaz.

Host insan bölümleri 147/80/40 oturum ama yalnız 16/4/4 kayıt grubudur. Grup ayrımı var; gruplar arasında katılımcı kimliğinin bağımsızlığı ayrıca çözülmemiş. Yeni ağ model fold'larında calibration yalnız 2 replay, test negatifleri yalnız 4 replay ve iki kaynak yörüngesinin tekrarlarıdır. Ortam fold'larında bunlar 1 ve 2'ye düşüyor. Mevcut güven aralıkları katılımcı/görev bağımlılığını kapsamıyor.

Operasyonel yarar için alarm yükünü de raporlamak gerekir. Yalnız açıklayıcı bir örnek: hedef popülasyonda AI oranı %1, recall %87 ve FPR %3.7 olsaydı pozitif alarmların yaklaşık %19'u gerçekten AI olurdu. Bu, projeden ölçülmüş saha sonucu değil, taban oranın etkisini gösteren hesaplamadır.

**4. Grafik modelini ana yenilik yapmak mevcut kanıtla savunulamaz**

| Yöntem | Model fold'ları üzerinde ortalama recall | Ortalama FPR |
|---|---:|---:|
| SVC | 0.867 | 0.037 |
| Grafik, seed 42 | 0.758 | 0.071 |
| Sırası karıştırılmış grafik | 0.799 | 0.104 |
| Kenarları kaldırılmış grafik | 0.785 | 0.067 |
| SVC veya grafik pozitifse alarm | 0.913 | 0.087 |

Grafiğin sırasını/kenarlarını bozunca üstünlüğün kaybolduğu gösterilmiyor. Ensemble recall artışı da FPR artışıyla birlikte geliyor. Bunlar eşit yanlış-alarm bütçesinde karşılaştırılmalı. Bu sonuçlardan “grafikler hiçbir zaman faydalı değildir” sonucu da çıkmaz; mevcut temsil ve deneylerde artı değer gösterilmemiştir. [Kayıtlı karşılaştırmalar](RESULTS_V2.md).

SVC zaten güçlü ve meşru bir baseline. Yayın için mutlaka daha karmaşık bir sinir ağı eklemek gerekmiyor. Ölçüm geçerliliği, yeni veri ve genellemenin sınırları güçlü bir bilimsel katkı olabilir.

**5. Gönderim öncesi giderilmesi gereken somut tutarsızlıklar**

| Bulgu | Kanıt ve gerekli düzeltme |
|---|---|
| README/REPORT ham model komutunun geri konduğunu söylüyor; kod uyumsuz komutu tamamen atıyor | `authored()` yalnız eşleşen komutları listeye ekliyor, uyuşmayanlarda sayacı artırıyor. Yöntem açıklaması düzeltilecek; hangi dönüşümlerde model metninin kullanılabileceği ayrı provenance denetimiyle belirlenecek. |
| “Ayrımı çoğunlukla zamanlama taşıyor” ifadesi yeni v2 sonuçlarını karşılamıyor | Zamanlamasız ağ modeli sekiz ana fold'da F1=1.00; tek port-sayısı denetimi de aynı skoru veriyor. Zamanlama baskınlığı iddiası kaldırılmalı veya başka, açıkça ayrılmış deneyle desteklenmeli. |
| Tarihsel Qwen host sonucu boş oturum diye açıklanıyor | Hosttaki sekiz Qwen oturumu düzeltme sonrasında 2–7 komut içeriyor; eğitim sözlüğüyle filtrelenince de hiçbiri boş değil. Sıfır komutlu sekiz Qwen oturumu farklı, yeni eşlenmiş koleksiyonda. Bu veri kümeleri karıştırılmamalı. |
| İki collector hatasının dışlandığı söyleniyor ama kayıtlar değerlendirmede | İki `ai_llama3.1-8b_b_*_services` kaydında UnicodeDecodeError var. Bunlar `new_rows()` tarafından okunuyor ve ilgili test ID listelerinde bulunuyor. Dahil etme/dışlama, yeniden deneme ve başarısızlık paydası açık ve tutarlı olmalı. |
| Counterfactual kontrolün kodu var, sonucu yok | Yerel eşlenmiş kayıtlarda `counterfactual_script` sayısı 0; sonuç tablosu boş. Kodun varlığı tamamlanmış deney anlamına gelmez. |
| İki script kaydında komut çıktısı ile pcap kapsamı uyuşmuyor | `script_a_0` ve `script_b_0` üç IP'ye başarılı nmap çıktısı kaydediyor; mevcut pcaptaki giden paketler yalnız `172.30.0.11` için. Yakalama eksikliği veya kayıt/pcap eşleşmesi araştırılmalı. Kesin nedeni bu incelemede belirlenmedi. Script kapsama ve zamanlama sonuçları doğrulama bekliyor. |

Kod dayanakları: [host komut filtresi](../scripts/evaluate_host_v2.py), [network veri yükleme ve splitler](../scripts/evaluate_network_v2.py), [collector](../harness/lab/collect_v2.py), [counterfactual runner](../harness/lab/counterfactual_v2.py). Yalnız yakalanmış dosyanın hash'inin doğrulanması, yakalanması gereken bütün paketlerin bulunduğunu göstermez.

Ayrıca yeni koleksiyon `eth0` üzerinde özel Docker ağından yakalanıyor. README/REPORT'taki genel “loopback” tanımı gerçek arayüz/topolojiyle netleştirilmeli; gerçekçi WAN gecikmesi ve kaybı test edilmediği eleştirisi geçerli kalır. Host-only tarihsel değerlendirme ile yeni eşlenmiş host değerlendirmesi de aynı ön işlem değildir: yenisi ilk altı komut başlığını kullanıyor, ağ komutlarını kaldırmıyor. Makalede bu ayrım açık yazılmalı.

**6. Özgünlük: alan boş değil; katkı sınırı daha keskin çizilmeli**

| Yakın çalışma | Yapılmış olan | Proje için anlamı |
|---|---|---|
| LLM Agent Honeypot, 2024; v2 2025 | SSH honeypot, prompt injection ve zaman analiziyle LLM ajanlarını saldırganlar arasından ayırma | “AI saldırganını tespit eden ilk çalışma” iddiası uygun değil. Pasif, eş görevli ve kontrollü karşılaştırmanın farkı gösterilmeli. |
| TRACE, Mayıs 2026 arXiv | Terminal komutlarından TF-IDF/LinearSVC ile model ailesi atfı; 2,028 oturum, yedi aile, üç ajan altyapısı ve altyapı-dışı değerlendirme | SVC ve terminal parmak izi tek başına yenilik değil. Model atfı ile operatör kökeni farklı hedefler; yayımlanmış skorları doğrudan karşılaştırmak adil değil. |
| Honey for the Agent, 2026 | Dokuz model, altı prompt ve beş SSH ortamında 16,200 yürütme; davranış parmak izi ve çevresel yönlendirme | Küçük bir yeni model/ortam eklemesi zayıf kalır. İnsan/script kontrolü, ölçüm karışıklıkları ve bağımsız genelleme daha güçlü ayrım yaratabilir. |

Kaynaklar: [LLM Agent Honeypot makalesi](https://arxiv.org/abs/2410.13919), [TRACE tam metni](https://arxiv.org/html/2605.01186v1), [Honey for the Agent için DTU yayın kaydı](https://orbit.dtu.dk/en/publications/honey-for-the-agent-cyber-deception-and-behavioral-fingerprinting/). TRACE için incelenen kaynak arXiv ön baskısıdır. DTU kaydı Honey çalışmasını AD&D 2026 için kabul edilmiş/basım aşamasında gösteriyor; tam metnine bu kayıttan erişemedim, karşılaştırma açık özet ve veri tanımına dayanıyor.

ML güvenlik değerlendirmesinde örneklem yanlılığı, tesadüfi korelasyonlar ve gerçek dışı başarı yorumlarının etkisi ayrıca [Arp ve arkadaşlarının USENIX Security 2022 çalışmasında](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) ele alınıyor. Projenin deney planını bu metodolojik çizgide güçlendirmek mantıklı.

**7. Önerdiğim makale yönü**

Çalışma başlığı önerisi: **“Detecting LLM-Driven Shell Operators: A Controlled Study of Behavioral Signals and Confounds.”**

Ana soru: “Görev, araç, tarama bütçesi, ajan altyapısı ve ağ koşulları eşitlendiğinde; komut ve trafik gözlemleri LLM operatörlerini insanlardan ve geleneksel otomasyondan ne ölçüde ayırabiliyor?”

Savunulabilir katkılar: eşlenmiş canlı-insan/AI/script veri kümesi; model, görev ve altyapı genellemesini ayrı ölçen protokol; görünen başarının hangi kısmının toplama koşullarından geldiğini gösteren kontrollü deneyler; eşit alarm bütçesinde host/ağ katkısı ve görev başarısını koruyan kaçınma değerlendirmesi.

Algoritmik performans eş koşullarda güçlü kalırsa bir tespit makalesi gelişir. Belirgin biçimde çökerse, farklı veri kümeleri ve bağımsız altyapılarda tekrarlanan bir “davranışla tespitin sınırları” ölçüm makalesi gelişebilir. Tek bir hatalı pilotun düzeltilmesi bu ikinci yol için de tek başına yeterli olmaz.

İki kavramsal sınır açık yazılmalı. İlki, aynı komut dizisini üreten AI ve script'e yalnız komut metnine bakan deterministik dedektörün farklı karar veremeyeceğidir. “Komutu AI mı yazdı?” ve “şimdi çevrimiçi kararı AI mı veriyor?” farklı etiketlerdir. İkincisi, gözlem noktasıdır: eşlenmiş koleksiyonda komutlar saldırgan containerındaki `docker exec` üzerinden kaydediliyor. Hedef ağındaki bir sensör bu komutları kendiliğinden göremez. Host+ağ kullanım senaryosunun SSH honeypot, yönetilen uç nokta veya hangi sensör yerleşimi olduğu açıklanmalı.

**8. Yatırım sırası ve deney planı**

| Öncelik | İş | Tamamlanma ölçütü |
|---|---|---|
| P0 | İddia–kod–veri tutarlılığı | Yukarıdaki hatalar çözüldü; tüm tablolar tek sonuç kaynağından üretiliyor; ham/işlenmiş/başarısız oturum sayıları izlenebiliyor. |
| P0 | Pcap bütünlüğü | Her kontrol komutunun beklenen trafiği ve hedefi pcapta doğrulanıyor; yakalama başlangıç/bitişi ve kayıp sayaçları kaydediliyor. |
| P1 | Eş görevli küçük canlı pilot | İnsan/AI/script aynı talimat, port bütçesi ve araçlarla çalışıyor; tek port sayısı gibi görev göstergeleri sınıfı doğrudan ayırmıyor. |
| P1 | Dondurulmuş ana çalışma | Katılımcı kimlikleri, bağımsız ajan altyapıları, model aileleri ve görevler için önceden belirlenmiş train/cal/test ayrımları var. |
| P2 | Görev başarısı ve kaçınma | Tespit başarısıyla birlikte doğrulanmış görev tamamlama ölçülüyor; hiçbir şey yapmayan ajan “başarıyla kaçındı” sayılmıyor. |
| P2 | Bağımsız doğrulama | Yeni altyapı, yeni görev veya ikinci ekip/ortamdan gelen veri, sabit eşik ve modelle yalnız son testte kullanılıyor. |
| P2 | Yayın artefaktı | Anonimleştirilmiş paylaşılabilir veri veya kontrollü erişim, veri sürümleri/hash'leri, split manifestleri ve bütün tabloları üreten komut mevcut. |

Kaynak planlaması için başlangıç taslağı: 40–60 canlı katılımcı, farklı deneyim düzeyleri ve kişi başına 6–8 görev; AI tarafında birbirinden ayrılmış 4–6 model ailesi, en az iki bağımsız ajan uygulaması, birkaç görev ailesi ve birden fazla ortam. Tam faktöriyel bir seçenek olan 6 aile × 3 altyapı × 6 görev × 2 ortam × 10 tekrar, 2,160 AI oturumu eder. Bunlar yayın için zorunlu sayılar veya yapılmış güç analizi değildir; pilot varyansı, etki büyüklüğü, katılımcı içi bağımlılık ve hedeflenen FPR'ye göre küçültülmeli/büyütülmeli. İnsan tekrarları toplam oturumu artırır, bağımsız insan sayısını artırmaz.

Çalışma başlamadan katılımcı onamı ve kurumun araştırma etiği değerlendirmesi planlanmalı. İlk pilot sonrası birincil metrik ve hipotezler dondurulmalı; son test kümesi model seçimi için kullanılmamalı. Düşük FPR için test negatifi sayısı ayrıca planlanmalı; toplam eğitim verisinin büyüklüğü bunun yerine geçmez.

Temel karşılaştırmalar: komut sayısı/port sayısı/durum-kontrol oranı gibi basit kurallar; unigram ve bigram SVC; kategori-frekansı modeli; aynı girdili grafik kontrolleri; host/ağ/birleşik sistemler. Sabit FPR'de recall, PR-AUC, gözlem süresi veya ilk k komutta tespit ve görev başarısı birlikte raporlanmalı. Aynı test örneklerindeki farklar eşlenmiş, katılımcı/görev yapısına uygun yeniden örnekleme ile değerlendirilmelidir. Fold'larda tekrar kullanılan negatifler bağımsız test örnekleri gibi havuzlanmamalı.

Prompt'ta durum-kontrol teşviki, aynı yörüngenin script replay'i, eşit port bütçesi ve kontrollü ağ gecikmesi/kaybı ayrı müdahaleler olarak incelenmeli. Komut üretmeyen/başaramayan AI oturumları tam-denominator analizinde tutulmalı; yalnız başarılı/aktif oturum analizi ayrıca verilmeli. Başarısızlıkların sınıfı kolaylaştırdığı durumlar görünür kalmalı.

**9. Dergi seçimi**

Benim ilk hedef önerim, yukarıdaki deneyler tamamlanırsa **Computers & Security** olur: konu ve uygulamalı güvenlik değerlendirmesi bakımından uygun. Bu bir kabul garantisi değil, kapsam ve mevcut araştırma yönüne dayanan değerlendirmemdir. [Yayıncı sayfası](https://shop.elsevier.com/journals/computers-and-security/0167-4048).

**IEEE TIFS** ve **IEEE TDSC** daha iddialı hedefler olarak düşünülebilir. Bu proje için o hedefleri, farklı altyapılarda tekrarlanan güçlü bir bilimsel sonuç, savunmacının erişebildiği sensörlerle gösterilmiş yarar ve bağımsız testle gerekçelendirmek isterim. TIFS ayrıca kod/veri üzerinden yeniden üretilebilirliği açıkça teşvik ediyor. [TIFS kapsamı ve yeniden üretilebilirlik](https://signalprocessingsociety.org/publications-resources/ieee-transactions-information-forensics-and-security), [TDSC kapsamı](https://www.computer.org/digital-library/journals/tq/cfp-dependable-secure-computing).

Güncel JCR/SJR dilimlerini bu incelemede doğrulamadım; Q1 veya etki faktörü etiketi atamıyorum. Dergi seçimini önce katkının türü ve kanıtın gücü üzerinden yapmak daha yararlı.

**Gönderim kararı:** Mevcut sonuçlarla güçlü dergiye gönderim önermiyorum. Önce eş görevli canlı pilot ve ölçüm sorunlarının çözümü; ardından sabit protokolle kapsamlı çalışma. Yeni makalenin ana sermayesi, yüksek bir laboratuvar F1 sayısından çok, o sayının neden oluştuğunu ve hangi koşullarda geçerli kaldığını güvenilir biçimde açıklayabilmek olmalı.

**Bu incelemenin sınırı:** Yeni insan/AI oturumu toplanmadı; Docker ortamı veya ücretli API deneyi başlatılmadı. GNN'lerin tamamı yeniden eğitilmedi; bunların değerlendirmesi mevcut sonuç dosyaları ve kod incelemesine dayanıyor. Yapılan çalıştırmalar testler, altı SVC fold'u, 48 pcap'ın yeniden özellik çıkarımı ve port-sayısı teşhis deneyidir. Uygulama kodu ile mevcut deney sonuçları değiştirilmedi; bu değerlendirme ve ek teşhis JSON'u eklendi.

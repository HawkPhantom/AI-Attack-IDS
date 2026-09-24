**AI-Attack-IDS — güncel yayın hazırlığı değerlendirmesi**

24 Eylül 2026 · İncelenen durum: df71886 üzerindeki mevcut çalışma ağacı ve yerel matched_v3 kayıtları. Bu değerlendirme, 23 Eylül tarihli incelemeye ek güncellemedir.

**Kararım: Deney altyapısı ve araştırma sorusu belirgin biçimde gelişmiş; güçlü dergiye gönderim için hâlâ erken. Mevcut README/REPORT hem bazı bulguları gereğinden fazla olumsuz yorumluyor hem de deney tasarımının sağladığı güvenceleri abartıyor.** İyi bir makale için kullanılabilir bir temel var. Öncelik sonuçları daha iddialı yazmak değil, ölçüm ve karşılaştırma hatalarını düzeltip bağımsız doğrulamayı tamamlamak.

Önce README ve REPORT okundu; ardından protokol, matched sonuçları, toplama/değerlendirme kodu, ham komutlar ve pcap dosyaları karşılaştırıldı. 18 birim testi geçti. Yeni değerlendirme ham veriden ayrı bir geçici dosyaya çalıştırıldı: 35 fold içeren sonuç JSON'u, depodaki JSON ile nesne düzeyinde tamamen aynı. Bu, hesaplamanın tekrar üretildiğini gösterir; veri ve yorumların doğru olduğunu tek başına göstermez. Eski host/GNN/intent deneylerinin tamamı bu turda yeniden eğitilmedi.

Sayısal denetim, incelenen dosyaların SHA-256 değerleri ve ek duyarlılık hesabı: [publication_audit_2026-09-24.json](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/experiments/publication_audit_2026-09-24.json).

**Doğrulanan ilerleme**

Önceki eşit olmayan AI–insan replay karşılaştırmasına ek olarak aynı laboratuvarda deterministik script kontrolleri toplanmış. Native döngü yanında gerçek upstream smolagents kullanılıyor. Model ailesi, framework, görev ve profil dışarıda bırakma değerlendirmeleri mevcut. Aynı komutları yeniden oynatma kontrolü gerçekten yapılmış; kaçınma ve yapay ağ gecikmesi oturumları mevcut. Görev başarısı, yanlış raporlanan servisleri de cezalandırıyor. Kalibrasyon ve eğitim ayrımı, veri kaynağı kimlikleri, runtime hash'leri, yakalama sayaçları ve boş oturumların korunması değerli iyileştirmeler.

Bunlar önceki pilotun önemli açıklarını ele alıyor. Ancak eklenen kontrollerin doğru yorumlanması gerekiyor.

**Verinin gerçek kapsamı**

| Grup | Deneme | Mevcut QC'ye göre uygun | Tam doğru görev cevabı |
|---|---:|---:|---:|
| AI, normal ağ/normal prompt | 48 | 42 | 15 |
| AI, kaçınma promptu | 32 | 30 | 8 |
| AI, gecikme/kayıp | 16 | 13 | 6 |
| Deterministik script | 48 | 48 | Ölçülmüyor |
| Aynı komutların script replay'i | 13 | 13 | Ölçülmüyor |
| Toplam | 157 | 146 | — |

Dolayısıyla uygun örneklerde 85 AI, 48 script ve 13 counterfactual var. Belgelerdeki 96/48/13 sayıları deneme sayılarıdır. Mevcut matched ana sonuçlarda canlı insan veya insan replay sınıfı yok; insan replay sonuçları eski ayrı veri kümesine ait. Bütün 96 AI denemesinin repeat değeri 0: çok sayıda koşul var, aynı koşulun bağımsız tekrarları yok. Aşağıdaki QC bulgusu nedeniyle 146 sayısı da nihai temiz veri sayısı olarak görülmemeli.

**1. Yayın öncesi zorunlu: kalite kontrolünün geçerli saydığı bozuk bir oturum var**

[ai_9fc950fe6b82a13f4913.json](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/harness/runs/matched_v3/ai_9fc950fe6b82a13f4913.json:37) üç hedeften başarılı ping cevapları içeriyor. Sonraki iki komutta “No such container” Docker hatası var. Buna rağmen pcap yalnız 24 baytlık başlıktan oluşuyor, paket sayısı sıfır, eligible=true. Bu kayıt hem normal AI değerlendirmesinde hem aynı-komut karşılaştırmasında yer alıyor.

Neden QC'den kaçtığı kodda görülebiliyor: [session_quality.py](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/harness/lab/session_quality.py:25) yalnız dönüş kodu 0 olan komutların Nmap çıktısını denetliyor. Kısmen başarılı fakat timeout ile biten ping ve Docker taşıma hatası bu kontrolde yakalanmıyor. [Observation.command](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/harness/lab/study_v3.py:127), docker exec'i check=False çalıştırdığından daemon hatası normal komut çıktısı olarak kaydedilebiliyor. Yakalama hash'inin eşleşmesi ve tcpdump'ın sıfır kernel drop bildirmesi eksiksiz gözlem kanıtı değil.

Düzeltme: komutun başarısızlığı ile yürütücü/taşıma hatasını ayırın; başarılı ICMP ve diğer protokol kanıtlarını da yakalama ile çapraz kontrol edin. Konteyner/capture kimliğini oturum boyunca doğrulayın. Hatalı kaydı sessizce silmeyin; karantina nedeni ve değişen paydalar görünür olsun. Konteynerin neden kaybolduğunu bu inceleme kesinleştirmedi.

Yalnız bu kaydı dışarıda bırakan keşifsel yeniden hesaplama yaptım; eşlenmiş karşılaştırması da düşüyor. Örneğin zamanlamalı RF'nin model-fold ortalama AUROC/recall/FPR'si 0.874/0.753/0'dan 0.877/0.747/0'a; counterfactual ortalama AUROC'si 0.846'dan 0.750'ye değişiyor. Bu bir doğrulama sonucu değil, ölçüm hatasının etkisini gösteren duyarlılık hesabı. Ana sonuç dosyaları değiştirilmedi.

**2. Rapora alınmayan Random Forest, ana sonuç cümlesini değiştiriyor**

Değerlendirici iki Random Forest baseline'ını hesaplıyor: [evaluate_network_v2.py](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/scripts/evaluate_network_v2.py:88). Ancak README/REPORT/MATCHED_RESULTS tablolarında ikisi de yok. Aynı dört model fold'unun eşit ağırlıklı ortalamaları:

| Yöntem | AUROC | Kalibrasyonda %5 hedefindeki recall | Gerçek test FPR |
|---|---:|---:|---:|
| Host komut-adı SVC | 0.194 | 0.169 | 0.000 |
| Ağ SVC, zamanlamasız | 0.884 | 0.805 | 0.583 |
| Ağ SVC, zamanlamalı | 0.865 | 0.866 | 0.458 |
| Ağ RF, zamanlamasız | 0.725 | 0.630 | 0.292 |
| **Ağ RF, zamanlamalı** | **0.874** | **0.753** | **0.000** |

Bu son satır düşük popülasyon FPR'sini doğrulamaz; aynı altı negatif oturum dört fold'da tekrar kullanılıyor. Fakat “ağ katmanı burada kullanılabilir FPR'ye kalibre edilemiyor” şeklindeki bütün yöntemleri kapsayan ifade veriyi doğru temsil etmiyor. Bulgular model seçimine bağlı. Başarısız doğrusal modeli bütün ağ yaklaşımının sonucu diye sunmak da, RF'nin 0/6 sonucunu başarı garantisi diye sunmak da uygun değil.

Bütün baseline'lar açıkça raporlanmalı. Bundan sonraki model/hiperparametre seçimi geliştirme verisinde yapılmalı, son test seçim için kullanılmamalı. Tablolarda “%5 FPR'de recall” yerine “kalibrasyonda %5 FPR hedefiyle seçilen eşikte recall” yazılması daha doğru.

**3. “Split başına dört bağımsız negatif grup” doğru değil**

[negative_split](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/scripts/evaluate_study_v3.py:32) ve gerçek kimlikler şu bölünmeyi veriyor:

| Bölüm | Oturum | Script ailesi |
|---|---:|---|
| Eğitim | 36 | curl_http, devtcp_bash, nc_each, nc_joint, nmap_joint, ping_then_nmap |
| Kalibrasyon | 6 | Yalnız nmap_version |
| Test | 6 | Yalnız nmap_each |

Bootstrap çıktısındaki dört grup, model fold'unda üç AI görev grubu ile **bir** negatif script grubunun toplamı. Dört bağımsız negatif grup değil. Negatif grup tek olduğundan FPR bootstrap aralığı [FPR, FPR] biçiminde çöküyor; bu kesinlik değil, farklı negatif kaynakları hakkında belirsizliği ölçememek.

Üstelik mevcut bütün fold/yöntemlerde %1 ve %5 kalibrasyon eşikleri aynı. Altı kalibrasyon örneğiyle iki düşük-FPR hedefi ayrı bir biçimde sınanamıyor. İyimser bağımsız Bernoulli varsayımı altında bile 0/6 yanlış pozitifin tek taraflı %95 üst sınırı %39.3. Buradaki altı oturum aynı aileden geldiği için bu yalnız açıklayıcı bir hesap, saha garantisi değil.

Düzeltme: farklı araçlar ve bağımsız uygulamalar içeren çok daha geniş negatif havuz, birden çok negatif aileyi içeren ayrı kalibrasyon/test ve geliştirme aşamasında aile dışarıda bırakma duyarlılığı. Aynı altı testi fold'lar arasında toplayıp 24 bağımsız negatif gibi saymayın.

**4. AUROC 0.19 “komutlarda bilgi yok” demek değil; host baseline tam komut içeriğini kullanmıyor**

AUROC 0.194 şans düzeyi 0.5 değildir. Etiket/puan yönünü ve eğitim–test dağılımını incelemeyi gerektiren ters sıralamadır. Aynı puanları ters çevirmek bu testte matematiksel olarak yaklaşık 0.806 AUROC verir; bu, sinyal yokluğu yorumunun geçersizliğini gösterir. Teste bakıp yön çevirerek 0.806'yı yeni doğrulanmış sonuç diye sunmak da doğru olmaz.

Ayrıca [özellik çıkarımı](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/scripts/evaluate_network_v2.py:61), ilk altı komutun yalnız ilk kelimesini alıyor. Argümanlar, tam metin ve shell yapısı yok. Örneğin çok adımlı bir shell ifadesi yalnız “for” veya “bash” olarak temsil edilebiliyor. Buradan bütün “komut içeriği” yöntemleri hakkında sonuç çıkarılamaz.

Savunulabilir ifade: “Bu komut-adı/TF-IDF baseline'ı mevcut negatif-aile bölünmesinde genellenemiyor.” Geliştirme aşamasında tam-komut ve argüman-normalize edilmiş baseline'lar, token/shell ayrıştırma denetimi ve farklı negatif aile split'leri karşılaştırılmalı.

**5. Gecikme/kayıp karşılaştırması bütün operatörlere eşit uygulanmış değil**

Ham veride delay_loss koşulunda 16 AI denemesi var; **sıfır script ve sıfır insan oturumu** var. [evaluate_study_v3.py](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/scripts/evaluate_study_v3.py:65), gecikmeli AI testlerine normal ağdaki hte negatiflerini ekliyor. Gecikmeli script toplansa bile mevcut değerlendirme yolu bunları bu teste katmıyor.

Dolayısıyla [README](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/README.md:213) ve [MATCHED_RESULTS](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/experiments/MATCHED_RESULTS.md:79) içindeki “her operatöre eşit” ifadesi mevcut deney için yanlış. Bu test, olumlu sınıfa müdahale edilen tek taraflı dayanıklılık kontrolü olarak etiketlenebilir. Eşit koşullu dayanıklılık testi için hem AI hem negatifler aynı gecikme/kayıp koşullarında test edilmeli; kalibrasyonun normal ağdan aktarımı mı yoksa yeniden kalibrasyon mu olduğu önceden tanımlanmalı.

Ayrıca yakalama loopback'te değil, Docker operatör konteynerinin eth0 arayüzünde yapılıyor. Doğru sınırlama, tek yerel Docker altyapısı ve sınırlı sentetik ağ müdahalesidir; gerçek WAN doğrulaması yok.

**6. Kaçınma anlatısı ve tablosu başarı filtresiyle tutarlı değil**

MATCHED_RESULTS içindeki “Evasion (task-success gated)” tablosu, başarılı alt kümenin değil bütün uygun kaçınma oturumlarının metrikleriyle eşleşiyor. [Kod](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/scripts/evaluate_study_v3.py:97) başarılı alt kümeyi ayrıca successful_ai_sensitivity alanına yazıyor.

Uygun 30 kaçınma oturumunun 8'i tam doğru: Gemma4 altı, Llama bir, Qwen bir. Bu yüzden “yalnız Gemma4 görevi tamamlıyor” genellemesi de yanlış. Her model için başarı paydası, başarı koşuluyla kaçınma oranı ve bütün denemeler içindeki “başarılı ve tespit edilmemiş” oranı birlikte gösterilmeli. Normal prompt ile eşlenmiş fark olmadan yalnız düşük skor almak, promptun kaçınma sağladığını göstermez.

Durum kontrolü konusunda daha temel bir sorun var: bütün uygun matched oturumlarda mevcut tanıma göre pwd/id/whoami/uname/hostname sayısı **sıfır**; tam yürütülen komutlarda bu sözcükler için yapılan ek arama da eşleşme bulmadı. “Kaçınmada durum-kontrol payı çöktü” denemez, çünkü normal koşulda da sıfırdı. 0.5 AUROC burada değişkenin sabit olmasının sonucudur; script ile AI'nın aynı refleksi gösterdiğinin kanıtı değildir.

**7. Aynı izin verilen bütçe, bütün davranış karıştırıcılarını ortadan kaldırmıyor**

Altı komut bir maksimum gönderim sayısı. Scriptler göreve/stratejiye göre 1, 3 veya 6 gönderim yapıyor; tek gönderimde çok sayıda shell alt-komutu bulunabiliyor. AI komut sayısı da değişiyor. Komut-sayısı kontrolünün AUROC 0.77 vermesi hâlâ uzunluk/başarı/araç kullanımına bağlı ayrım olabileceğini gösteriyor. Port sayısının 0.62'ye düşmesi eski 1000-port kestirmesinin normal pilotta büyük ölçüde azaltıldığını gösterir; bütün karıştırıcıların giderildiğini ispatlamaz.

En az bir uygun kaçınma oturumu, [ai_6920b82376a34a7fb295](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/harness/runs/matched_v3/ai_6920b82376a34a7fb295.json), 6 yerine **1000 TCP portuna** ulaşmış. Bu normal-model tablosunun değil kaçınma verisinin sorunu. Bütçe ihlali kaydediliyor fakat ayrı analiz edilmiyor. Ayrıca curl_http stratejisi discover/inventory görevlerinde de yalnız 80/8080 portlarına gidiyor; tüm TCP servislerini keşfetme görevini kapsamıyor. Scriptlere nihai görev cevabı üretilmediği için başarı eşitliği de ölçülmüş değil.

Düzeltme: ortak izin verilen kapsam, gerçek yürütülen kapsam, görev başarısı ve komut/alt-komut sayısını ayrı raporlayın. İhlalleri veya başarısızlığı sessizce silmek yerine bütün-deneme ve protokole-uygun duyarlılık analizlerini açıkça ayırın. Başarı bilgisi olmadan “adil bütçe bütün kestirmeleri kaldırdı” sonucuna gitmeyin.

**8. Counterfactual kontrol değerli; “yalnız zamanlama ayırır” sonucu erken**

13 çiftin komut metinleri gerçekten aynı. Deterministik komut-adı özelliklerinin eşit olması nedeniyle host puanları 13 çiftte de eşit: bu beklenen bir tutarlılık kontrolüdür. AI tarafından yazılmış komutların script olarak oynatılması “komutu kim yazdı?” sorusunda zaten aynı yazarlığa, “o anda kim yürütüyor?” sorusunda farklı mekanizmaya karşılık gelir. Bu iki hedef ayrı tanımlanmalı.

Ağ zamanlamasız SVC için 13 çiftin 4'ünde AI puanı yüksek, 4'ünde düşük, 5'inde eşit. Ortalama 0.50, her çiftin eşit olduğu anlamına gelmiyor. Zamanlamalı SVC'de 10 yüksek, 2 düşük, 1 eşit. Tablodaki 0.81, 13 ayrı iki-örnekli fold'un ortalaması; büyük bir ortak test kümesinin tek AUROC'si değil. Çiftler ortak kaynak model/framework/görevlere bağlı ve biri yukarıda gösterilen bozuk ölçümü içeriyor.

Yerel model bekleme süreleri ile beklemeden çalışan replay arasında zamanlama farkı beklenir. Zamanlama katkısını AI'ya özgü göstermek için gecikmesi eşleştirilmiş scriptler, rastgele bekleme kontrolleri, farklı model sunucuları/donanımlar ve gerçek insan düşünme süreleri gerekiyor. Mevcut sonuç “bu koşullarda zamanlama özellikleri ek ayrım sağlıyor” diye sınırlandırılmalı.

**9. İnsan çalışmasına geçmeden önce plan–değerlendirici uyuşmazlığı düzeltilmeli**

Hazırlanan 60 katılımcı yuvası gerçek katılımcı değildir; bu doğru açıklanmış. Kolektör planned_partition değerini [kayıtlara ekliyor](/Users/furkanciylan/Desktop/ai-ids-git/AI-Attack-IDS/harness/lab/study_v3.py:390), ancak değerlendirici bu alanı kullanmayıp katılımcıları SHA-256 sırasına göre yeniden bölüyor. Mevcut planın 60 ID'si bu mantıktan geçirildiğinde **34'ünün bölümü değişiyor**.

Şu an insan verisi olmadığı için bu, mevcut sonuçlarda insan verisi sızıntısı bulunduğu anlamına gelmez. Fakat önceden dondurulmuş insan protokolüne uyulmayacağı anlamına gelir. İnsan toplamadan önce plan hash'i/partition tutarlılığı ve plan dışı ID reddi doğrulanmalı. Ayrıca operasyon belgesindeki ayrı human_v3 klasörü, varsayılan olarak yalnız matched_v3 okuyan değerlendiriciye nasıl dahil edilecek açıkça tanımlanmalı.

**10. Tekrar üretim ve rapor tutarlılığı tamamlanmalı**

- README'nin ana tekrar üretim bağlantısı hâlâ v2 PROTOCOL dosyasına gidiyor; v3 komutları ve kilidi aynı belgede görünmüyor.
- MATCHED_RESULTS “evaluate_study_v3.py tarafından üretildi” diyor; bu script yalnız JSON yazıyor. Markdown için sürümlenmiş üretici mevcut değil.
- report.html eski 1.00 performans iddialarını hâlâ içeriyor. Üstteki tarihsel uyarı, aşağıdaki güçlü ana iddialarla çelişiyor.
- “İki sağlayıcı” ifadesi v3'teki dört model/üç model ailesi tanımıyla uyumlu değil.
- Ham kayıtlar, pcaps ve runtime manifestleri yerelde, git dışında. Hakemlerin tekrar üretmesi için uygun bir sürümlü veri/artefakt paketi gerekiyor. Hash, tek başına geçmiş kodun içeriğini yeniden kurmaz.
- Mevcut 18 test yararlı yazılım değişmezlerini sınar; rapor–JSON tutarlılığını, gecikmede iki sınıfın bulunmasını, gerçek bütçe ihlallerini ve planlanan insan split'lerinin korunmasını sınamaz.

**Şu an savunulabilir bilimsel sonuç**

“Ortak laboratuvar ve izin verilen görev bütçesi altında, AI–deterministik otomasyon ayrımı kullanılan özelliklere, negatif kaynaklara ve sınıflandırıcıya duyarlıdır. İncelenen komut-adı baseline'ı genellenememektedir; bazı ağ modelleri umut verici sıralama göstermektedir. Küçük ve dar negatif örneklem, gözlenen düşük yanlış-pozitif oranlarının genellenmesine izin vermemektedir. Canlı insan ayrımı ve gerçek ağlara aktarım henüz doğrulanmamıştır.”

Bu çerçeve mevcut veriye daha yakın. “AI tespit edilemez”, “tek sinyal zamanlama” veya “ağ yaklaşımı kullanılamaz” gibi genel sonuçlar henüz desteklenmiyor. Aynı şekilde bir RF satırından saha kullanımı çıkarılamaz.

**Makale katkısı ve literatürdeki yer**

Model ailesi atfı zaten inceleniyor: [TRACE](https://arxiv.org/abs/2605.01186) üç scaffold ve yedi model ailesiyle terminal davranışından atıf yapıyor; hedefi sizin AI–insan–otomasyon ikili/çoklu köken sorunuzla aynı değil. [Honey for the Agent](https://orbit.dtu.dk/en/publications/honey-for-the-agent-cyber-deception-and-behavioral-fingerprinting/) dokuz model ve beş ortamda davranış parmak izlerini araştırıyor; bu incelemede açık özet kullanıldı, tam metin erişime kapalı. [LLM Agent Honeypot](https://arxiv.org/abs/2410.13919) AI ajanlarını ayırmak için zamanlama ve prompt injection yaklaşımını zaten ele alıyor. “İlk AI saldırgan dedektörü” katkısı savunulmamalı.

Sizin olası özgün katkınız: köken ile araç/görev/başarı/zamanlama etkilerini kontrollü biçimde ayıran, canlı insan ve farklı otomasyon ailelerini birlikte kapsayan bir ölçüm çalışması; buna açık veri ve savunmacının erişebildiği sensörlerle doğrulanmış bir değerlendirme protokolü eklemek. Yüksek skor şart değil; güçlü negatif sonuç da değerli olabilir, fakat bu pilot bütün yöntemlerin başarısızlığını kanıtlamıyor. ML güvenlik değerlendirmesindeki bu tür yorum sorunlarının genel çerçevesi için [Arp ve arkadaşları, USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) uygun bir metodolojik kaynak.

**Gönderime giden öncelik sırası**

1. Ölçüm hatasını ve QC kapsamını düzeltin; bütün yöntemleri ve doğru paydaları kullanarak raporları tek üreticiden yenileyin. Veri dışlama/yeniden toplama gerekçeleri sürümlensin.
2. Geliştirme deneyinde negatif aile çeşitliliğini ve bağımsız tekrarları artırın; model ailesi/framework/görev dışarıda bırakma sonuçlarını ana iddia ile birlikte raporlayın. Başarılı ajan alt kümesini ayrıca inceleyin.
3. Gecikme/kayıp koşullarını iki sınıfa eşit uygulayın; gecikmesi eşleştirilmiş script kontrolünü ve yeni ağ/donanım koşulunu ekleyin.
4. İnsan planı–değerlendirici uyumunu sağlayıp gerçek katılımcıları aynı görevlerde toplayın. İnsan karşılaştırması merkezde kalacaksa bunun yerine arşiv replay kullanılamaz; araştırma yalnız AI–otomasyona daraltılırsa başlık ve sonuç kapsamı da daraltılmalı.
5. Birincil hipotez, model seçimi, dışlama kuralları, başarı ölçütü ve örneklem gerekçesini sabitleyin. Sonra hiç kullanılmamış kaynaklardan bağımsız test toplayın. Katılımcı/ailenin tekrarları bağımsız gözlem sayılmamalı.
6. Makaleyi bu doğrulamaya göre yazın; savunmacının komutları nasıl görebileceğini, hangi olayın “saldırı” kabul edildiğini ve gerçek operasyonel yararı açıklayın. Yetkili keşif görevi tek başına kötü niyet veya başarılı ihlal etiketi değildir; insan verisi eklemek de tek başına bu etiketi doğrulamaz.

**Dergi önerime önemli düzeltme**

23 Eylül değerlendirmesindeki Computers & Security önerimi geri çekiyorum. [Yayıncının mevcut kapsam sayfası](https://shop.elsevier.com/journals/computers-and-security/0167-4048), AI/ML'nin önemli bileşen olduğu başvurular için moratoryum belirtiyor. Önceki öneride bu açık kapsam kısıtını atlamışım. Bugünkü bu proje için onu ilk hedef önermek doğru değil. ScienceDirect kapsam sayfasına ayrıca erişim denemesi 403 verdi; burada dayanak erişilebilen yayıncının kendi sayfası.

[IEEE TIFS](https://signalprocessingsociety.org/publications-resources/ieee-transactions-information-forensics-and-security) bilgi güvenliği ve adli analiz kapsamıyla tematik olarak düşünülebilir ve yeniden üretilebilirliği teşvik ediyor. Ancak mevcut pilotu TIFS düzeyinde gönderime hazır görmüyorum; bu bir kabul olasılığı veya güncel Q dilimi değerlendirmesi değil. Dergi listesini ana katkı ve dış doğrulama netleştiğinde, güncel kapsam kurallarına göre yeniden daraltmak gerekir.

**Bu turda yapılanlar ve sınır**

README/REPORT, v3 kodu, bütün 157 yerel kaydın QC/hash/özellik hesapları ve kayıtlı bütün v3 fold'ları incelendi; 18 test ve tam v3 yeniden üretimi tamamlandı. Ek olarak bozuk tek kaydı dışarıda bırakan keşifsel duyarlılık çalıştırıldı. Bu rapor ve sayısal denetim dosyası eklendi. Uygulama kodu, README/REPORT ve esas deney sonuçları değiştirilmedi; yeni katılımcı, model oturumu, Docker deneyi veya ücretli API çağrısı başlatılmadı.


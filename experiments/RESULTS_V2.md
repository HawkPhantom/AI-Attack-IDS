# Düzeltilmiş host + network deneyleri (v2)

Bu rapor README/REPORT içindeki tarihsel sayısal iddiaların yerine geçer. Kod/protokol hataları düzeltildi; gerçek insanlarla eş görevli veri toplama ve bağımsız ajan altyapıları henüz tamamlanmadı.

## Deney kapsamı

- Yeni eşlenmiş oturum sayısı: **48**; köken dağılımı: `{'ai': 32, 'human_replay': 12, 'script': 4}`.
- Sıfır giden-trafik oturumları: `{'ai': 8}`. Bunlar analizden çıkarılmadı.
- Veri toplama sırasında `2` oturumda collector hatası kaldı; bunlar sonuçlarda ayrı tutuldu ve başarılı model oturumu sayılmadı.
- Her yeni oturumda komutlar ve pcap birlikte kaydedildi. Dört yerel model, iki servis profili, iki bağlam politikası ve iki görev kullanıldı.
- İnsan sınıfı yeni bir insan katılımcı çalışması değil, arşivlenmiş insan komutlarının replay verisidir. Script kontrolleri ayrı tutulur.
- Tarihsel network pcap sayısı: 14 (8 AI, 6 replay). Port 22 paketleri eski yakalama filtresi yüzünden geri getirilemez.

## Host: sürücü kaynaklı dönüşüm denetimi

Malicious/evasion tarihsel verisinde 3215 kayıtlı komutun **337** tanesi ham model çıktısından çıkarılan komutla uyuşmuyor. Bu dönüşümler model tarafından yazılmış komut analizinden çıkarıldı.

Durum kontrolü komutları: kayıtlı 840; dönüşümler çıkarılınca 503. Bu düşüş, promptların durum kontrolünü teşvik etme etkisini ortadan kaldırmaz.

İnsan train/calibration/test sayıları: `{'train': 147, 'cal': 80, 'test': 40}`. Gruplar birbirinden ayrıdır. Tarihsel heuristic filtreler kaldırıldığı, benign AI çıkarıldığı ve iki AI ortamı birlikte kullanıldığı için eski skorlarla fark tek bir düzeltmenin etkisi değildir.

## Host: görülmemiş model

Aynı ilk-20-komut sınırı ve yalnız eğitimden türetilen ortak sözlük, tüm host modellerine uygulanır. GNN üç tohumla çalıştırıldı. Tablodaki aralık güven aralığı değil, tohumlar arası min–max değeridir.

| Dışarıda tutulan model | AI n | SVC recall | SVC %95 Wilson | SVC FPR | GNN recall aralığı | Ensemble recall aralığı |
|---|---:|---:|---|---:|---|---|
| gemini3pro | 14 | 0.857 | 0.601–0.960 | 0.050 | 0.571–0.786 | 0.857–0.857 |
| geminiflash | 49 | 0.939 | 0.835–0.979 | 0.050 | 0.959–0.959 | 0.959–0.959 |
| gemma3 | 24 | 0.708 | 0.508–0.851 | 0.025 | 0.583–0.625 | 0.792–0.833 |
| gemma4 | 23 | 0.783 | 0.581–0.903 | 0.025 | 0.565–0.696 | 0.783–0.826 |
| llama | 23 | 0.913 | 0.732–0.976 | 0.025 | 0.783–0.870 | 0.957–1.000 |
| qwen | 8 | 1.000 | 0.676–1.000 | 0.050 | 0.875–1.000 | 1.000–1.000 |

**Sonuç:** evrensel 1.00 GNN/ensemble tabanı korunmuyor. SVC, kategori-frekansı, sırası karıştırılmış grafik ve kenarsız grafik sonuçları birlikte değerlendirilmelidir; yüksek skor tek başına topolojinin katkısını kanıtlamaz.

### Grafik katkısı: model foldlarının ortalama recall değeri

| Yöntem | Ortalama recall | Ortalama insan FPR |
|---|---:|---:|
| svc | 0.867 | 0.037 |
| categories | 0.801 | 0.079 |
| graph_seed42 | 0.758 | 0.071 |
| shuffle_seed42 | 0.799 | 0.104 |
| no_edges_seed42 | 0.785 | 0.067 |
| ensemble_seed42 | 0.913 | 0.087 |

Bu ortalamalar model foldlarına eşit ağırlık verir. Aynı insan test grubu farklı foldlarda tekrar kullanılır; bunlar bağımsız yeni insan gözlemleri olarak toplanmaz.

### Diğer host kontrolleri

| Deney | SVC recall | SVC FPR | Macro F1 |
|---|---:|---:|---:|
| no_state:gemini3pro | 0.643 | 0.075 | 0.797 |
| no_state:geminiflash | 0.735 | 0.100 | 0.809 |
| evasion:geminiflash | 1.000 | 0.050 | 0.959 |
| evasion_retrain:geminiflash | 1.000 | 0.075 | 0.940 |
| no_state:gemma3 | 0.500 | 0.050 | 0.738 |
| evasion:gemma3 | 0.750 | 0.025 | 0.881 |
| evasion_retrain:gemma3 | 0.875 | 0.075 | 0.863 |
| no_state:gemma4 | 0.826 | 0.100 | 0.863 |
| evasion:gemma4 | 1.000 | 0.025 | 0.964 |
| evasion_retrain:gemma4 | 1.000 | 0.075 | 0.902 |
| no_state:llama | 0.783 | 0.100 | 0.844 |
| evasion:llama | 0.667 | 0.025 | 0.845 |
| evasion_retrain:llama | 0.667 | 0.025 | 0.845 |
| no_state:qwen | 0.125 | 0.100 | 0.511 |
| environment:empty | 0.922 | 0.075 | 0.912 |
| environment:ctf | 0.765 | 0.025 | 0.857 |

### Düşük FPR hedefi

Eşikler yalnız 80 calibration insanından seçilir; test insanı sayısı 40 olduğu için test FPR çözünürlüğü %2.5’tir. Bu veriyle %1 gerçek popülasyon FPR garantisi verilmez. Ayrıntılı hedef/gerçekleşen değerler `host_v2.json` içindedir.

| Dışarıda tutulan model | %1 hedefinde recall / test FPR | %5 hedefinde recall / test FPR |
|---|---|---|
| gemini3pro | 0.357 / 0.000 | 0.857 / 0.025 |
| geminiflash | 0.490 / 0.000 | 0.857 / 0.025 |
| gemma3 | 0.042 / 0.000 | 0.708 / 0.025 |
| gemma4 | 0.391 / 0.000 | 0.783 / 0.025 |
| llama | 0.348 / 0.000 | 0.826 / 0.000 |
| qwen | 0.500 / 0.000 | 1.000 / 0.025 |

### GNN kaçınma ve durum-komutu kontrolleri

| Deney | SVC recall | GNN ortalama recall / FPR | Ensemble ortalama recall / FPR |
|---|---:|---|---|
| no_state:gemini3pro | 0.643 | 0.548 / 0.242 | 0.643 / 0.242 |
| no_state:geminiflash | 0.735 | 0.687 / 0.167 | 0.776 / 0.208 |
| evasion:geminiflash | 1.000 | 0.392 / 0.083 | 1.000 / 0.108 |
| evasion_retrain:geminiflash | 1.000 | 0.569 / 0.158 | 1.000 / 0.167 |
| no_state:gemma3 | 0.500 | 0.444 / 0.325 | 0.611 / 0.325 |
| evasion:gemma3 | 0.750 | 0.250 / 0.092 | 0.875 / 0.092 |
| evasion_retrain:gemma3 | 0.875 | 0.375 / 0.133 | 0.875 / 0.142 |
| no_state:gemma4 | 0.826 | 0.826 / 0.308 | 0.928 / 0.333 |
| evasion:gemma4 | 1.000 | 0.250 / 0.100 | 1.000 / 0.100 |
| evasion_retrain:gemma4 | 1.000 | 1.000 / 0.117 | 1.000 / 0.133 |
| no_state:llama | 0.783 | 0.812 / 0.300 | 0.855 / 0.308 |
| evasion:llama | 0.667 | 0.333 / 0.050 | 0.667 / 0.050 |
| evasion_retrain:llama | 0.667 | 0.889 / 0.108 | 0.889 / 0.125 |
| no_state:qwen | 0.125 | 0.375 / 0.200 | 0.375 / 0.225 |

## Tek değişkenli artefakt kontrolleri

Aynı örneklem ve splitler korunarak yalnız tarihsel komut dönüşümlerini çıkarmanın SVC recall etkisi:

| Model | Kayıtlı komutlar | Modelden çıkarılan komutlar |
|---|---:|---:|
| gemini3pro | 1.000 | 0.857 |
| geminiflash | 0.939 | 0.939 |
| gemma3 | 0.792 | 0.708 |
| gemma4 | 0.870 | 0.783 |
| llama | 1.000 | 0.913 |
| qwen | 1.000 | 1.000 |

Aynı 14 pcap, aynı Random Forest ve oturum-dışı split ile eski network özelliklerinin macro F1'i **0.785**, yön ayrımı düzeltildikten sonra **0.714**. Bu bir ön-işleme ablation kontrolüdür; görülmemiş model genelleme deneyi değildir.

## Network ve ortak katman değerlendirmesi

Aşağıdaki değerler aynı test oturumlarında macro F1’dir. AI modelinin tüm oturumları eğitimden çıkarılır; negatif replay kaynak grupları da train/calibration/test arasında ayrılır. Zamanlamasız network, paket hızını ve SYN aralıklarını kullanmaz; araç seçimi/tarama bütçesi karışıklığı yine kalabilir.

| Veri / fold | Host | Network (zamansız) | Host+network (zamansız) | Network (+zamanlama) | Host+network (+zamanlama) |
|---|---:|---:|---:|---:|---:|
| Eski pcap / model:gemma3:4b | 0.733 | 0.733 | 0.733 | 1.000 | 1.000 |
| Eski pcap / model:gemma4 | 0.733 | 0.733 | 0.733 | 0.733 | 0.733 |
| Eski pcap / model:llama3.1:8b | 0.733 | 0.733 | 0.733 | 0.733 | 0.733 |
| Eski pcap / model:qwen3:4b | 0.733 | 1.000 | 1.000 | 1.000 | 1.000 |
| Yeni eşlenmiş / model:gemma3:4b | 0.778 | 1.000 | 1.000 | 1.000 | 1.000 |
| Yeni eşlenmiş / model:gemma4:latest | 0.778 | 1.000 | 1.000 | 0.911 | 0.911 |
| Yeni eşlenmiş / model:llama3.1:8b | 0.778 | 1.000 | 1.000 | 1.000 | 1.000 |
| Yeni eşlenmiş / model:qwen3:4b | 0.778 | 1.000 | 1.000 | 1.000 | 1.000 |
| Yeni eşlenmiş / environment:a | 0.818 | 1.000 | 1.000 | 1.000 | 1.000 |
| Yeni eşlenmiş / environment:b | 0.600 | 1.000 | 1.000 | 0.884 | 0.884 |
| Yeni eşlenmiş / context_policy:full_history | 0.804 | 1.000 | 1.000 | 0.928 | 0.928 |
| Yeni eşlenmiş / context_policy:recent_history | 0.804 | 1.000 | 1.000 | 1.000 | 1.000 |
| Yeni eşlenmiş / unseen_script_controls | — | — | — | — | — |

Yeni negatifler canlı insan değil replay olduğundan bu sonuçlar insan–AI saha başarısı değildir. AI’ye verilen dar port bütçesi ile arşiv komutlarının görevleri aynı değildir. Dört script kontrolü eğitimde görülmemiştir; bunların F1’i yalnız negatiflerden oluştuğu için aşağıda daha anlamlı olan yanlış alarm oranı ayrıca verilir.

| Yöntem | Görülmemiş script FPR |
|---|---:|
| host_only | 0.500 |
| network_no_timing | 0.500 |
| host_network_no_timing | 0.500 |
| network_rf_no_timing | 1.000 |
| network_with_timing | 0.500 |
| host_network_with_timing | 0.500 |
| network_rf_with_timing | 1.000 |

### Komut üretebilen AI oturumlarıyla duyarlılık kontrolü

Komut üreten AI oturumu: 24. Tam-denominator sonuçları yukarıdadır; `nonempty_ai_folds` içindeki ikinci analiz boş ajan yanıtlarının ayrımı ne kadar taşıdığını gösterir.

| Dışarıda tutulan model | Host F1 | Network zamansız F1 | Birleşik zamansız F1 |
|---|---:|---:|---:|
| gemma3:4b | 0.778 | 1.000 | 1.000 |
| gemma4:latest | 0.778 | 1.000 | 1.000 |
| llama3.1:8b | 0.778 | 1.000 | 1.000 |

### Aynı AI komutlarının script olarak tekrar oynatılması

Bu kontrol, komut kaynağı ile o anda karar veren operatörü ayırır. Host girdisi aynıdır; yalnız yürütme/zamanlama ve ağ tepkileri değişebilir. Skorlar kalibre edilmiş olasılık değildir.

| Çift | Host AI / script skoru | Network zamansız AI / script skoru | Network zamanlı AI / script skoru |
|---|---|---|---|

## Görev kapsamı ve yürütme başarısızlıkları

Kapsam, beklenen açık servislerden pcap içinde SYN+ACK yanıtı gözlenenlerin oranıdır. Ajanın çıktıyı doğru anladığını veya exploit yaptığını kanıtlamaz. Buna rağmen hiç ilerlemeyen ajanları başarılı recon ile karıştırmamak için yararlıdır.

| Model / köken | Oturum | Ortalama açık-servis kapsamı | Çalıştırılan komut | Timeout | Sıfır dışı çıkış kodu |
|---|---:|---:|---:|---:|---:|
| gemma3:4b | 8 | 0.411 | 48 | 15 | 24 |
| gemma4:latest | 8 | 1.000 | 43 | 0 | 4 |
| human_replay | 12 | 0.892 | 72 | 4 | 14 |
| llama3.1:8b | 8 | 1.000 | 37 | 3 | 10 |
| qwen3:4b | 8 | 0.000 | 0 | 0 | 0 |
| script | 4 | 0.240 | 18 | 0 | 3 |

## Niyet ekseni

Tüm korpuslarda grup-dışı macro F1: **0.896**. Yalnız AI içinde model-dışı macro F1: **0.785**.

Bunlar kötü niyetin bağımsız doğrulanması değildir: MUNI ve Schonlau farklı kaynak/dönemlerdir. Etiketler gerçek zarar kanıtından değil verilen görevlerden gelir. Canlı, eş görevli insan benign/malicious deneyi olmadan bu sorun çözülmüş sayılmaz.

## Tamamlananlar ve kalanlar

- Tamamlandı: komut fallback düzeltmesi, provenance kayıtları, yönlü network özellikleri, SYN tabanlı SSH yönü, eğitim-içi ön işleme, aynı girdili modeller, üç GNN tohumu, ablation kontrolleri, Wilson aralıkları ve calibration eşikleri.
- Tamamlandı: tarihsel host/pcap yeniden analizi ve yeni eşlenmiş laboratuvar koleksiyonu; aynı splitlerde host/network/birleşik değerlendirme; script ve başarısız-ajan kontrolleri.
- Kalan: aynı görev ve bütçede canlı insan katılımcıları, bağımsız ajan frameworkleri, daha geniş görev/ortam örneklemi, yeni protokolde görev başarısı korunarak adaptif kaçınma, gerçek ağ jitter/loss deneyi, bağımsız saha testi.
- HASSH için yeni bir AI-origin doğrulaması yapılmadı. İstemci kimliği otonom AI operatörünün kanıtı değildir.

## Tekrar üretim ve artefaktlar

- [Protokol ve çalıştırma komutları](PROTOCOL.md)
- [Host tahminleri, CI ve eşikler](host_v2.json)
- [Network ve birleşik katman tahminleri](network_v2.json)
- [Niyet analizi](intent_v2.json)
- [Model/imaj kimlikleri](runtime_manifest.json)
- [Paket sürümleri](requirements-lock.txt)

Ham oturumlar ve pcap dosyaları `harness/runs/corrected_v2/` altında yereldir ve git-ignore kapsamındadır. Sonuç JSON’ları ve bu rapor versiyonlanabilir. Wilson aralıkları oturum bağımlılığı ve eğitim belirsizliğini kapsamaz; küçük pilot sonuçları dağıtım garantisi değildir.

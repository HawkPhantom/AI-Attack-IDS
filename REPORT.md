<h1 align="center">AI-Attack IDS · Technical Report</h1>
<p align="center"><b>Detecting an AI operator behind the shell, under equalized task and budget.</b></p>

<p align="center">
  <a href="#-english"><img src="https://img.shields.io/badge/lang-English-0072B2?style=for-the-badge" alt="English"></a>
  <a href="#-türkçe"><img src="https://img.shields.io/badge/dil-Türkçe-E69F00?style=for-the-badge" alt="Türkçe"></a>
</p>

> Method and exact commands: **[experiments/PROTOCOL.md](experiments/PROTOCOL.md)** ·
> full per-fold tables: **[experiments/MATCHED_RESULTS.md](experiments/MATCHED_RESULTS.md)** ·
> required live-human follow-up: **[experiments/HUMAN_STUDY.md](experiments/HUMAN_STUDY.md)**.

---

<details open id="-english">
<summary><h2>🇬🇧 English</h2></summary>

### Summary

| what | result |
|---|---|
| Network + timing (SVC) vs automation | AUROC **0.92** at **0.01** test FPR (recall 0.82) |
| Host + network + timing vs automation | AUROC **0.95** at **0.00** test FPR (recall 0.72) |
| Host command-name TF-IDF vs automation | AUROC 0.87 but recall 0.24, unstable across splits — weak signal |
| Port / command / state controls | 0.61 / 0.77 / 0.50 — budget matched; command *volume* a partial confound; state tokens constant |
| Matched emulated-WAN impairment (both classes) | separation survives (RF+timing AUROC 0.96, 0 FP) |
| Frozen unseen test (tasks/profiles/families) | 0/16 false positives (network+timing AUROC 0.89, RF+timing 1.00) |
| Intent (corpus classification) | grouped **0.896**, AI-only **0.785** — descriptive, not malice |
| Human class | **replayed archived commands, not live participants** |

The project asks whether an intrusion detector can identify an AI operator behind a shell session from the command sequence and the network traffic, once the comparison is fair — equalizing task and tool/scan budget across operators and measuring against deterministic automation over a wide pool of independent script families. The honest reading: network and combined detectors (especially with inter-packet timing) **do separate AI from automation with AUROC ~0.9 and a low test false-positive rate**, the separation **survives matched emulated-WAN impairment and a frozen test on unseen tasks/profiles/negative-families**, but the host command-name baseline is weak and unstable, and none of this is a *validated* low-FPR detector: the negatives are deterministic automation (not live humans), the FP resolution is coarse, and command volume remains a partial confound.

### 1 · The question — origin, not attribution

We are not asking *which* LLM this is, only whether the operator is a language model. The design exists to stop that question collapsing into an easier one: if the AI and its comparison classes differ in task, tool budget or scan breadth, a detector separates them without learning about agency. So origin is measured against automation under a matched budget, and single-feature controls check that the budget really is matched.

### 2 · Design

Each session is captured as a command sequence and a directional pcap, for three operator classes on one isolated lab, under equal command timeouts and no injected recovery commands:

- **AI agents** — gemma3, gemma4, llama3.1, qwen3, driven by two independent scaffolds (our native loop and the upstream `smolagents` tool-calling agent sharing the same shell executor).
- **`script`** — eight deterministic families (nmap/nc/curl/`/dev/tcp` variants) as negative controls.
- **`human_live`** — participants choosing commands from the same instructions and outputs. The consent/collection package is ready but **no participant data exists**; today's human negatives are replayed archived commands (`human_replay`), which is not a live decision and is labelled distinctly.

Every operator gets the same instructions, the same six in-scope ports and the same six-command budget. The evaluation contract (`scripts/eval_common.py`) fits vocabulary/TF-IDF/scalers on training data only; holds out whole AI models, tasks, environments and negative source-groups; selects false-positive thresholds only on a separate calibration set; reports Wilson intervals and a group-resampling cluster bootstrap; and quarantines incompletely-captured sessions rather than scoring them.

### 3 · Command and network behavior against automation

Leave-one-model-out, each held-out AI model versus deterministic scripts under the matched budget, with a wide negative pool of **16 independent script families** (several families per calibration/test split):

| detector | AUROC | recall @cal-5% | test FPR |
|---|---:|---:|---:|
| port count only *(control)* | 0.61 | 0.23 | 0.00 |
| command count only *(control)* | 0.77 | 0.00 | 0.00 |
| state-check share only *(control)* | 0.50 | 0.00 | 0.00 |
| host command-name TF-IDF | 0.87 | 0.24 | 0.00 |
| network SVC, no timing | 0.92 | 0.67 | 0.14 |
| network SVC, with timing | 0.92 | 0.82 | 0.01 |
| network RF, with timing | 0.94 | 0.51 | 0.00 |
| host + network, with timing | 0.95 | 0.72 | 0.00 |

The controls confirm the budget is matched — port count alone reaches only 0.61 — while **command count reaches 0.77**, so command volume is a partial confound, and **state-check share is 0.50 because those tokens never appear in these matched sessions** (a constant feature, not evidence that a script and an LLM look alike). The **host command-name TF-IDF** baseline reaches AUROC 0.87 but its recall at a 5%-calibrated threshold is only 0.24 and it inverts on some splits — computed from the first token of the first six commands, it is a weak, unstable signal. **Network and combined models separate AI from automation and hold a low test false-positive rate** across the wide negative pool of independent families: network+timing AUROC 0.92 at 0.01 FPR (recall 0.82), host+network+timing 0.95 at 0.00 FPR. This is still not a *validated* deployment FPR — each split holds only tens of negatives (a zero-FP fold has a wide exact upper bound), the negatives are automation not live humans, and cluster intervals are wide.

### 4 · Identical commands, different operator

Replaying an AI session's exact commands as a script isolates the operator from the command text:

| detector | AUROC |
|---|---:|
| host command-name TF-IDF | 0.50 |
| network SVC, no timing | 0.50 |
| network SVC, with timing | 0.81 |

Command-name features tie by construction across the 13 pairs — a consistency check, not a finding. Timing features add some separation, but each row is a two-sample fold and the mean is over 13 folds; local-model inference waits versus wait-free replay are an expected timing difference, so this is "timing adds separation under these conditions," not an established AI-specific signal. "Did an AI write this command?" and "is an AI deciding online now?" remain different questions.

### 5 · Evasion, matched impairment, and a frozen test

**Evasion.** Of 32 attempts (30 eligible), **9 produce the exact correct answer** (gemma4 6, llama 2, qwen 1) — several models complete the task. The state-check share does not "collapse" — those tokens are zero in the normal condition too. Two evasion sessions **exceeded the port budget** (~1000 TCP ports), recorded and excluded from matched-budget claims; the success-gated subset is in `successful_ai_sensitivity` per fold. Detection holds under evasion (network+timing AUROC 0.97 at 0.01 FPR). An agent that suppresses all useful reconnaissance is not counted as evading.

**Matched emulated-WAN impairment.** An emulated netem profile — delay 80ms±40ms (normal), 1.5% correlated loss, 5% reordering — is applied to **both** AI and scripts (16 impaired AI, 32 impaired scripts) and evaluated impaired-AI vs impaired-scripts, with the threshold re-fit on impaired negatives. The separation survives (network RF+timing AUROC 0.96, recall 0.81, 0 FP; network+timing 0.72). This remains emulation on a single Docker host with capture on the operator container's `eth0`, **not** a real wide-area network.

**Frozen confirmatory test.** With the detector and threshold frozen on the development data, a held-out set of **unseen tasks (triage, dbweb), unseen service profiles (c, d) and 4 reserved script families** (`nmap_reason`, `nmap_seq`, `ssh_probe`, `telnet_probe`) is scored **once**: network+timing and host+network reach **0/16 false positives** (AUROC 0.86–0.89), RF+timing AUROC 1.00. Encouraging generalization, but 16 negatives still leave a wide exact 95% FP upper bound.

### 6 · Against archived human command corpora

Compared against a different human corpus (archived cyber-range logs) rather than automation, command content separates far better — leave-one-model-out recall 0.71–1.00 — but that comparison carries the corpus, era, task and installed-tool differences between two data sources, so it measures those alongside agency. A graph model over the command-transition topology does not beat the lexical baseline (shuffling order or removing edges barely changes it), so the added structure is not where a signal lives. This is why the controlled comparison is against automation under a matched budget.

### 7 · Intent (malicious vs benign)

Task category separates at leave-one-group-out macro F1 **0.896** across corpora and **0.785** within the AI side. This is descriptive corpus classification: the corpora differ in source and era and labels come from the assigned task, not proven harm. A permuted-label control cannot remove that provenance confound. No malice claim follows without a live, matched-task human study.

### 8 · Honest limitations

- **The human class is replay, not live participation** — the largest limitation. The question needs live participants choosing commands from the same task and outputs ([HUMAN_STUDY.md](experiments/HUMAN_STUDY.md)).
- **Pilot sample.** 253 attempts, 237 eligible (112 AI, 128 script across 16 families, 13 counterfactual; 16 quarantined). Every AI attempt is repeat 0. Each split holds several negative families but still only tens of negatives, so a zero-FP fold has a wide exact upper bound; cluster intervals are wide.
- **The signal is real but not deployment-validated.** Network and combined detectors reach AUROC ~0.92–0.95 at ~0–1% test FPR, survive matched impairment, and generalize on a frozen unseen test — but the negatives are deterministic automation, not live humans, and the FP resolution is coarse. The host command-name baseline is weak and unstable (AUROC 0.87, recall 0.24, inverts on some splits).
- **Command volume is a partial confound** the matched budget does not fully remove (command-count control 0.77); two evasion sessions exceeded the budget.
- **Four local open-weight models across three families** (gemma×2, llama, qwen); two scaffolds share one executor; a network-only defender does not see the commands captured inside the operator container.
- **Open work:** live matched-task humans, more independently-implemented agents, many more independent negatives, broader tasks/environments, a realistic-network experiment.

### 9 · Reproduction and artifacts

Protocol and commands: [PROTOCOL.md](experiments/PROTOCOL.md) · full tables: [MATCHED_RESULTS.md](experiments/MATCHED_RESULTS.md) · per-fold predictions/thresholds and runtime/dependency locks under `experiments/`. Raw sessions and pcaps are local, git-ignored; result JSONs and these documents are versioned.

### Data sources

| dataset | role | link |
|---|---|---|
| **MUNI shell commands** | archived human commands (replayed as negatives; intent corpus) | [Zenodo 8136017](https://zenodo.org/records/8136017) (CC-BY-4.0) |
| **DTU "Honey for the Agent"** | AI-attack reference, deception design | [Zenodo 20818246](https://zenodo.org/records/20818246) (CC-BY-4.0) |
| **Schonlau SEA** | real benign human command streams (intent corpus) | [schonlau.net](https://www.schonlau.net/intrusion.html) |
| **Gemini 3.x API** | frontier AI host sessions | [ai.google.dev](https://ai.google.dev) |
| **TRACE** | fingerprinting-pipeline reference | [arXiv 2605.01186](https://arxiv.org/abs/2605.01186) |

</details>

---

<details id="-türkçe">
<summary><h2>🇹🇷 Türkçe</h2></summary>

### Özet

| ne | sonuç |
|---|---|
| Ağ + zamanlama (SVC), otomasyona karşı | AUROC **0.92**, **%1** test FPR (recall 0.82) |
| Host + ağ + zamanlama, otomasyona karşı | AUROC **0.95**, **%0** test FPR (recall 0.72) |
| Host komut-adı TF-IDF | AUROC 0.87 ama recall 0.24, split'ler arası kararsız — zayıf sinyal |
| Port / komut / durum kontrolleri | 0.61 / 0.77 / 0.50 — bütçe eşit; komut *hacmi* kısmi confound; durum token'ları sabit |
| Eşit emüle-WAN bozunumu (iki sınıf) | ayrım hayatta kalıyor (RF+zamanlama AUROC 0.96, 0 FP) |
| Dondurulmuş görülmemiş test (görev/profil/aile) | 0/16 yanlış-pozitif (ağ+zamanlama AUROC 0.89, RF+zamanlama 1.00) |
| Niyet (korpus sınıflandırma) | gruplu **0.896**, yalnız-AI **0.785** — betimsel, kötü-niyet değil |
| İnsan sınıfı | **oynatılmış arşiv komutları, canlı katılımcı değil** |

Proje, bir saldırı dedektörünün — karşılaştırma adil hale getirildiğinde — operatörün bir AI ajanı olduğunu komut dizisi ve ağ trafiğinden tanıyıp tanıyamayacağını sorar; görevi ve araç/tarama bütçesini eşitler ve geniş bir bağımsız script-ailesi havuzuyla deterministik otomasyona karşı ölçer. Dürüst okuma: ağ ve birleşik dedektörler (özellikle paketler-arası zamanlamayla) **AI'yı otomasyondan AUROC ~0.9 ve düşük test yanlış-pozitif oranıyla ayırıyor**, ayrım **eşit emüle-WAN bozunumunu ve görülmemiş görev/profil/negatif-aile üzerinde dondurulmuş bir testi atlatıyor**, ama host komut-adı baseline'ı zayıf ve kararsız, ve bunların hiçbiri *doğrulanmış* düşük-FPR bir dedektör değil: negatifler canlı insan değil otomasyon, FP çözünürlüğü kaba, ve komut hacmi kısmi bir confound olarak kalıyor.

### 1 · Soru — atıf değil köken

*Hangi* LLM olduğunu değil, operatörün bir dil modeli olup olmadığını soruyoruz. Tasarım, bu sorunun daha kolay bir soruya çökmesini engellemek için var: AI ile karşılaştırma sınıfları görev, araç bütçesi veya tarama genişliğinde farklıysa, dedektör onları ajans öğrenmeden ayırır. Bu yüzden köken eşit bütçe altında otomasyona karşı ölçülür, ve tek-özellikli kontroller bütçenin gerçekten eşit olduğunu denetler.

### 2 · Tasarım

Her oturum komut dizisi ve yönlü pcap olarak yakalanır; tek izole laboratuvarda üç operatör sınıfı için, eşit komut zaman aşımlarıyla ve enjekte edilmiş kurtarma komutu olmadan:

- **AI ajanları** — gemma3, gemma4, llama3.1, qwen3; iki bağımsız iskele ile (kendi native döngümüz ve aynı shell yürütücüsünü paylaşan upstream `smolagents` araç-çağıran ajanı).
- **`script`** — negatif kontrol olarak sekiz deterministik aile (nmap/nc/curl/`/dev/tcp` çeşitleri).
- **`human_live`** — aynı talimat ve çıktılardan komut seçen katılımcılar. Onam/toplama paketi hazır ama **katılımcı verisi yok**; bugünkü insan negatifleri oynatılmış arşiv komutlarıdır (`human_replay`) — canlı bir karar değil ve ayrı etiketlenir.

Her operatör aynı talimatı, aynı altı kapsam-içi portu ve aynı altı-komut bütçesini alır. Değerlendirme sözleşmesi (`scripts/eval_common.py`) sözlük/TF-IDF/ölçekleyicileri yalnız eğitimde fit eder; AI modellerini, görevleri, ortamları ve negatif kaynak-gruplarını bütünüyle dışarıda tutar; yanlış-pozitif eşiklerini yalnız ayrı bir calibration setinde seçer; Wilson aralıkları ve grup-yeniden-örnekleyen bir cluster bootstrap raporlar; ve eksik-yakalanan oturumları skorlamak yerine karantinaya alır.

### 3 · Komut ve ağ davranışı otomasyona karşı

Leave-one-model-out, her dışarıda tutulan AI modeli eşit bütçe altında deterministik scriptlere karşı, **16 bağımsız script ailesinden oluşan geniş bir negatif havuzuyla** (split başına birkaç aile):

| dedektör | AUROC | recall @kal-%5 | test FPR |
|---|---:|---:|---:|
| yalnız port sayısı *(kontrol)* | 0.61 | 0.23 | 0.00 |
| yalnız komut sayısı *(kontrol)* | 0.77 | 0.00 | 0.00 |
| yalnız durum-kontrol payı *(kontrol)* | 0.50 | 0.00 | 0.00 |
| host komut-adı TF-IDF | 0.87 | 0.24 | 0.00 |
| ağ SVC, zamanlamasız | 0.92 | 0.67 | 0.14 |
| ağ SVC, zamanlamalı | 0.92 | 0.82 | 0.01 |
| ağ RF, zamanlamalı | 0.94 | 0.51 | 0.00 |
| host + ağ, zamanlamalı | 0.95 | 0.72 | 0.00 |

Kontroller bütçenin eşit olduğunu doğruluyor — yalnız port sayısı 0.61 — ama **komut sayısı 0.77'ye ulaşıyor** (komut hacmi kısmi confound), ve **durum-kontrol payı 0.50 çünkü o token'lar bu eşit oturumlarda hiç geçmiyor** (sabit özellik). **Host komut-adı TF-IDF** AUROC 0.87 alıyor ama %5-kalibre eşikte recall'ı yalnız 0.24 ve bazı split'lerde tersleniyor — ilk altı komutun ilk kelimesinden hesaplanan zayıf, kararsız bir sinyal. **Ağ ve birleşik modeller AI'yı otomasyondan ayırıyor ve geniş bağımsız-aile negatif havuzunda düşük test yanlış-pozitif oranı tutuyor**: ağ+zamanlama AUROC 0.92, %1 FPR (recall 0.82); host+ağ+zamanlama 0.95, %0 FPR. Bu hâlâ *doğrulanmış* bir dağıtım FPR'si değil — split başına yalnız onlarca negatif (sıfır-FP fold'un geniş exact üst sınırı), negatifler canlı insan değil otomasyon, ve cluster aralıkları geniş.

### 4 · Aynı komutlar, farklı operatör

Bir AI oturumunun tam komutlarını script olarak oynatmak, operatörü komut metninden ayırır:

| dedektör | AUROC |
|---|---:|
| host komut-adı TF-IDF | 0.50 |
| ağ SVC, zamanlamasız | 0.50 |
| ağ SVC, zamanlamalı | 0.81 |

13 çiftte komut-adı özellikleri yapısı gereği eşitlenir — bir tutarlılık kontrolü, bir bulgu değil. Zamanlama özellikleri bir miktar ayrım ekliyor, ama her satır iki-örnekli bir fold ve ortalama 13 fold üzerinden; yerel-model çıkarım beklemeleri ile beklemesiz replay beklenen bir zamanlama farkıdır, yani bu "bu koşullarda zamanlama ayrım ekliyor" demek, AI'ya özgü kanıtlanmış bir sinyal değil. "Bu komutu bir AI mı yazdı?" ve "şimdi çevrimiçi kararı bir AI mı veriyor?" farklı sorular olarak kalıyor.

### 5 · Kaçınma, eşit bozunum ve dondurulmuş test

**Kaçınma.** 32 denemenin (30 uygun) **9'u tam doğru cevabı üretiyor** (gemma4 6, llama 2, qwen 1) — birkaç model tamamlıyor. Durum-kontrol payı "çökmüyor" — normal koşulda da sıfır. İki oturum **port bütçesini aştı** (~1000 port), kayıtlı ve dışlanmış; başarı-kapılı alt küme `successful_ai_sensitivity`'de. Kaçınma altında tespit tutuyor (ağ+zamanlama AUROC 0.97, %1 FPR). Tüm yararlı keşfi bastıran ajan kaçınmış sayılmaz.

**Eşit emüle-WAN bozunumu.** Emüle netem profili — gecikme 80ms±40ms (normal), %1.5 korelasyonlu kayıp, %5 reordering — **hem** AI'ya **hem** scriptlere uygulandı (16 bozunmuş AI, 32 bozunmuş script), bozunmuş-vs-bozunmuş değerlendirildi, eşik bozunmuş negatiflerde yeniden fit edildi. Ayrım hayatta kalıyor (ağ RF+zamanlama AUROC 0.96, recall 0.81, 0 FP; ağ+zamanlama 0.72). Bu tek Docker host'ta emülasyon, operatör konteynerinin `eth0`'ında yakalama, **gerçek** bir WAN değil.

**Dondurulmuş doğrulama testi.** Dedektör ve eşik geliştirmede donduruldu; **görülmemiş görevler (triage, dbweb), görülmemiş servis profilleri (c, d) ve 4 rezerve script ailesi** (`nmap_reason`, `nmap_seq`, `ssh_probe`, `telnet_probe`) bir kez skorlandı: ağ+zamanlama ve host+ağ **0/16 yanlış-pozitif** (AUROC 0.86–0.89), RF+zamanlama AUROC 1.00. Umut verici genelleme, ama 16 negatif hâlâ geniş bir exact %95 FP üst sınırı bırakıyor.

### 6 · Arşiv insan komut korpuslarına karşı

Otomasyon yerine farklı bir insan korpusuna (arşivlenmiş cyber-range kayıtları) karşı komut içeriği çok daha iyi ayırıyor — leave-one-model-out recall 0.71–1.00 — ama o karşılaştırma iki veri kaynağı arasındaki korpus, dönem, görev ve kurulu-araç farklarını taşır, dolayısıyla ajans yanında bunları da ölçer. Komut-geçiş topolojisi üzerinde bir grafik model sözcüksel baseline'ı geçmiyor (sırayı karıştırmak veya kenarları çıkarmak neredeyse değiştirmiyor), yani ek yapı sinyalin yaşadığı yer değil. Kontrollü karşılaştırmanın eşit bütçe altında otomasyona karşı olmasının nedeni budur.

### 7 · Niyet (zararlı vs zararsız)

Görev kategorisi korpuslar arasında leave-one-group-out macro F1 **0.896** ve AI içinde **0.785** ile ayrılıyor. Bu betimsel korpus sınıflandırmasıdır: korpuslar kaynak/dönem olarak farklı ve etiketler kanıtlı zarardan değil verilen görevden gelir. Permüte-etiket kontrolü bu köken confound'unu kaldıramaz. Canlı, eş görevli insan çalışması olmadan niyet iddiası çıkmaz.

### 8 · Dürüst sınırlamalar

- **İnsan sınıfı replay'dir, canlı katılım değil** — en büyük sınırlama. Soru, aynı görev ve çıktılardan komut seçen canlı katılımcılar gerektirir ([HUMAN_STUDY.md](experiments/HUMAN_STUDY.md)).
- **Pilot örneklem.** 253 deneme, 237 uygun (112 AI, 16 aileye yayılan 128 script, 13 counterfactual; 16 karantina). Her AI denemesi repeat 0. Her split birkaç negatif aile içeriyor ama hâlâ yalnız onlarca negatif, dolayısıyla sıfır-FP fold'un geniş bir exact üst sınırı var; cluster aralıkları geniş.
- **Sinyal gerçek ama dağıtım-doğrulaması yok.** Ağ ve birleşik dedektörler AUROC ~0.92–0.95'e, ~%0–1 test FPR ile ulaşıyor, eşit bozunumu atlatıyor ve dondurulmuş görülmemiş testte genelleşiyor — ama negatifler canlı insan değil otomasyon, FP çözünürlüğü kaba. Host komut-adı baseline'ı zayıf ve kararsız (AUROC 0.87, recall 0.24, bazı split'lerde tersleniyor).
- **Komut hacmi, eşit bütçenin tam gideremediği kısmi bir confound** (komut-sayısı kontrolü 0.77); iki kaçınma oturumu bütçeyi aştı.
- **Üç aileye yayılan dört yerel açık-ağırlık model** (gemma×2, llama, qwen); iki iskele tek yürütücü paylaşıyor; yalnız-ağ savunucusu operatör konteynerinde yakalanan komutları görmez.
- **Açık işler:** canlı eş-görevli insanlar, daha fazla bağımsız uygulanmış ajan, çok daha fazla bağımsız negatif, daha geniş görev/ortamlar, gerçekçi bir ağ deneyi.

### 9 · Tekrar üretim ve veri kaynakları

Protokol ve komutlar [PROTOCOL.md](experiments/PROTOCOL.md); tüm tablolar [MATCHED_RESULTS.md](experiments/MATCHED_RESULTS.md); fold-bazlı tahminler/eşikler ve runtime/bağımlılık kilitleri `experiments/` altında. Veri kaynakları için yukarıdaki İngilizce tabloya bakın.

</details>

---

<p align="center"><sub>Local open-weight models (Ollama) + Docker · isolated lab · research and defensive use only</sub></p>

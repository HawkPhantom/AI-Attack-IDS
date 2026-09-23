<h1 align="center">AI-Attack IDS · Technical Report</h1>
<p align="center"><b>Detecting an AI operator behind the shell, from host and network behavior.</b></p>

<p align="center">
  <a href="#-english"><img src="https://img.shields.io/badge/lang-English-0072B2?style=for-the-badge" alt="English"></a>
  <a href="#-türkçe"><img src="https://img.shields.io/badge/dil-Türkçe-E69F00?style=for-the-badge" alt="Türkçe"></a>
</p>

> The method and exact commands are in **[experiments/PROTOCOL.md](experiments/PROTOCOL.md)**;
> the required live-human follow-up is in **[experiments/HUMAN_STUDY.md](experiments/HUMAN_STUDY.md)**;
> per-fold predictions and thresholds are under `experiments/`.

---

<details open id="-english">
<summary><h2>🇬🇧 English</h2></summary>

### Summary

| what | result |
|---|---|
| Host leave-one-model-out, lexical SVC recall (held-out model) | **0.71–1.00** at 2.5–5% human FPR (Wilson intervals wide) |
| Does the transition **graph** add signal? | **No clear gain** — shuffled-order / no-edge controls ≈ the real graph; SVC alone (0.867) > graph (0.758) |
| State-check commands (malicious/evasion set) | **503**; load-bearing but also prompt-encouraged, not proven intrinsic |
| Low false-positive target | 1% FPR **not** validated (40 test humans; 2.5% FPR resolution) |
| Network — legacy captures, directional | macro F1 **0.714** (preprocessing comparison, not generalization) |
| Network — paired lab | strong with **timing**, but loopback + replay-not-human + scan-budget confounds |
| Intent (corpus classification) | grouped F1 **0.896**; AI-only **0.785** — not independent evidence of malice |
| Human class | **replay of archived commands, not live participants** |

The project asks whether an intrusion detector can tell that the operator behind a shell session is an AI agent, from the command sequence and the network traffic. The honest reading is a real-but-modest host signal, an unproven graph contribution, a timing-dominated network signal on an unrealistic loopback, and no completed human-vs-AI field claim.

### 1 · The question — origin, not attribution

> *"Can we build an IDS that tells whether an incoming attack is driven by an AI agent rather than a human or a script, no matter which model is behind it?"*

We are not asking *which* LLM this is, only whether the operator is a language model. The tests that matter are generalization to unseen models and robustness once known confounds are controlled.

### 2 · Method

Every session is captured as a command sequence and a directional pcap, for three operator classes — AI agents, `human_replay` (archived human commands replayed by a program), and deterministic `script` controls — under equal time limits. The evaluation contract (`scripts/eval_common.py`) is conservative:

- **The model's own commands are scored.** The harness does not inject flags into agent commands. Where a logged command carries executor-added flags (337 of 3,215 malicious/evasion commands — e.g. `nmap -T4 --host-timeout 25s`, `ping -c 3`, `ssh -o BatchMode=yes …`), the model's own text from `raw_command` is used, so the detector sees agent behavior rather than harness formatting.
- **Directional network features.** Target ports/IPs/SYNs from outbound traffic only; received-RST fraction from inbound only; SSH transport direction from the first TCP SYN's endpoints.
- **Training-only preprocessing.** Common vocabulary, TF-IDF and scalers fit on training data only, after a 20-command cap, with network commands removed. Empty/unparseable sessions are kept.
- **Honest uncertainty.** Session recall/FPR with Wilson intervals; three graph seeds (17/42/73) reported as a min–max range (not a CI); FPR thresholds chosen only on a held-out calibration set; per-batch class weights that do not cancel.
- **Held-out design.** Leave-one-model-out for the AI side; disjoint human recording groups for train (147) / calibration (80) / test (40); script controls never enter training.

### 3 · Host layer — generalization to unseen models

| held-out model | AI n | SVC recall | SVC 95% Wilson | SVC FPR | graph recall (seeds) | ensemble (seeds) |
|---|---:|---:|---|---:|---|---|
| gemini-3.1-pro | 14 | 0.857 | 0.601–0.960 | 0.050 | 0.571–0.786 | 0.857 |
| gemini-3.5-flash | 49 | 0.939 | 0.835–0.979 | 0.050 | 0.959 | 0.959 |
| gemma3 | 24 | 0.708 | 0.508–0.851 | 0.025 | 0.583–0.625 | 0.792–0.833 |
| gemma4 | 23 | 0.783 | 0.581–0.903 | 0.025 | 0.565–0.696 | 0.783–0.826 |
| llama3.1 | 23 | 0.913 | 0.732–0.976 | 0.025 | 0.783–0.870 | 0.957–1.000 |
| qwen3 | 8 | 1.000 | 0.676–1.000 | 0.050 | 0.875–1.000 | 1.000 |

A held-out model is recognized above chance, but the intervals are wide and the two Gemini models are one provider (not independent frontier families). The `qwen3` row is an empty-session artifact (§6).

### 4 · Does the graph earn its keep? No clear evidence

Mean recall over the model folds (equal weight per fold):

| method | mean recall | mean human FPR |
|---|---:|---:|
| lexical SVC | **0.867** | 0.037 |
| category-frequency logistic | 0.801 | 0.079 |
| graph topology (seed 42) | 0.758 | 0.071 |
| graph, **shuffled command order** | 0.799 | 0.104 |
| graph, **edges removed** | 0.785 | 0.067 |
| OR-ensemble (SVC ∪ graph) | 0.913 | 0.087 |

Shuffling the order or deleting the edges leaves the graph model essentially unchanged, and the lexical SVC alone beats it. A high ensemble number does not demonstrate that transition *topology* carries the signal; the ensemble's 0.913 is mostly the SVC. The lexical SVC is the primary detector; the graph is an inconclusive control.

### 5 · State-check tendency, no-state and evasion controls

LLM agents re-query `pwd`/`whoami`/`id`/`uname`/`hostname` far more than the human recordings — 503 such commands across the malicious/evasion set. The recon prompts also instruct a `pwd` fallback, so this is not a prompt-free property. It is load-bearing for the detector: a `no_state` ablation (dropping those five tokens) lowers SVC recall markedly (gemma3 0.71→0.50, qwen 1.00→0.13, gemini-flash 0.94→0.74). Under evasion prompts the state share collapses and the detector's response is model-dependent (`evasion:gemma4` SVC 1.00, `evasion:llama` 0.67, `evasion:gemma3` 0.75); adversarial retraining recovers some models. Full per-experiment numbers are under `experiments/`. A prompt-free, live-human replication remains outstanding.

### 6 · Task coverage — some agents barely act

Coverage = the share of expected open services that returned a SYN+ACK; a floor on activity, not proof of comprehension or exploitation.

| operator | sessions | mean open-service coverage | commands run | timeouts | nonzero exit codes |
|---|---:|---:|---:|---:|---:|
| gemma3:4b | 8 | 0.411 | 48 | 15 | 24 |
| gemma4:latest | 8 | 1.000 | 43 | 0 | 4 |
| llama3.1:8b | 8 | 1.000 | 37 | 3 | 10 |
| **qwen3:4b** | 8 | **0.000** | **0** | 0 | 0 |
| human_replay | 12 | 0.892 | 72 | 4 | 14 |
| script | 4 | 0.240 | 18 | 0 | 3 |

`qwen3:4b` produces no usable commands, so its "detection" is detection of an empty session — a caution for any per-model number that includes it.

### 7 · Network layer

- **Legacy captures.** The 14 legacy pcaps (8 AI, 6 replay), a Random Forest and an out-of-session split give macro F1 **0.714** with directional features. These captures dropped port-22 traffic, so this is a preprocessing comparison, not an unseen-model generalization test.
- **Paired lab.** On the 48 paired sessions, host, network and combined models use identical folds. Network features — especially with inter-packet **timing** — separate AI from replay strongly (combined F1 up to 1.00; host alone ≈ 0.60–0.82). But this is a **loopback** lab with no realistic latency/loss; the negatives are replay, not live humans; and the agent's constrained port budget differs from the replay's task. Timing carries most of the separation. Four unseen scripts are frequently mis-flagged (host-only / network-no-timing false-alarm rate 0.50), so this is not a solved discrimination.
- **HASSH** identifies a *programmatic client* (paramiko vs OpenSSH), which also covers Ansible/CI, rather than agency itself.

### 8 · Intent axis (malicious vs benign)

Across the command corpora, leave-one-group-out macro F1 is **0.896**; within the AI side only, leave-one-model-out is **0.785**. This is descriptive corpus classification: the corpora differ in source and era, and the labels come from the assigned task, not from proven harm. A permuted-label control cannot remove that provenance confound. No malice claim follows without a live, matched-task human study.

### 9 · Honest limitations

- **The human class is replay, not live participation** — the single largest limitation. Live participants must choose commands from the same task instructions and outputs before any human-vs-AI claim ([HUMAN_STUDY.md](experiments/HUMAN_STUDY.md)).
- **Pilot sample.** 48 paired sessions ({ai: 32, replay: 12, script: 4}; 8 zero-traffic AI kept; 2 collector errors excluded); command/network sets similarly small. Wilson intervals ignore session dependence and training variance.
- **No validated low FPR.** With 40 test humans the FPR resolution is 2.5%; a 1% population FPR needs ≈299 independent negatives with zero false positives, far beyond this sample.
- **The graph contribution is unproven** (shuffle / no-edge ≈ real graph).
- **Two frontier models, one provider,** and the pro model was heavily API-rate-limited (small n).
- **Network is loopback and confounded** (no jitter/loss; replay ≠ human; scan-budget mismatch; timing dominates).
- **The environment/context variants are one driver** — two service profiles and two context policies of the same collector, not independent agent frameworks.
- **Open work:** live matched-task humans, independently-implemented agents, broader tasks/environments, adaptive evasion that preserves reconnaissance success, a real network-impairment experiment, independent field testing.

### Data sources

| dataset | role | link |
|---|---|---|
| **MUNI shell commands** | real human commands (replayed as negatives) | [Zenodo 8136017](https://zenodo.org/records/8136017) (CC-BY-4.0) |
| **DTU "Honey for the Agent"** | malicious+AI reference, deception design | [Zenodo 20818246](https://zenodo.org/records/20818246) (CC-BY-4.0) |
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
| Host leave-one-model-out, sözcüksel SVC recall | **0.71–1.00** (%2.5–5 insan FPR; Wilson aralıkları geniş) |
| Geçiş **grafiği** sinyal ekliyor mu? | **Net kazanç yok** — karıştırılmış/kenarsız kontroller ≈ gerçek grafik; SVC tek başına (0.867) > grafik (0.758) |
| Durum-kontrol komutu (malicious/evasion) | **503**; belirleyici ama prompt-teşvikli, içsel olduğu kanıtlı değil |
| Düşük yanlış-pozitif hedefi | %1 FPR **doğrulanmadı** (40 test insanı; %2.5 FPR çözünürlüğü) |
| Ağ — eski yakalamalar, yönlü | macro F1 **0.714** (ön-işleme karşılaştırması, genelleme değil) |
| Ağ — eşlenmiş lab | **zamanlama** ile güçlü, ama loopback + replay-insan-değil + tarama-bütçesi confound'u |
| Niyet (korpus sınıflandırma) | gruplu F1 **0.896**; yalnız-AI **0.785** — bağımsız kötü-niyet kanıtı değil |
| İnsan sınıfı | **arşiv komutlarının replay'i, canlı katılımcı değil** |

Proje, bir saldırı dedektörünün, operatörün bir AI ajanı olduğunu komut dizisi ve ağ trafiğinden ayırt edip edemeyeceğini sorar. Dürüst okuma: gerçek ama mütevazı bir host sinyali, kanıtlanmamış bir grafik katkısı, gerçekçi olmayan bir loopback'te zamanlama-baskın bir ağ sinyali ve tamamlanmamış bir insan-vs-AI saha iddiası.

### 1 · Soru — atıf değil köken

> *"Sisteme gelen bir saldırının, arkasındaki model ne olursa olsun, bir insan ya da script yerine bir AI ajanı tarafından sürüldüğünü ayırt eden bir IDS kurabilir miyiz?"*

*Hangi* LLM olduğunu değil, operatörün bir dil modeli olup olmadığını soruyoruz. Önemli sınavlar, görülmemiş modellere genelleme ve bilinen confound'lar kontrol edilince sağlamlık.

### 2 · Yöntem

Her oturum komut dizisi ve yönlü bir pcap olarak yakalanır; üç operatör sınıfı için — AI ajanları, `human_replay` (arşivlenmiş insan komutlarının bir programca oynatılması) ve deterministik `script` kontrolleri — eşit süre sınırıyla. Değerlendirme sözleşmesi (`scripts/eval_common.py`) temkinlidir:

- **Modelin kendi komutu skorlanır.** Harness ajan komutlarına bayrak enjekte etmez. Bir kayıtlı komut executor-eklentili bayrak taşıyorsa (3.215 malicious/evasion komutunun 337'si — ör. `nmap -T4 --host-timeout 25s`, `ping -c 3`, `ssh -o BatchMode=yes …`), yerine modelin `raw_command`'daki kendi metni kullanılır; böylece dedektör harness biçimlemesini değil ajan davranışını görür.
- **Yönlü ağ özellikleri.** Hedef port/IP/SYN yalnız giden; alınan-RST oranı yalnız gelen; SSH taşıma yönü ilk TCP SYN'e göre.
- **Yalnız-eğitimde ön işleme.** Ortak sözlük, TF-IDF ve ölçekleyiciler yalnız eğitimde, 20-komut sınırından sonra, ağ komutları çıkarılarak fit edilir. Boş/çözümlenemeyen oturumlar tutulur.
- **Dürüst belirsizlik.** Wilson aralıklı oturum recall/FPR; üç grafik tohumu (17/42/73) min–max aralığı olarak (güven aralığı değil); FPR eşikleri yalnız calibration setinde; iptal olmayan batch sınıf ağırlıkları.
- **Held-out tasarım.** AI tarafı için leave-one-model-out; ayrık insan kayıt grupları train (147) / calibration (80) / test (40); script kontrolleri eğitime asla girmez.

### 3 · Host katmanı — görülmemiş modele genelleme

| dışarıda tutulan model | AI n | SVC recall | SVC %95 Wilson | SVC FPR | grafik recall (tohum) | ensemble (tohum) |
|---|---:|---:|---|---:|---|---|
| gemini-3.1-pro | 14 | 0.857 | 0.601–0.960 | 0.050 | 0.571–0.786 | 0.857 |
| gemini-3.5-flash | 49 | 0.939 | 0.835–0.979 | 0.050 | 0.959 | 0.959 |
| gemma3 | 24 | 0.708 | 0.508–0.851 | 0.025 | 0.583–0.625 | 0.792–0.833 |
| gemma4 | 23 | 0.783 | 0.581–0.903 | 0.025 | 0.565–0.696 | 0.783–0.826 |
| llama3.1 | 23 | 0.913 | 0.732–0.976 | 0.025 | 0.783–0.870 | 0.957–1.000 |
| qwen3 | 8 | 1.000 | 0.676–1.000 | 0.050 | 0.875–1.000 | 1.000 |

Dışarıda tutulan model şanstan yüksek tanınıyor, ama aralıklar geniş ve iki Gemini modeli tek sağlayıcı (bağımsız frontier aile değil). `qwen3` satırı boş-oturum artefaktıdır (§6).

### 4 · Grafik hakkını veriyor mu? Net kanıt yok

Model foldları üzerinde ortalama recall (fold başına eşit ağırlık):

| yöntem | ortalama recall | ortalama insan FPR |
|---|---:|---:|
| sözcüksel SVC | **0.867** | 0.037 |
| kategori-frekansı lojistik | 0.801 | 0.079 |
| grafik topoloji (tohum 42) | 0.758 | 0.071 |
| grafik, **sırası karıştırılmış** | 0.799 | 0.104 |
| grafik, **kenarları çıkarılmış** | 0.785 | 0.067 |
| OR-topluluğu (SVC ∪ grafik) | 0.913 | 0.087 |

Sırayı karıştırmak veya kenarları silmek grafik modeli neredeyse değiştirmiyor ve sözcüksel SVC tek başına onu geçiyor. Yüksek topluluk sayısı, sinyali *topolojinin* taşıdığını kanıtlamıyor; 0.913'ün çoğu SVC. Birincil dedektör sözcüksel SVC; grafik sonuçsuz bir kontrol.

### 5 · Durum-kontrol eğilimi, no-state ve kaçınma kontrolleri

LLM ajanları `pwd`/`whoami`/`id`/`uname`/`hostname`'i insan kayıtlarından çok daha fazla sorguluyor — malicious/evasion setinde 503 komut. Keşif promptları da bir `pwd` fallback'i söylüyor, dolayısıyla promptsuz bir özellik değil. Dedektör için belirleyici: bir `no_state` ablation'ı (bu beş token'ı çıkarmak) SVC recall'ını belirgin düşürüyor (gemma3 0.71→0.50, qwen 1.00→0.13, gemini-flash 0.94→0.74). Kaçınma promptları altında durum payı çöküyor ve tepki modele bağlı (`evasion:gemma4` SVC 1.00, `evasion:llama` 0.67, `evasion:gemma3` 0.75); düşmanca yeniden eğitim bazı modelleri kurtarıyor. Deney-bazlı tüm sayılar `experiments/` altında. Promptsuz, canlı-insan replikasyonu eksik.

### 6 · Görev kapsamı — bazı ajanlar neredeyse hiç iş yapmıyor

Kapsam = SYN+ACK dönen beklenen açık servislerin oranı; etkinlik tabanı, anlama/exploit kanıtı değil.

| operatör | oturum | ortalama açık-servis kapsamı | çalıştırılan komut | timeout | sıfır-dışı çıkış |
|---|---:|---:|---:|---:|---:|
| gemma3:4b | 8 | 0.411 | 48 | 15 | 24 |
| gemma4:latest | 8 | 1.000 | 43 | 0 | 4 |
| llama3.1:8b | 8 | 1.000 | 37 | 3 | 10 |
| **qwen3:4b** | 8 | **0.000** | **0** | 0 | 0 |
| human_replay | 12 | 0.892 | 72 | 4 | 14 |
| script | 4 | 0.240 | 18 | 0 | 3 |

`qwen3:4b` kullanılabilir komut üretmiyor; "tespiti" boş oturumun tespitidir — onu içeren her model sayısı için bir uyarı.

### 7 · Ağ katmanı

- **Eski yakalamalar.** 14 eski pcap (8 AI, 6 replay), Random Forest ve oturum-dışı split, yönlü özelliklerle macro F1 **0.714**. Bu yakalamalar port-22'yi dışladı, dolayısıyla ön-işleme karşılaştırması, görülmemiş-model genellemesi değil.
- **Eşlenmiş lab.** 48 eşlenmiş oturumda host, ağ ve birleşik modeller aynı foldları kullanır. Ağ özellikleri — özellikle paketler-arası **zamanlama** ile — AI'yı replay'den güçlü ayırıyor (birleşik F1 1.00'a kadar; yalnız host ≈ 0.60–0.82). Ama bu, gerçekçi gecikme/kayıp olmayan bir **loopback** lab; negatifler replay, canlı insan değil; ajanın dar port bütçesi replay'in görevinden farklı. Ayrımı çoğunlukla zamanlama taşıyor. Dört görülmemiş script sıkça yanlış işaretleniyor (host-only / ağ-zamansız yanlış-alarm 0.50), yani çözülmüş bir ayrım değil.
- **HASSH** bir *programatik istemci* (paramiko vs OpenSSH) tanımlar, ki Ansible/CI de dahil; ajansın kendisini değil.

### 8 · Niyet ekseni (zararlı vs zararsız)

Komut korpuslarında leave-one-group-out macro F1 **0.896**; yalnız AI tarafında leave-one-model-out **0.785**. Bu betimsel korpus sınıflandırmasıdır: korpuslar kaynak ve dönem olarak farklı ve etiketler verilen görevden gelir, kanıtlı zarardan değil. Permüte-etiket kontrolü bu köken confound'unu kaldıramaz. Canlı, eş görevli insan çalışması olmadan niyet iddiası çıkmaz.

### 9 · Dürüst sınırlamalar

- **İnsan sınıfı replay'dir, canlı katılım değil** — en büyük sınırlama. Herhangi bir insan-vs-AI iddiasından önce canlı katılımcılar aynı görev talimatı ve çıktılardan komut seçmeli ([HUMAN_STUDY.md](experiments/HUMAN_STUDY.md)).
- **Pilot örneklem.** 48 eşlenmiş oturum ({ai: 32, replay: 12, script: 4}; 8 sıfır-trafik AI tutuldu; 2 collector hatası dışlandı); komut/ağ setleri de küçük. Wilson aralıkları oturum bağımlılığını ve eğitim varyansını yok sayar.
- **Doğrulanmış düşük FPR yok.** 40 test insanıyla FPR çözünürlüğü %2.5; %1 popülasyon FPR'si sıfır yanlış-pozitifle ≈299 bağımsız negatif gerektirir, bu örneklemin çok ötesinde.
- **Grafik katkısı kanıtlanmadı** (karıştırma / kenarsız ≈ gerçek grafik).
- **İki frontier model tek sağlayıcı,** ve pro model ağır API rate-limit yedi (küçük n).
- **Ağ loopback ve confound'lu** (jitter/kayıp yok; replay ≠ insan; tarama-bütçesi uyumsuz; zamanlama baskın).
- **Ortam/bağlam varyantları tek sürücü** — aynı toplayıcının iki servis profili ve iki bağlam politikası, bağımsız ajan frameworkleri değil.
- **Açık işler:** canlı eş-görevli insanlar, bağımsız uygulanmış ajanlar, daha geniş görev/ortamlar, keşif başarısını koruyan adaptif kaçınma, gerçek ağ-bozunumu deneyi, bağımsız saha testi.

### Veri kaynakları

| veri seti | rol | bağlantı |
|---|---|---|
| **MUNI shell komutları** | gerçek insan komutları (negatif olarak replay) | [Zenodo 8136017](https://zenodo.org/records/8136017) (CC-BY-4.0) |
| **DTU "Honey for the Agent"** | zararlı+AI referansı, aldatma tasarımı | [Zenodo 20818246](https://zenodo.org/records/20818246) (CC-BY-4.0) |
| **Schonlau SEA** | gerçek zararsız insan komut akışları (niyet korpusu) | [schonlau.net](https://www.schonlau.net/intrusion.html) |
| **Gemini 3.x API** | frontier AI host oturumları | [ai.google.dev](https://ai.google.dev) |
| **TRACE** | parmak izi hattı referansı | [arXiv 2605.01186](https://arxiv.org/abs/2605.01186) |

</details>

---

<p align="center"><sub>Local open-weight models (Ollama) + Docker · isolated lab · research and defensive use only</sub></p>

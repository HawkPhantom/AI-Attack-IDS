<h1 align="center">AI-Attack IDS · Technical Report</h1>
<p align="center"><b>Detecting the LLM behind the shell.</b></p>

<p align="center">
  <a href="#-english"><img src="https://img.shields.io/badge/lang-English-0072B2?style=for-the-badge" alt="English"></a>
  <a href="#-türkçe"><img src="https://img.shields.io/badge/dil-Türkçe-E69F00?style=for-the-badge" alt="Türkçe"></a>
  &nbsp;·&nbsp; <a href="https://claude.ai/code/artifact/e98339a3-aef4-451d-af14-a5e492c5dea3">interactive HTML version</a>
</p>

> **Language / Dil.** English opens by default. Click **🇹🇷 Türkçe** below for the Turkish version. An interactive HTML report with a live language toggle is linked above.

---

<details open id="-english">
<summary><h2>🇬🇧 English</h2></summary>

### Summary

| metric | value |
|---|---|
| Leave-one-model-out floor, SVC only (ablation) | **0.81** |
| Leave-one-model-out floor, SVC + GNN ensemble | **1.00** |
| Ensemble human false-positive rate | **4 %** |
| Origin-axis F1 (AI vs real human), hardest feature space | **0.962** |
| State-verification rate, LLM vs human | **25 to 120×** |
| Early detection (first 10 commands) | F1 **0.869** |
| Network layer (outbound scan traffic) | F1 **0.785** |

The project builds an intrusion-detection approach that determines whether the operator behind a session is an **AI agent**, from a behavioral signature over the command sequence that generalizes to LLM families absent from the training set. The host-layer detector is an ensemble of a lexical model (TF-IDF + LinearSVC) and a structural one (a GNN over the command-transition graph); together they lift the worst-case generalization floor to 1.00.

### 1 · The question, origin not attribution

> *"Can we build an IDS that tells whether an incoming attack is driven by an AI agent rather than a human or a script, no matter which model is behind it?"*

This is not model attribution. We are not asking *which* LLM this is. We are asking something more basic: is the operator behind the session a language model at all? We answer it by fingerprinting behavior, and the crucial test is whether that fingerprint still holds for models the detector has never seen.

### 2 · Headline result, the signature generalizes across families

In a leave-one-**model**-out test, each AI model is pulled out of training entirely and then presented as an unknown actor. Even on the most unforgiving feature space we could build (33 shared command names, arguments stripped, session length equalized, network commands removed), an unseen LLM family is still flagged as "AI" between 76 % and 100 % of the time.

![Leave-one-model-out](assets/05_leave_one_model.png)

The signal is not a "gemma signature." It is an **LLM-agent signature**, shared across `gemma3:4b`, `gemma4`, `llama3.1:8b`, and `qwen3:4b`.

### 3 · Raising the floor, the GNN ensemble

The lexical detector's weak point is its floor: gemma3 held out at 0.81 (0.76 in the strictest setting). Because it keys on specific command tokens, an unseen model that uses different tokens is harder to place. To lift that floor we added a **GNN over the command-transition graph** (`scripts/ids_gnn.py`).

Each session becomes a directed graph. A node is a distinct binary; an edge is an observed transition `cmd_i → cmd_{i+1}`, weighted by count. Node features are **behavioral categories** (state-check, enumerate, network, privilege, process, package) plus degree, frequency and self-loop signals. They deliberately carry no command name, so the GNN reads the reconnaissance *topology*, for example a state-check hub re-queried on every step, rather than the vocabulary. That is what should transfer to models whose exact commands were never seen. The model is a two-layer GraphSAGE in pure PyTorch with a dense adjacency, so it needs no PyTorch-Geometric dependency.

![GNN ensemble](assets/08_gnn_ensemble.png)

| held-out model | SVC (lexical) | GNN (structural) | **Ensemble** | human FP |
|---|---|---|---|---|
| gemma3 | 0.81 | 1.00 | **1.00** | 0.03 |
| gemma4 | 0.92 | 0.83 | **1.00** | 0.06 |
| llama3.1 | 0.86 | 1.00 | **1.00** | 0.05 |
| qwen3 | 1.00 | 0.67 | **1.00** | 0.03 |
| **floor** | **0.81** | 0.67 | **1.00** | 0.04 mean |

The GNN on its own does **not** beat the SVC; its floor of 0.67 is worse. The gain is entirely in the **ensemble**. The GNN is strong on gemma3 and llama exactly where the SVC is weak, and the SVC is strong on gemma4 and qwen where the GNN is weak. An OR-ensemble lifts the floor from 0.81 to 1.00 at only 4 % human false-positive rate, which is direct evidence that the lexical and structural-behavioral views carry complementary signal. The SVC-only pipeline is the ablation.

### 4 · Mechanism, the state-verification reflex

An LLM retains no working memory across steps, so it re-queries its execution context on every turn: working directory (`pwd`), identity (`whoami`, `id`), host and kernel (`uname`, `hostname`). A human retains this state and does not repeat the queries. The difference is large and consistent across every model tested.

![State-verification share](assets/03_state_verification.png)

| operator | `pwd`/`whoami`/`id`/`uname`/`hostname` share |
|---|---|
| **Human** (MUNI, real) | **0.7 %** |
| gemma4 | 16.7 % |
| llama3.1 | 22.9 % |
| gemma3 | 24.3 % |
| qwen3 (collapsed) | 86.7 % |

Every LLM sits 25 to 120 times above human. Notably, gemma4 (newer and more capable) checks *less* than gemma3: the signature fades as models mature, but does not disappear. The GNN's behavioral node categories are the structural encoding of exactly this reflex.

![Command frequency, AI vs human](assets/04_command_freq.png)

The same commands, opposite priorities: the AI repeatedly verifies state, while the human performs enumeration and lateral movement (`ls` 44 %, `ssh` 17 %, `ping`).

### 5 · Problem space, two independent axes

The detector treats intent and origin as separate questions, and raises an alarm only where they meet. Each cell draws from its own data source, so the labels come from provenance rather than manual annotation.

| | **AI-driven** | **Human-driven** |
|---|---|---|
| **Malicious** | 🎯 autonomous AI attacker | classic attacker / pentester |
| **Benign** | legitimate automation (Ansible, CI, DevOps agent) | everyday admin work |

- **malicious + AI**: our harness (`gemma3 / gemma4 / llama / qwen`) plus the DTU dataset
- **malicious + human**: the MUNI dataset (real cyber-range trainees, `nmap` / `metasploit`)
- **benign + AI**: the same harness, driven by maintenance prompts
- **benign + human**: NL2Bash / shell-history corpora

### 6 · Robustness, origin axis under progressive restriction

Using **real** human sessions (MUNI: 267 sessions, 21,089 commands, 275 trainees), we progressively restrict the feature space. After removing arguments, environment-specific tokens, session-length differences and multi-host commands, the residual command-selection signal still yields macro F1 0.962. Truncated to the first 10 commands it reaches 0.869, detection before the attack completes.

![Origin axis under restriction](assets/02_origin_restriction.png)

| restriction | macro F1 (leave-one-group-out) |
|---|---|
| raw commands | 1.000 |
| common binaries, no args | 0.984 |
| + truncate to first 20 | 0.982 |
| **+ remove network commands (pure agency)** | **0.962** |
| first 10 commands (early detection) | 0.869 |
| label permutation (control) | 0.452 ✓ |

Every row uses leave-one-group-out (group = scenario / prompt), which prevents the classifier from memorizing a scenario. The permutation control at chance level confirms there is no hidden leakage.

### 7 · Sensor layers, three detection points

We implemented both a host/session-layer detector (Hat H) and a network-layer detector (Hat N), and evaluated them independently.

![Detection layer comparison](assets/07_layer_comparison.png)

**Hat H, command behavior (the main line).** F1 0.962 against real humans, model-independent, resilient. Its ensemble form (SVC + GNN) drives the leave-one-model-out floor to 1.00. Sensor point: an SSH honeypot, a bastion, or a host agent (auditd, eBPF). This is where the signal lives.

**Hat N, outbound scan traffic (complementary).** The usable network signal is not the timing of the encrypted SSH session but the traffic the agent generates during reconnaissance: port-scan spread, protocol mix, SYN inter-arrival timing (BoT-IoT / CIC-IoT style flow features). It reaches F1 0.785, but the separation is capability-dependent.

![Network flow features](assets/06_network_features.png)

During host discovery the AI emits a disproportionate share of ICMP echo requests (`icmp_frac` 0.33 vs 0.01); the human directs more SYN probes at closed ports (higher `syn` / `rst` fractions). A capable agent (gemma4 emitted 262K SYN at 6,977/s) produces scan traffic indistinguishable from a human's, while a weak one produces almost none, so Hat N reads capability as much as agency.

**HASSH handshake, evasion-resistant.** The SSH client version string and KEXINIT algorithm list are transmitted in cleartext, prior to key exchange. `paramiko` (9 kex algorithms) and a genuine `OpenSSH` client (14) are cleanly separable, and this separation is invariant under the keystroke-timing mimicry that defeats every payload-derived feature. Limitation: it identifies a *programmatic client*, which also covers Ansible and CI, rather than agency itself.

### 8 · Replication, DTU's deception effect

The DTU "Honey for the Agent" paper reports that a deception environment increases `ls` usage by 20.8 percentage points. Our initial reproduction produced 0.4. Two causes accounted for the gap: the driver did not pass the SSH banner to the model, and our triggering environments were plain Ubuntu whereas DTU's are Cowrie-based. After rebuilding on Cowrie, with bait directories injected into `fs.pickle`, the effect reached 13.9 percentage points, the same order of magnitude as the original.

![Deception effect](assets/01_deception_effect.png)

The driver of the effect is environment realism, not the prompt.

### 9 · Honest limitations

- **The sample is small.** 43 usable AI sessions once collapses are filtered, against 267 human. Treat the numbers as indicative, not settled.
- **The GNN alone underperforms the SVC.** Its value is only in the ensemble; on this data scale the structural view does not stand on its own, and the reported floor of 1.00 is the OR-ensemble, not the GNN.
- **qwen3:4b can't be trusted here.** Roughly 75 % of its sessions dissolve into reasoning-prose instead of commands, even with `think:false`. Its inflated 86.7 % state-verification is a looping artifact.
- **The intent axis is thinner.** Only origin is fully validated on real data; malicious-vs-benign still rests on synthetic benign-human sessions.
- **Some layers are low-cost to evade.** Keystroke-timing mimicry neutralizes Hat N's payload-derived features in roughly 20 lines of code. The evasion-resistant layers are Hat H (command *selection*) and HASSH.
- **One environment per side.** AI ran in empty containers, humans in a CTF range; despite the common-binary controls, a residual environment confound remains.

### Data sources

| dataset | role | link |
|---|---|---|
| **DTU "Honey for the Agent"** | malicious+AI reference, deception design | [Zenodo 20818246](https://zenodo.org/records/20818246) (CC-BY-4.0) |
| **MUNI shell commands** | real malicious+human | [Zenodo 8136017](https://zenodo.org/records/8136017) (CC-BY-4.0) |
| **TRACE** | fingerprinting-pipeline reference | [arXiv 2605.01186](https://arxiv.org/abs/2605.01186) |
| **NL2Bash** | benign+human commands | [GitHub](https://github.com/TellinaTool/nl2bash) |

</details>

---

<details id="-türkçe">
<summary><h2>🇹🇷 Türkçe</h2></summary>

### Özet

| metrik | değer |
|---|---|
| Leave-one-model-out tabanı, yalnız SVC (ablation) | **0.81** |
| Leave-one-model-out tabanı, SVC + GNN topluluğu | **1.00** |
| Topluluk insan yanlış-pozitif oranı | **%4** |
| Köken-ekseni F1 (AI vs gerçek insan), en zorlu özellik uzayı | **0.962** |
| Durum-yoklama oranı, LLM vs insan | **25 ila 120 kat** |
| Erken tespit (ilk 10 komut) | F1 **0.869** |
| Ağ katmanı (dışa giden tarama trafiği) | F1 **0.785** |

Proje, bir oturumun ardındaki operatörün bir **AI ajanı** olup olmadığını, komut dizisi üzerindeki ve eğitim setinde bulunmayan LLM ailelerine genelleşen bir davranış imzasından belirleyen bir saldırı-tespiti yaklaşımı kuruyor. Host-katmanı dedektörü bir sözcüksel modelin (TF-IDF + LinearSVC) ve bir yapısal modelin (komut-geçiş grafı üzerinde bir GNN) topluluğu; birlikte en kötü-durum genelleme tabanını 1.00'a çıkarıyorlar.

### 1 · Soru, atıf değil köken

> *"Sisteme gelen bir saldırının, arkasındaki model ne olursa olsun, bir insan ya da script yerine bir AI ajanı tarafından sürüldüğünü ayırt eden bir IDS kurabilir miyiz?"*

Bu, model atıfı değil. *Hangi* LLM olduğunu sormuyoruz. Daha temel bir şey soruyoruz: oturumun ardındaki operatör aslında bir dil modeli mi? Yanıtı davranışı parmak izleyerek veriyoruz; asıl sınav ise bu parmak izinin, dedektörün hiç görmediği modeller için de geçerli kalıp kalmadığı.

### 2 · Ana bulgu, imza aileler arasında genelleşiyor

Leave-one-**model**-out testinde her AI modeli eğitimden tamamen çekilir, ardından bilinmeyen bir aktör olarak sunulur. Kurabildiğimiz en tavizsiz özellik uzayında bile (33 ortak komut adı, argümanlar atılmış, oturum uzunluğu eşitlenmiş, ağ komutları çıkarılmış), görülmemiş bir LLM ailesi yine de %76 ile %100 arasında "AI" olarak işaretleniyor.

![Leave-one-model-out](assets/05_leave_one_model.png)

Sinyal bir "gemma imzası" değil. `gemma3:4b`, `gemma4`, `llama3.1:8b` ve `qwen3:4b` arasında paylaşılan bir **LLM-ajan imzası**.

### 3 · Tabanı yükseltmek, GNN topluluğu

Sözcüksel dedektörün zayıf noktası tabanı: gemma3 dışarıda bırakıldığında 0.81 (en katı ayarda 0.76). Spesifik komut token'larına dayandığı için, farklı token kullanan görülmemiş bir modeli yerleştirmek zorlaşıyor. Bu tabanı yükseltmek için **komut-geçiş grafı üzerinde bir GNN** ekledik (`scripts/ids_gnn.py`).

Her oturum yönlü bir grafa dönüşüyor. Bir düğüm benzersiz bir binary; bir kenar, sayısıyla ağırlıklandırılmış gözlenen bir geçiş `cmd_i → cmd_{i+1}`. Düğüm özellikleri **davranışsal kategoriler** (durum-yoklama, keşif, ağ, yetki, süreç, paket) artı derece, frekans ve öz-döngü sinyalleri. Bilinçli olarak hiç komut adı taşımıyorlar; böylece GNN sözcük dağarcığını değil, keşif *topolojisini* (örneğin her adımda yeniden sorgulanan bir durum-yoklama merkezi) okuyor. Tam komutları hiç görülmemiş modellere aktarılabilecek olan da bu. Model, saf PyTorch'ta yoğun bir komşuluk matrisiyle çalışan iki katmanlı bir GraphSAGE, dolayısıyla PyTorch-Geometric bağımlılığı gerektirmiyor.

![GNN topluluğu](assets/08_gnn_ensemble.png)

| dışarıda bırakılan model | SVC (sözcüksel) | GNN (yapısal) | **Topluluk** | insan FP |
|---|---|---|---|---|
| gemma3 | 0.81 | 1.00 | **1.00** | 0.03 |
| gemma4 | 0.92 | 0.83 | **1.00** | 0.06 |
| llama3.1 | 0.86 | 1.00 | **1.00** | 0.05 |
| qwen3 | 1.00 | 0.67 | **1.00** | 0.03 |
| **taban** | **0.81** | 0.67 | **1.00** | ort. 0.04 |

GNN tek başına SVC'yi **geçmiyor**; tabanı 0.67, daha kötü. Kazanç tamamen **toplulukta**. GNN, SVC'nin zayıf olduğu gemma3 ve llama'da güçlü; SVC ise GNN'in zayıf olduğu gemma4 ve qwen'de güçlü. Bir OR-topluluğu tabanı 0.81'den 1.00'a çıkarıyor, yalnızca %4 insan yanlış-pozitif oranıyla; bu da sözcüksel ve yapısal-davranışsal görünümlerin tamamlayıcı sinyal taşıdığının doğrudan kanıtı. SVC-yalnız hattı ablation'dır.

### 4 · Mekanizma, durum-yoklama refleksi

Bir LLM adımlar arasında çalışma belleği tutmaz; bu nedenle yürütme bağlamını her turda yeniden sorgular: çalışma dizini (`pwd`), kimlik (`whoami`, `id`), host ve çekirdek (`uname`, `hostname`). İnsan bu durumu belleğinde tuttuğu için sorguları tekrarlamaz. Fark büyük ve test edilen her modelde tutarlı.

![Durum-yoklama payı](assets/03_state_verification.png)

| operatör | `pwd`/`whoami`/`id`/`uname`/`hostname` payı |
|---|---|
| **İnsan** (MUNI, gerçek) | **%0.7** |
| gemma4 | %16.7 |
| llama3.1 | %22.9 |
| gemma3 | %24.3 |
| qwen3 (çökmüş) | %86.7 |

Her LLM insandan 25 ila 120 kat yüksek. Dikkat çekici biçimde gemma4 (daha yeni ve yetenekli) gemma3'ten *daha az* yokluyor: imza modeller olgunlaştıkça soluyor, ama silinmiyor. GNN'in davranışsal düğüm kategorileri, tam olarak bu refleksin yapısal kodlanmış hali.

![Komut frekansı, AI vs insan](assets/04_command_freq.png)

Aynı komutlar, zıt öncelikler: AI durumu tekrar tekrar doğrularken, insan keşif (enumeration) ve yanal hareket (lateral movement) yapıyor (`ls` %44, `ssh` %17, `ping`).

### 5 · Problem uzayı, iki bağımsız eksen

Dedektör niyet ve kökeni ayrı sorular olarak ele alır ve yalnızca ikisinin kesiştiği yerde alarm verir. Her hücre kendi veri kaynağından beslendiği için etiketler manuel işaretlemeden değil, kökenin kendisinden gelir.

| | **AI güdümlü** | **İnsan güdümlü** |
|---|---|---|
| **Zararlı** | 🎯 otonom AI saldırgan | klasik saldırgan / pentester |
| **Zararsız** | meşru otomasyon (Ansible, CI, DevOps ajanı) | gündelik yönetici işi |

- **zararlı + AI**: kendi harness'imiz (`gemma3 / gemma4 / llama / qwen`) artı DTU veri seti
- **zararlı + insan**: MUNI veri seti (gerçek cyber-range katılımcıları, `nmap` / `metasploit`)
- **zararsız + AI**: aynı harness, bakım promptlarıyla sürülüyor
- **zararsız + insan**: NL2Bash / shell-geçmişi korpusları

### 6 · Sağlamlık, kademeli kısıtlama altında köken ekseni

Gerçek insan oturumlarıyla (MUNI: 267 oturum, 21.089 komut, 275 katılımcı) özellik uzayını kademeli olarak kısıtlıyoruz. Argümanlar, ortama özgü token'lar, oturum-uzunluğu farkları ve çok-makineli komutlar çıkarıldıktan sonra, geriye kalan komut-seçim sinyali hâlâ makro F1 0.962 veriyor. İlk 10 komuta kırpıldığında 0.869'a ulaşıyor, saldırı tamamlanmadan tespit.

![Kısıtlama altında köken ekseni](assets/02_origin_restriction.png)

| kısıtlama | makro F1 (leave-one-group-out) |
|---|---|
| ham komutlar | 1.000 |
| ortak binary'ler, argümansız | 0.984 |
| + ilk 20'ye kırp | 0.982 |
| **+ ağ komutlarını çıkar (saf ajans)** | **0.962** |
| ilk 10 komut (erken tespit) | 0.869 |
| etiket permütasyonu (kontrol) | 0.452 ✓ |

Her satır leave-one-group-out kullanıyor (grup = senaryo / prompt); bu, sınıflandırıcının bir senaryoyu ezberlemesini engelliyor. Şans düzeyindeki permütasyon kontrolü gizli bir sızıntı olmadığını doğruluyor.

### 7 · Sensör katmanları, üç tespit noktası

**Hem** bir host/oturum-katmanı dedektörü (Hat H) **hem de** bir ağ-katmanı dedektörü (Hat N) uyguladık ve bağımsız olarak değerlendirdik.

![Tespit katmanı karşılaştırması](assets/07_layer_comparison.png)

**Hat H, komut davranışı (ana hat).** Gerçek insana karşı F1 0.962, modelden bağımsız, dayanıklı. Topluluk hali (SVC + GNN) leave-one-model-out tabanını 1.00'a çıkarıyor. Sensör noktası: bir SSH honeypot, bir bastion ya da bir host ajanı (auditd, eBPF). Sinyalin yaşadığı yer burası.

**Hat N, dışa giden tarama trafiği (tamamlayıcı).** Kullanılabilir ağ sinyali, şifreli SSH oturumunun zamanlaması değil, ajanın keşif (reconnaissance) sırasında ürettiği trafik: port-tarama yayılımı, protokol karışımı, SYN paketleri arası zamanlama (BoT-IoT / CIC-IoT tarzı akış özellikleri). F1 0.785'e ulaşıyor, ancak ayrım yeteneğe bağımlı.

![Ağ akış özellikleri](assets/06_network_features.png)

Host keşfi sırasında AI orantısız oranda ICMP echo request üretiyor (`icmp_frac` 0.33 vs 0.01); insan ise kapalı portlara daha fazla SYN probu yönlendiriyor (daha yüksek `syn` / `rst` oranları). Yetenekli bir ajan (gemma4 saniyede 6.977 hızla 262K SYN üretti) insanınkinden ayırt edilemeyen tarama trafiği üretiyor, zayıf olansa neredeyse hiç üretmiyor, yani Hat N ajans kadar yeteneği de okuyor.

**HASSH el sıkışması, kaçınmaya dirençli.** SSH istemci sürüm dizesi ve KEXINIT algoritma listesi, anahtar değişiminden önce açık metin olarak iletilir. `paramiko` (9 kex algoritması) ile gerçek bir `OpenSSH` istemcisi (14) net biçimde ayrılabiliyor ve bu ayrım, her payload-türevli özelliği yenen keystroke-zamanlama taklidi altında değişmez. Sınır: ajansın kendisini değil, bir *programatik istemciyi* tanımlıyor, buna Ansible ve CI de dâhil.

### 8 · Replikasyon, DTU'nun aldatma etkisi

DTU'nun "Honey for the Agent" makalesi, bir aldatma ortamının `ls` kullanımını 20,8 puan artırdığını bildiriyor. İlk reprodüksiyonumuz 0,4 üretti. Farkın iki nedeni vardı: driver, SSH banner'ını modele iletmiyordu ve tetikleyici ortamlarımız düz Ubuntu'yken DTU'nunkiler Cowrie tabanlıydı. Yem dizinleri `fs.pickle`'a enjekte edilerek Cowrie üzerine yeniden kurulduğunda etki 13,9 puana ulaştı, orijinaliyle aynı büyüklük mertebesi.

![Aldatma etkisi](assets/01_deception_effect.png)

Etkinin sürücüsü prompt değil, ortam gerçekçiliği.

### 9 · Dürüst sınırlamalar

- **Örneklem küçük.** Çökmeler ayıklandıktan sonra 43 kullanılabilir AI oturumu, 267 insana karşı. Rakamları kesin değil, gösterge niteliğinde okuyun.
- **GNN tek başına SVC'nin altında.** Değeri yalnızca toplulukta; bu veri ölçeğinde yapısal görünüm tek başına ayakta duramıyor ve raporlanan 1.00 tabanı GNN değil, OR-topluluğudur.
- **qwen3:4b burada güvenilmez.** Oturumlarının kabaca %75'i, `think:false` ile bile komut yerine reasoning-metnine dağılıyor. Şişmiş %86,7'lik durum-yoklaması bir döngü artefaktı.
- **Niyet ekseni daha ince.** Gerçek veriyle tam doğrulanan yalnızca köken; zararlı-zararsız ayrımı hâlâ sentetik zararsız-insan oturumlarına dayanıyor.
- **Bazı katmanlardan kaçmak düşük maliyetli.** Keystroke-zamanlama taklidi, Hat N'in payload-türevli özelliklerini yaklaşık 20 satır kodla etkisizleştiriyor. Kaçınmaya dirençli katmanlar Hat H (komut *seçimi*) ile HASSH.
- **Taraf başına tek ortam.** AI boş container'larda, insan CTF range'inde çalıştı; ortak-binary kontrollerine rağmen artık bir ortam confound'u kalıyor.

### Veri kaynakları

| veri seti | rol | bağlantı |
|---|---|---|
| **DTU "Honey for the Agent"** | zararlı+AI referansı, aldatma tasarımı | [Zenodo 20818246](https://zenodo.org/records/20818246) (CC-BY-4.0) |
| **MUNI shell komutları** | gerçek zararlı+insan | [Zenodo 8136017](https://zenodo.org/records/8136017) (CC-BY-4.0) |
| **TRACE** | parmak izi hattı referansı | [arXiv 2605.01186](https://arxiv.org/abs/2605.01186) |
| **NL2Bash** | zararsız+insan komutları | [GitHub](https://github.com/TellinaTool/nl2bash) |

</details>

---

<p align="center"><sub>Local open-weight models (Ollama) + Docker. Isolated lab. Research and defensive use only.</sub></p>

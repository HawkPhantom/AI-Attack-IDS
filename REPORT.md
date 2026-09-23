# AI-Attack IDS — current technical report

The current report is **[experiments/RESULTS_V2.md](experiments/RESULTS_V2.md)**.
It includes corrected host and network analyses, paired layer comparisons,
script controls and explicit unresolved experimental limitations.

Güncel rapor: **[Düzeltilmiş host + network deneyleri](experiments/RESULTS_V2.md)**.
Eski yüzde 100 başarı, genel AI refleksi ve çözülmüş ortam karışıklığı iddiaları
güncel sonuç olarak kullanılmamalıdır.

<details>
<summary>Historical report — superseded / Önceki rapor, güncel kanıt değildir</summary>

<h1 align="center">AI-Attack IDS · Technical Report</h1>
<p align="center"><b>Detecting the LLM behind the shell.</b></p>

<p align="center">
  <a href="#-english"><img src="https://img.shields.io/badge/lang-English-0072B2?style=for-the-badge" alt="English"></a>
  <a href="#-türkçe"><img src="https://img.shields.io/badge/dil-Türkçe-E69F00?style=for-the-badge" alt="Türkçe"></a>
</p>

> **Language / Dil.** English opens by default. Click **🇹🇷 Türkçe** below for the Turkish version.

---

<details open id="-english">
<summary><h2>🇬🇧 English</h2></summary>

### Summary

| metric | value |
|---|---|
| **Frontier held-out recall** (gemini-3.1-pro / gemini-3.5-flash, never trained on) | **1.00 / 1.00** |
| Leave-one-model-out floor, SVC only (ablation) | **0.76** |
| Leave-one-model-out floor, SVC + GNN ensemble | **1.00** |
| Ensemble human false-positive rate | **6 %** |
| Origin-axis F1 (AI vs real human), hardest feature space | **0.962** |
| Intent-axis F1 (malicious vs benign), real data on both human cells (Schonlau) | **0.936** |
| State-verification reflex, frontier vs human | **26–32 % vs 0.7 %** |
| Adaptive evasion — command-selection recall (baseline → evasion → retrain) | **0.91 → 0.68 → 0.82** |
| Early detection (first 10 commands) | F1 **0.869** |
| Network layer (outbound scan traffic) | F1 **0.785** |

The project builds an intrusion-detection approach that determines whether the operator behind a session is an **AI agent**, from a behavioral signature over the command sequence that generalizes to LLM families absent from the training set — including two **frontier** families (Gemini 3.x) that are orders of magnitude larger than any training model, yet are still recognized 100 % of the time. The host-layer detector is an ensemble of a lexical model (TF-IDF + LinearSVC) and a structural one (a GNN over the command-transition graph); together they lift the worst-case generalization floor to 1.00. We also stress the signature with a white-box **adaptive attacker** and quantify **frontier refusal behavior**. All headline recalls carry bootstrap 95 % CIs.

### 1 · The question, origin not attribution

> *"Can we build an IDS that tells whether an incoming attack is driven by an AI agent rather than a human or a script, no matter which model is behind it?"*

This is not model attribution. We are not asking *which* LLM this is. We are asking something more basic: is the operator behind the session a language model at all? We answer it by fingerprinting behavior, and the crucial test is whether that fingerprint still holds for models the detector has never seen.

### 2 · Headline result, the signature generalizes to *frontier* families

In a leave-one-**model**-out test, each AI model is pulled out of training entirely and then presented as an unknown actor. Even on the most unforgiving feature space we could build (44 shared command names, arguments stripped, session length equalized, network commands removed), an unseen LLM family is still flagged as "AI" by the lexical detector alone — and the two **frontier** Gemini families are caught **100 %** of the time despite never appearing in training and being orders of magnitude larger than any training model.


| held-out family (SVC only, strict space) | recall | bootstrap 95 % CI |
|---|---|---|
| gemma3:4b | 0.76 | [0.59, 0.90] |
| llama3.1:8b | 0.87 | [0.67, 1.00] |
| gemma4 | 0.95 | [0.85, 1.00] |
| qwen3:4b (n=3) | 1.00 | [1.00, 1.00] |
| **gemini-3.1-pro** (frontier, n=10) | **1.00** | [1.00, 1.00] |
| **gemini-3.5-flash** (frontier, n=40) | **1.00** | [1.00, 1.00] |
| **floor / mean** | **0.76 / 0.93** | |

This is the decisive test of the "small-model artifact" objection, and it fails: the signal is neither a "gemma signature" nor a "weak-model signature." It is an **LLM-agent signature**, shared across `gemma3:4b`, `gemma4`, `llama3.1:8b`, `qwen3:4b`, and frontier `gemini-3.1-pro` / `gemini-3.5-flash`.

### 3 · Raising the floor, the GNN ensemble

The lexical detector's weak point is its floor: gemma3 still holds out at **0.76** in the strictest setting. Because it keys on specific command tokens, an unseen model that uses different tokens is harder to place. To lift that floor we added a **GNN over the command-transition graph** (`scripts/ids_gnn.py`).

Each session becomes a directed graph. A node is a distinct binary; an edge is an observed transition `cmd_i → cmd_{i+1}`, weighted by count. Node features are **behavioral categories** (state-check, enumerate, network, privilege, process, package) plus degree, frequency and self-loop signals. They deliberately carry no command name, so the GNN reads the reconnaissance *topology*, for example a state-check hub re-queried on every step, rather than the vocabulary. That is what should transfer to models whose exact commands were never seen. The model is a two-layer GraphSAGE in pure PyTorch with a dense adjacency, so it needs no PyTorch-Geometric dependency.


| held-out model | SVC (lexical) | GNN (structural) | **Ensemble** | ens 95 % CI | human FP |
|---|---|---|---|---|---|
| gemma3 | 0.76 | 1.00 | **1.00** | [1.00, 1.00] | 0.05 |
| gemma4 | 0.95 | 1.00 | **1.00** | [1.00, 1.00] | 0.06 |
| llama3.1 | 0.93 | 1.00 | **1.00** | [1.00, 1.00] | 0.06 |
| qwen3 | 1.00 | 1.00 | **1.00** | [1.00, 1.00] | 0.05 |
| **gemini-3.1-pro** ✱ | 1.00 | 1.00 | **1.00** | [1.00, 1.00] | 0.08 |
| **gemini-3.5-flash** ✱ | 1.00 | 1.00 | **1.00** | [1.00, 1.00] | 0.05 |
| **floor** | **0.76** | **1.00** | **1.00** | | 0.06 mean |

<sub>✱ frontier Gemini family, never in training.</sub>

The ensemble reaches a leave-one-model-out floor of **1.00** at **6 % mean human false-positive rate**. The structural (GNN) and lexical (SVC) views are complementary: the SVC floors at 0.76 on gemma3 because it keys on vocabulary, while the GNN — reading reconnaissance *topology* rather than command names — recognizes every held-out family, the frontier ones included, so the ensemble never misses. Two honesty notes: the GNN figure is a single-seed run, so read its 1.00 as "no held-out miss at this scale/seed," not proven-zero-error; and the SVC-only pipeline is the ablation, its **0.76** floor the conservative headline number.

### 4 · Mechanism, the state-verification reflex

An LLM retains no working memory across steps, so it re-queries its execution context on every turn: working directory (`pwd`), identity (`whoami`, `id`), host and kernel (`uname`, `hostname`). A human retains this state and does not repeat the queries. The difference is large and consistent across every model tested.


| operator | `pwd`/`whoami`/`id`/`uname`/`hostname` share |
|---|---|
| **Human** (MUNI, real) | **0.7 %** |
| gemma4 | 16.1 % |
| llama3.1 | 21.5 % |
| gemma3 | 23.8 % |
| **gemini-3.1-pro** (frontier) | **25.6 %** |
| **gemini-3.5-flash** (frontier) | **32.4 %** |
| qwen3 (collapsed) | 86.7 % |

Every LLM sits 23 to 120 times above human — and the two **frontier** models sit at the *top* of the non-collapsed range (25–32 %), not the bottom. Whatever "more capable" buys, it does not buy escape from the stateless-context reflex. (gemma4 checking a little less than gemma3 shows the effect can fade within a family; the frontier result shows it does not vanish with scale.) The GNN's behavioral node categories are the structural encoding of exactly this reflex.

![Command frequency, AI vs human](assets/04_command_freq.png)

The same commands, opposite priorities: the AI repeatedly verifies state, while the human performs enumeration and lateral movement (`ls` 44 %, `ssh` 17 %, `ping`).

### 5 · Problem space, two independent axes

The detector treats intent and origin as separate questions, and raises an alarm only where they meet. Each cell draws from its own data source, so the labels come from provenance rather than manual annotation.

| | **AI-driven** | **Human-driven** |
|---|---|---|
| **Malicious** | 🎯 autonomous AI attacker | classic attacker / pentester |
| **Benign** | legitimate automation (Ansible, CI, DevOps agent) | everyday admin work |

- **malicious + AI**: our harness (`gemma3 / gemma4 / llama / qwen`), across two environments, plus the DTU dataset
- **malicious + human**: the MUNI dataset (real cyber-range trainees, `nmap` / `metasploit`)
- **benign + AI**: the same harness, driven by maintenance prompts
- **benign + human**: **Schonlau SEA** — contiguous windows of real users' recorded command streams

Both human cells are **real** (`scripts/ids_2axis.py`): malicious+human is the same real MUNI corpus the origin axis is validated on, and benign+human is the **Schonlau SEA** dataset — 50 real users' shell activity recorded end-to-end via process accounting, sliced into contiguous windows so the command *order* (and thus the 1,2-gram and transition structure the models key on) is authentic rather than assembled. On this footing, intent (malicious vs benign) separates at macro F1 **0.936** in the common-binary space, with a label-permutation control at **0.543** (≈ chance). The residual caveat is *era/domain*: Schonlau is 1990s workstation activity and its windows are accounting slices rather than login-delimited sessions — the common-binary space and the chance-level permutation bound this, but it remains a second corpus distinct from MUNI/AI.

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

### 9 · Second environment, isolating agency from the box

**The problem this addresses.** The origin axis asks whether AI and human *command behaviour* differ. But there is a catch in how the two sides were run: the AI operated in a bare Ubuntu container with only basic shell tools, while the MUNI humans sat on a cyber-range attacker box equipped with a full offensive toolkit (`nmap`, `john`, `fcrackzip`, `sqlmap`, …). Part of any AI-vs-human gap could then be *which tools were installed*, not agency. The point of this experiment is to close that gap by running the AI in an environment that matches the human one, so that whatever separation is left is behaviour, not equipment.

**The setup.** The environment is a small CTF range in three pieces (`harness/lab/`). An **attacker box** is a container the agent logs into over SSH; its toolkit is mirrored from the MUNI host (`Dockerfile.ctf_attacker`: nmap, hydra, sqlmap, john, fcrackzip, nc, ssh, curl, …). **Three target machines** sit on an isolated subnet (`172.30.0.0/24`) running real listening services (FTP / telnet / HTTP / MySQL banners), so a scan returns genuine results. A password-protected archive is left on the attacker box for a cracking task.

**What the agent does.** The loop is the same one used everywhere else (`harness/lab/run_ctf_range.py` → `driver.py`): the model is given a penetration-test brief — reconnaissance, service exploitation, or archive/credential cracking — and issues exactly one shell command per turn; the command runs on the attacker box, its output is fed back, up to 20 turns. So the agent sweeps the subnet with `nmap`, probes the services it finds, attempts `ssh`, cracks the archive with `john` / `fcrackzip` — producing recon/exploit command sequences in the same operational setting the MUNI humans worked in. This yields **25 usable AI sessions** across `gemma3 / gemma4 / llama / qwen`, alongside the 43 empty-container ones; the whole comparison is in `scripts/ids_env_confound.py`.

With the toolbox the same on both sides, an AI-vs-human separation can be read as agency rather than tool availability. The evidence comes in two parts: the behavioural reflex, then the classifier once the environment is matched.

**The state-verification reflex is environment-invariant.** It is the mechanism from §4, and it barely moves when the box changes:

| operator, by environment | `pwd`/`whoami`/`id`/`uname`/`hostname` share |
|---|---|
| **Human** (MUNI cyber range) | **0.7 %** |
| AI, empty container | 26.5 % |
| AI, CTF range (matched toolset) | 23.9 % |

Both AI environments sit ~34× above human. Because this is a property of the operator and not the toolbox, it is the strongest single piece of evidence that the origin signal is agency.

**The classifier side, once the environment is controlled.** Putting the second environment next to the headline is more honest than the headline alone:

| origin test | macro F1 | reading |
|---|---|---|
| headline — empty-container AI vs human, single environment | **0.962** | strong, but partly environment-aided |
| combined — AI across *both* environments vs human, common binaries | **0.903** | holds up with the second environment folded in |
| same-environment — AI-CTF vs human, full common space | 0.703 | shared network tools (both sides run `nmap`/`ssh`) add confusion |
| **same-environment — AI-CTF vs human, non-network (pure agency)** | **0.771** | cannot be tool availability |
| cross-environment transfer — held-out AI environment recalled as AI | 0.28–0.46 | vocabulary is environment-bound |

**Controlling the environment pulls the separation down from the 0.962 headline to 0.771 in the strictest cut.** Part of that gap is the confound held out as intended; part is that CTF sessions are recon-heavy and thin once network commands are stripped, on a small sample (25). What survives the environment change is the reflex and command *selection over shared behaviour* — which is exactly what the reflex table and the common-binary origin axis measure; what does not survive is the specific command *vocabulary*. The confound is **measured and largely bracketed**, not left as a bare caveat.

### 10 · Adaptive evasion, a white-box attacker who knows the detector

A signature is only interesting if it survives an attacker trying to beat it. We ran a white-box adaptive attacker: the same recon/exploit task, but the operator prompt now instructs the model to behave like a stateful human — never re-check identity/`pwd`/`uname`, keep state in memory, don't repeat commands (`evade_recon` / `evade_exploit` in `harness/driver.py`; analysis in `scripts/ids_evasion.py`). Evasion sessions are held out model-by-model so they are genuinely unseen.

| detector | baseline recall | under evasion | after defender retrains on evasion |
|---|---|---|---|
| reflex only (`state-check share > τ`) | ~0.95–1.00 | **0.00–0.30** | — |
| command-selection SVC (fair space) | 0.91 | **0.68** [0.56, 0.88] | **0.82** |

The state-verification share collapses exactly as instructed (`geminiflash 40.5 % → 7.0 %`, `gemma3 21.9 % → 4.4 %`, `llama 26.2 % → 0.8 %`), so a detector relying only on the reflex is defeated (recall → ~0). The broader **command-selection** signal is more durable: even while suppressing the reflex the agents still enumerate with an un-human systematicity, so the SVC keeps mean recall **0.68**, and adversarial retraining recovers it to **0.82** — an arms race, not a silver bullet. Per model the residual varies: `llama`'s evasion genuinely fools the classifier (recall 0.33), while `geminiflash`'s evasive sessions are *still* caught (1.00) because a frontier model's "human-like" recon remains exhaustive in a way real humans are not. **Deployment implication:** the reflex is the interpretable signal but the evadable one; command selection is the robust one — do not lean on the reflex alone.

### 11 · Frontier compliance, refusal as its own signal

A behavior that only appears with frontier models: they drive reconnaissance and benign maintenance, but refuse overt exploitation a large fraction of the time (*"I cannot assist with identifying or exploiting vulnerabilities"*); the local 4–8 B models almost never refuse. Refusal rate over behavioral (non-error) sessions (`scripts/ids_frontier_compliance.py`):

| task | gemini-3.5-flash refuse % |
|---|---|
| benign / crack / deception | 0 % |
| reconnaissance | 24 % |
| **exploitation** | **62 %** |

Two consequences. It is a **selection effect** worth stating — the malicious frontier sessions we analyze are the compliant ones. And it is a finding for defenders: an autonomous *frontier* agent tasked with exploitation frequently self-aborts, so today's "autonomous AI attacker" threat leans more on uncensored/local models than on refusal-trained frontier APIs — which is exactly why the generalization floor is still a *local* model (gemma3, 0.76), not a frontier one.

### 12 · Honest limitations

- **The sample is modest.** ~161 usable AI sessions across two environments and six model families (incl. gemini-3.1-pro n=10, gemini-3.5-flash n=40) against 267 human. Bootstrap CIs are honestly wide on small-n rows (qwen n=3, gemini-pro n=10) — treat those as indicative.
- **The reflex is fully evadable; command selection is what survives.** A white-box attacker drives a reflex-only detector to ~0 recall (§10); the command-selection SVC degrades to 0.68 and recovers to 0.82 with adversarial retraining. The interpretable signal and the robust signal are different signals.
- **Frontier data has a compliance/rate-limit selection effect.** Frontier models refuse overt exploitation often (flash 62 %), so analyzed malicious-frontier sessions are the compliant ones; and gemini-3.1-**pro** was heavily API-rate-limited on the available key (many 429s), so its n is smaller and its benign cell is empty. The frontier claim rests mainly on flash (n=40), with pro (n=10) corroborating.
- **The GNN's 1.00 is a single-seed result.** The structural view recognizes every held-out family, but it is one seed at this data scale — read it as "no held-out miss here," not proven-zero-error. The SVC-only 0.76 floor is the conservative headline.
- **qwen3:4b can't be trusted here.** ~75 % of its sessions dissolve into reasoning-prose even with `think:false`; its 86.7 % state-verification is a looping artifact and n=3 makes its 1.00 recall weak evidence.
- **The benign+human corpus is a distinct domain.** Schonlau SEA gives real, sequentially-ordered benign sessions, but it is 1990s workstation-era activity — a different domain from MUNI/AI, and its windows are accounting slices, not login-delimited sessions. The common-binary space + chance permutation (0.543) bound this.
- **Some layers are low-cost to evade.** Keystroke-timing mimicry neutralizes Hat N's payload-derived features in ~20 lines. The evasion-resistant layers are Hat H (command *selection*) and HASSH.
- **The environment confound is bracketed, not just noted.** The AI side spans two environments — the empty container and a CTF-range box whose toolset matches the MUNI host (§9) — so agency is measured with the box held closer to fixed. The reflex is nearly identical across both AI environments (26.5 % / 23.9 % vs 0.7 % human) and origin stays separable inside the matched environment (F1 0.771). Cross-environment *lexical* transfer is only partial (0.28–0.46), so command selection over shared behaviour — not vocabulary — is what travels.

### Data sources

| dataset | role | link |
|---|---|---|
| **DTU "Honey for the Agent"** | malicious+AI reference, deception design | [Zenodo 20818246](https://zenodo.org/records/20818246) (CC-BY-4.0) |
| **MUNI shell commands** | real malicious+human | [Zenodo 8136017](https://zenodo.org/records/8136017) (CC-BY-4.0) |
| **Schonlau SEA** | real benign+human (end-to-end command streams) | [schonlau.net](https://www.schonlau.net/intrusion.html) |
| **Gemini 3.x API** | frontier malicious+AI (gemini-3.1-pro, gemini-3.5-flash) | [ai.google.dev](https://ai.google.dev) |
| **TRACE** | fingerprinting-pipeline reference | [arXiv 2605.01186](https://arxiv.org/abs/2605.01186) |
| **NL2Bash** | benign+human (legacy fallback) | [GitHub](https://github.com/TellinaTool/nl2bash) |

</details>

---

<details id="-türkçe">
<summary><h2>🇹🇷 Türkçe</h2></summary>

### Özet

| metrik | değer |
|---|---|
| **Frontier held-out recall** (gemini-3.1-pro / gemini-3.5-flash, eğitimde YOK) | **1.00 / 1.00** |
| Leave-one-model-out tabanı, yalnız SVC (ablation) | **0.76** |
| Leave-one-model-out tabanı, SVC + GNN topluluğu | **1.00** |
| Topluluk insan yanlış-pozitif oranı | **%6** |
| Köken-ekseni F1 (AI vs gerçek insan), en zorlu özellik uzayı | **0.962** |
| Niyet-ekseni F1 (zararlı vs zararsız), Schonlau gerçek benign | **0.936** |
| Durum-yoklama refleksi, frontier vs insan | **%26–32 vs %0.7** |
| Adaptif kaçınma — komut-seçim recall (temel → kaçınma → yeniden eğitim) | **0.91 → 0.68 → 0.82** |
| Erken tespit (ilk 10 komut) | F1 **0.869** |
| Ağ katmanı (dışa giden tarama trafiği) | F1 **0.785** |

Proje, bir oturumun ardındaki operatörün bir **AI ajanı** olup olmadığını, komut dizisi üzerindeki ve eğitim setinde bulunmayan LLM ailelerine genelleşen bir davranış imzasından belirleyen bir saldırı-tespiti yaklaşımı kuruyor. Host-katmanı dedektörü bir sözcüksel modelin (TF-IDF + LinearSVC) ve bir yapısal modelin (komut-geçiş grafı üzerinde bir GNN) topluluğu; birlikte en kötü-durum genelleme tabanını 1.00'a çıkarıyorlar.

### 1 · Soru, atıf değil köken

> *"Sisteme gelen bir saldırının, arkasındaki model ne olursa olsun, bir insan ya da script yerine bir AI ajanı tarafından sürüldüğünü ayırt eden bir IDS kurabilir miyiz?"*

Bu, model atıfı değil. *Hangi* LLM olduğunu sormuyoruz. Daha temel bir şey soruyoruz: oturumun ardındaki operatör aslında bir dil modeli mi? Yanıtı davranışı parmak izleyerek veriyoruz; asıl sınav ise bu parmak izinin, dedektörün hiç görmediği modeller için de geçerli kalıp kalmadığı.

### 2 · Ana bulgu, imza aileler arasında genelleşiyor

Leave-one-**model**-out testinde her AI modeli eğitimden tamamen çekilir, ardından bilinmeyen bir aktör olarak sunulur. Kurabildiğimiz en tavizsiz özellik uzayında bile (44 ortak komut adı, argümanlar atılmış, oturum uzunluğu eşitlenmiş, ağ komutları çıkarılmış), görülmemiş bir LLM ailesi yine de "AI" olarak işaretleniyor — ve eğitimde hiç bulunmayan, eğitim modellerinden kat kat büyük iki **frontier** Gemini ailesi **%100** yakalanıyor.


| dışarıda bırakılan aile (yalnız SVC, katı uzay) | recall | bootstrap %95 GA |
|---|---|---|
| gemma3:4b | 0.76 | [0.59, 0.90] |
| llama3.1:8b | 0.87 | [0.67, 1.00] |
| gemma4 | 0.95 | [0.85, 1.00] |
| qwen3:4b (n=3) | 1.00 | [1.00, 1.00] |
| **gemini-3.1-pro** (frontier, n=10) | **1.00** | [1.00, 1.00] |
| **gemini-3.5-flash** (frontier, n=40) | **1.00** | [1.00, 1.00] |
| **taban / ortalama** | **0.76 / 0.93** | |

Bu, "küçük-model artefaktı mı?" itirazının kesin sınavı ve itiraz çürüyor: sinyal ne "gemma imzası" ne de "zayıf-model imzası". `gemma3:4b`, `gemma4`, `llama3.1:8b`, `qwen3:4b` ve frontier `gemini-3.1-pro` / `gemini-3.5-flash` arasında paylaşılan bir **LLM-ajan imzası**.

### 3 · Tabanı yükseltmek, GNN topluluğu

Sözcüksel dedektörün zayıf noktası tabanı: gemma3 en katı ayarda hâlâ **0.76**. Spesifik komut token'larına dayandığı için, farklı token kullanan görülmemiş bir modeli yerleştirmek zorlaşıyor. Bu tabanı yükseltmek için **komut-geçiş grafı üzerinde bir GNN** ekledik (`scripts/ids_gnn.py`).

Her oturum yönlü bir grafa dönüşüyor. Bir düğüm benzersiz bir binary; bir kenar, sayısıyla ağırlıklandırılmış gözlenen bir geçiş `cmd_i → cmd_{i+1}`. Düğüm özellikleri **davranışsal kategoriler** (durum-yoklama, keşif, ağ, yetki, süreç, paket) artı derece, frekans ve öz-döngü sinyalleri. Bilinçli olarak hiç komut adı taşımıyorlar; böylece GNN sözcük dağarcığını değil, keşif *topolojisini* (örneğin her adımda yeniden sorgulanan bir durum-yoklama merkezi) okuyor. Tam komutları hiç görülmemiş modellere aktarılabilecek olan da bu. Model, saf PyTorch'ta yoğun bir komşuluk matrisiyle çalışan iki katmanlı bir GraphSAGE, dolayısıyla PyTorch-Geometric bağımlılığı gerektirmiyor.


| dışarıda bırakılan model | SVC (sözcüksel) | GNN (yapısal) | **Topluluk** | %95 GA | insan FP |
|---|---|---|---|---|---|
| gemma3 | 0.76 | 1.00 | **1.00** | [1.00, 1.00] | 0.05 |
| gemma4 | 0.95 | 1.00 | **1.00** | [1.00, 1.00] | 0.06 |
| llama3.1 | 0.93 | 1.00 | **1.00** | [1.00, 1.00] | 0.06 |
| qwen3 | 1.00 | 1.00 | **1.00** | [1.00, 1.00] | 0.05 |
| **gemini-3.1-pro** ✱ | 1.00 | 1.00 | **1.00** | [1.00, 1.00] | 0.08 |
| **gemini-3.5-flash** ✱ | 1.00 | 1.00 | **1.00** | [1.00, 1.00] | 0.05 |
| **taban** | **0.76** | **1.00** | **1.00** | | ort. 0.06 |

<sub>✱ eğitimde hiç bulunmayan frontier Gemini ailesi.</sub>

Topluluk, leave-one-model-out tabanını **1.00**'a taşıyor, yalnızca **%6 ortalama insan yanlış-pozitif** oranıyla. Yapısal (GNN) ve sözcüksel (SVC) görünümler tamamlayıcı: SVC gemma3'te 0.76 tabanına iniyor çünkü sözcük dağarcığına dayanıyor; komut adları yerine keşif *topolojisini* okuyan GNN ise frontier dahil her dışarıda bırakılan aileyi tanıyor, dolayısıyla topluluk hiç ıskalamıyor. İki dürüstlük notu: GNN tek-tohumlu (single-seed) bir koşu, 1.00'ını "bu ölçekte/tohumda held-out ıskası yok" olarak okuyun, sıfır-hata kanıtı değil; SVC-yalnız hattı ablation'dır ve **0.76** tabanı temkinli manşet sayıdır.

### 4 · Mekanizma, durum-yoklama refleksi

Bir LLM adımlar arasında çalışma belleği tutmaz; bu nedenle yürütme bağlamını her turda yeniden sorgular: çalışma dizini (`pwd`), kimlik (`whoami`, `id`), host ve çekirdek (`uname`, `hostname`). İnsan bu durumu belleğinde tuttuğu için sorguları tekrarlamaz. Fark büyük ve test edilen her modelde tutarlı.


| operatör | `pwd`/`whoami`/`id`/`uname`/`hostname` payı |
|---|---|
| **İnsan** (MUNI, gerçek) | **%0.7** |
| gemma4 | %16.1 |
| llama3.1 | %21.5 |
| gemma3 | %23.8 |
| **gemini-3.1-pro** (frontier) | **%25.6** |
| **gemini-3.5-flash** (frontier) | **%32.4** |
| qwen3 (çökmüş) | %86.7 |

Her LLM insandan 23 ila 120 kat yüksek — ve iki **frontier** model, çökmemiş aralığın *tepesinde* (%25–32), tabanında değil. "Daha yetenekli" olmak ne kazandırırsa kazandırsın, durumsuz-bağlam refleksinden kaçış kazandırmıyor. (gemma4'ün gemma3'ten biraz daha az yoklaması etkinin bir aile içinde solabildiğini; frontier sonucu ise ölçekle silinmediğini gösterir.) GNN'in davranışsal düğüm kategorileri, tam olarak bu refleksin yapısal kodlanmış hali.

![Komut frekansı, AI vs insan](assets/04_command_freq.png)

Aynı komutlar, zıt öncelikler: AI durumu tekrar tekrar doğrularken, insan keşif (enumeration) ve yanal hareket (lateral movement) yapıyor (`ls` %44, `ssh` %17, `ping`).

### 5 · Problem uzayı, iki bağımsız eksen

Dedektör niyet ve kökeni ayrı sorular olarak ele alır ve yalnızca ikisinin kesiştiği yerde alarm verir. Her hücre kendi veri kaynağından beslendiği için etiketler manuel işaretlemeden değil, kökenin kendisinden gelir.

| | **AI güdümlü** | **İnsan güdümlü** |
|---|---|---|
| **Zararlı** | 🎯 otonom AI saldırgan | klasik saldırgan / pentester |
| **Zararsız** | meşru otomasyon (Ansible, CI, DevOps ajanı) | gündelik yönetici işi |

- **zararlı + AI**: kendi harness'imiz (`gemma3 / gemma4 / llama / qwen`), iki ortamda, artı DTU veri seti
- **zararlı + insan**: MUNI veri seti (gerçek cyber-range katılımcıları, `nmap` / `metasploit`)
- **zararsız + AI**: aynı harness, bakım promptlarıyla sürülüyor
- **zararsız + insan**: **Schonlau SEA** — gerçek kullanıcıların kaydedilmiş komut akışlarından bitişik pencereler

Her iki insan hücresi de **gerçek** (`scripts/ids_2axis.py`): zararlı+insan, köken ekseninin doğrulandığı aynı gerçek MUNI korpusu; zararsız+insan **Schonlau SEA** — 50 gerçek kullanıcının süreç muhasebesiyle uçtan uca kaydedilmiş kabuk etkinliği, komut *sırası* (dolayısıyla modellerin dayandığı 1,2-gram ve geçiş yapısı) derlenmiş değil özgün kalacak biçimde bitişik pencerelere bölünmüş. Bu zeminde niyet (zararlı vs zararsız) ortak-binary uzayında makro F1 **0.936** ile ayrılıyor; etiket-permütasyon kontrolü **0.543** (≈ şans). Kalan çekince *dönem/alan*: Schonlau 1990'lar iş-istasyonu etkinliğidir ve pencereleri login-sınırlı oturumlar değil muhasebe dilimleridir — ortak-binary uzayı ve şans düzeyindeki permütasyon bunu sınırlar, ama yine de MUNI/AI'dan farklı ikinci bir korpustur.

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

### 9 · İkinci ortam, ajansı ortamdan ayırmak

**Bu deneyin çözdüğü sorun.** Köken ekseni, AI ile insanın *komut davranışının* farklı olup olmadığını sorar. Ama iki tarafın nasıl koşturulduğunda bir açık var: AI yalnızca temel kabuk araçları olan boş bir Ubuntu container'ında çalıştı, MUNI insanları ise tam bir saldırı araç setiyle (`nmap`, `john`, `fcrackzip`, `sqlmap`, …) donatılmış bir cyber-range saldırgan kutusundaydı. O hâlde AI-insan farkının bir kısmı ajans değil, *hangi araçların kurulu olduğu* olabilir. Bu deneyin amacı, AI'yı insanınkiyle eşleşen bir ortamda çalıştırıp o açığı kapatmak; böylece geriye kalan ayrım, ekipman değil davranış olur.

**Kurulum.** Ortam, üç parçadan oluşan küçük bir CTF menzili (`harness/lab/`). Bir **saldırgan kutusu**, ajanın SSH ile giriş yaptığı bir container'dır; araç seti MUNI kutusundan aynalanmıştır (`Dockerfile.ctf_attacker`: nmap, hydra, sqlmap, john, fcrackzip, nc, ssh, curl, …). **Üç hedef makine** izole bir alt ağda (`172.30.0.0/24`) gerçek dinleyen servisler (FTP / telnet / HTTP / MySQL banner'ları) çalıştırır; böylece bir tarama gerçek sonuç döner. Saldırgan kutusunda, kırma görevi için parola-korumalı bir arşiv bırakılır.

**Ajan ne yapıyor.** Döngü, her yerde kullanılanla aynı (`harness/lab/run_ctf_range.py` → `driver.py`): modele bir sızma-testi görevi verilir — keşif, servis exploitasyonu veya arşiv/kimlik kırma — ve her turda tam olarak bir kabuk komutu üretir; komut saldırgan kutusunda çalışır, çıktısı geri beslenir, 20 tura kadar. Yani ajan alt ağı `nmap` ile tarar, bulduğu servisleri yoklar, `ssh` dener, arşivi `john` / `fcrackzip` ile kırar — MUNI insanlarının çalıştığı aynı operasyonel ortamda keşif/exploit komut dizileri üretir. Bu, 43 boş-container oturumunun yanında `gemma3 / gemma4 / llama / qwen` üzerinden **25 kullanılabilir AI oturumu** veriyor; tüm karşılaştırma `scripts/ids_env_confound.py` içinde.

Araç kutusu iki tarafta da aynıyken, bir AI-insan ayrımı araç mevcudiyeti değil ajans olarak okunabilir. Kanıt iki parçada: önce davranışsal refleks, sonra ortam eşitlenince sınıflandırıcı.

**Durum-yoklama refleksi ortamdan bağımsız.** §4'teki mekanizmadır ve ortam değişince neredeyse hiç oynamaz:

| operatör, ortama göre | `pwd`/`whoami`/`id`/`uname`/`hostname` payı |
|---|---|
| **İnsan** (MUNI cyber range) | **%0.7** |
| AI, boş container | %26.5 |
| AI, CTF menzili (eşli araç seti) | %23.9 |

Her iki AI ortamı da insandan ~34 kat yüksek. Bu, araç kutusunun değil operatörün özelliği olduğu için, köken sinyalinin ajans olduğuna dair en güçlü tek kanıt.

**Sınıflandırıcı tarafı, ortam kontrol edilince.** İkinci ortamı headline'ın yanına koymak, tek başına headline'dan daha dürüst:

| köken testi | makro F1 | okuma |
|---|---|---|
| headline — boş-container AI vs insan, tek ortam | **0.962** | güçlü, ama kısmen ortam-destekli |
| birleşik — AI *her iki* ortamda vs insan, ortak binary'ler | **0.903** | ikinci ortam katılınca ayakta kalıyor |
| aynı-ortam — AI-CTF vs insan, tam ortak uzay | 0.703 | paylaşılan ağ araçları (iki taraf da `nmap`/`ssh`) karıştırıyor |
| **aynı-ortam — AI-CTF vs insan, ağ-dışı (saf ajans)** | **0.771** | araç mevcudiyeti olamaz |
| ortamlar-arası transfer — dışarıda bırakılan AI ortamı 'ai' yakalanma | 0.28–0.46 | sözcük dağarcığı ortama bağlı |

**Ortamı kontrol etmek, ayrımı 0.962 headline'dan en katı kesitte 0.771'e çekiyor.** Bu farkın bir kısmı confound'un kastedildiği gibi sabitlenmesi; bir kısmı da CTF oturumlarının recon-ağırlıklı olması ve ağ komutları çıkarılınca incelmesi, üstelik küçük örneklemde (25). Ortam değişimini atlatan şey refleks ve *paylaşılan davranış üzerinden komut seçimi* — ki refleks tablosu ve ortak-binary köken ekseni tam da bunu ölçer; atlatamayan ise spesifik komut *sözcük dağarcığı*. Confound sadece kabul edilmiş bir çekince değil, **ölçülmüş ve büyük ölçüde sınırlanmış**.

### 10 · Adaptif kaçınma, dedektörü bilen beyaz-kutu saldırgan

Bir imza, ancak onu yenmeye *çalışan* bir saldırgana dayanırsa ilginçtir. Beyaz-kutu adaptif bir saldırgan koşturduk: aynı keşif/exploit görevi, ama operatör prompt'u modele durumlu bir insan gibi davranmasını söylüyor — kimliği/`pwd`/`uname` asla yeniden yoklama, durumu bellekte tut, komut tekrarlama (`harness/driver.py` içindeki `evade_recon` / `evade_exploit`; analiz `scripts/ids_evasion.py`). Kaçınma oturumları model-model dışarıda bırakılır, yani gerçekten görülmemiştir.

| dedektör | temel recall | kaçınma altında | savunan kaçınmayla yeniden eğitince |
|---|---|---|---|
| yalnız refleks (`durum-yoklama payı > τ`) | ~0.95–1.00 | **0.00–0.30** | — |
| komut-seçim SVC (adil uzay) | 0.91 | **0.68** [0.56, 0.88] | **0.82** |

Durum-yoklama payı tam da söylendiği gibi çöküyor (`geminiflash %40.5 → %7.0`, `llama %26.2 → %0.8`), yani yalnız reflekse dayanan dedektör yenilir (recall → ~0). Daha geniş **komut-seçim** sinyali ise daha dayanıklı: ajanlar refleksi bastırsa bile insan-dışı bir sistematiklikle keşif yapmayı sürdürdüğü için SVC ortalama **0.68** recall korur ve düşmanca yeniden eğitim bunu **0.82**'ye çıkarır — sihirli değnek değil, bir silahlanma yarışı. Modele göre kalan değişir: `llama`'nın kaçınması sınıflandırıcıyı gerçekten kandırıyor (0.33), `geminiflash`'ın kaçınma oturumları ise *hâlâ* yakalanıyor (1.00) çünkü frontier bir modelin "insansı" keşfi bile insanların olmadığı kadar kapsamlı. **Dağıtım çıkarımı:** refleks yorumlanabilir ama kaçınılabilir sinyaldir; komut seçimi dayanıklı olandır — yalnız reflekse yaslanmayın.

### 11 · Frontier uyum, sinyal olarak ret

Yalnızca frontier modellerle ortaya çıkan bir davranış: keşif ve zararsız bakımı yürütürler, ama açık exploitasyonu önemli bir oranda **reddederler** (*"Zafiyet tanımlamaya veya sömürmeye yardımcı olamam"*); yerel 4–8 B modeller neredeyse hiç reddetmez. Davranışsal (hatasız) oturumlar üzerinden ret oranı (`scripts/ids_frontier_compliance.py`):

| görev | gemini-3.5-flash ret % |
|---|---|
| benign / crack / aldatma | %0 |
| keşif | %24 |
| **exploitasyon** | **%62** |

İki sonuç. Bu bir **seçim etkisi**dir — analiz ettiğimiz zararlı-frontier oturumları uyum gösterenlerdir. Ve savunanlar için bir bulgudur: exploitasyonla görevlendirilen otonom bir *frontier* ajanı sıkça kendini durdurur, dolayısıyla bugünkü "otonom AI saldırgan" tehdidi, ret-eğitimli frontier API'lerinden çok sansürsüz/yerel modellere yaslanır — genelleme tabanının hâlâ *yerel* bir model (gemma3, 0.76) olmasının, frontier bir model olmamasının nedeni tam da budur.

### 12 · Dürüst sınırlamalar

- **Örneklem mütevazı.** İki ortam ve altı model ailesinde ~161 kullanılabilir AI oturumu (gemini-3.1-pro n=10, gemini-3.5-flash n=40 dahil), 267 insana karşı. Bootstrap GA'lar küçük-n satırlarında (qwen n=3, gemini-pro n=10) dürüstçe geniştir — bunları gösterge olarak okuyun.
- **Refleks tamamen kaçınılabilir; asıl dayanan komut seçimidir.** Beyaz-kutu saldırgan yalnız-refleks dedektörünü ~0 recall'a düşürür (§10); komut-seçim SVC'si 0.68'e iner ve düşmanca yeniden eğitimle 0.82'ye döner. Yorumlanabilir sinyal ile dayanıklı sinyal farklı sinyallerdir.
- **Frontier veride uyum/rate-limit seçim etkisi var.** Frontier modeller açık exploitasyonu sık reddeder (flash %62), dolayısıyla analiz edilen zararlı-frontier oturumları uyum gösterenlerdir; ayrıca gemini-3.1-**pro** eldeki anahtarda ağır API rate-limit yedi (çok sayıda 429), bu yüzden n'i daha küçük ve benign hücresi boş. Frontier iddiası çoğunlukla flash'a (n=40) dayanıyor, pro (n=10) doğruluyor.
- **GNN'in 1.00'ı tek-tohumlu bir sonuç.** Yapısal görünüm her dışarıda bırakılan aileyi tanıyor, ama bu veri ölçeğinde tek bir tohum — "burada held-out ıskası yok" olarak okuyun, sıfır-hata değil. Temkinli manşet SVC-yalnız 0.76 tabanıdır.
- **qwen3:4b burada güvenilmez.** Oturumlarının ~%75'i `think:false` ile bile komut yerine reasoning-metnine dağılıyor; %86,7'lik durum-yoklaması döngü artefaktı ve n=3, 1.00 recall'ını zayıf kanıt yapar.
- **Benign+insan korpusu farklı bir alan.** Schonlau SEA gerçek, sıralı benign oturumlar verir, ama 1990'lar iş-istasyonu dönemi — MUNI/AI'dan farklı bir alan ve pencereleri login-sınırlı oturumlar değil muhasebe dilimleri. Ortak-binary uzayı + şans permütasyonu (0.543) bunu sınırlar.
- **Bazı katmanlardan kaçmak düşük maliyetli.** Keystroke-zamanlama taklidi Hat N'in payload-türevli özelliklerini ~20 satırla etkisizleştirir. Kaçınmaya dirençli katmanlar Hat H (komut *seçimi*) ile HASSH.
- **Ortam confound'u kabul edilmiş bir çekince değil, sınırlanmış.** AI tarafı iki ortama yayılıyor — boş container ve araç seti MUNI kutusuna eşli CTF-menzili (§9). Refleks iki AI ortamında neredeyse aynı (%26.5 / %23.9 vs %0.7) ve köken eşli ortamda hâlâ ayrılabilir (F1 0.771). Ortamlar-arası *sözcüksel* transfer kısmi (0.28–0.46), yani sözcük değil, paylaşılan davranış üzerinden komut seçimi aktarılan kısımdır.

### Veri kaynakları

| veri seti | rol | bağlantı |
|---|---|---|
| **DTU "Honey for the Agent"** | zararlı+AI referansı, aldatma tasarımı | [Zenodo 20818246](https://zenodo.org/records/20818246) (CC-BY-4.0) |
| **MUNI shell komutları** | gerçek zararlı+insan | [Zenodo 8136017](https://zenodo.org/records/8136017) (CC-BY-4.0) |
| **Schonlau SEA** | gerçek zararsız+insan (uçtan uca komut akışları) | [schonlau.net](https://www.schonlau.net/intrusion.html) |
| **Gemini 3.x API** | frontier zararlı+AI (gemini-3.1-pro, gemini-3.5-flash) | [ai.google.dev](https://ai.google.dev) |
| **TRACE** | parmak izi hattı referansı | [arXiv 2605.01186](https://arxiv.org/abs/2605.01186) |
| **NL2Bash** | zararsız+insan (eski yedek) | [GitHub](https://github.com/TellinaTool/nl2bash) |

</details>

---

<p align="center"><sub>Local open-weight models (Ollama) + Docker. Isolated lab. Research and defensive use only.</sub></p>

</details>

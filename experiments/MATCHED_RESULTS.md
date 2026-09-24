# Matched-budget results

Every operator (AI agents, deterministic scripts, and the planned live-human study)
receives the **same six in-scope ports and the same six-command budget** with identical
task instructions, so scan breadth cannot stand in for operator origin. Rendered from
`experiments/study_v3_results.json` by `scripts/report_matched.py`.

## Scope of the data

Status: **AI-versus-script development pilot; no live-human evidence**. Attempts 253, eligible 237,
quarantined 16. All AI attempts have repeat index 0 — many
conditions, no independent repeats of a condition.

| group | attempts | eligible | exact-correct answer |
|---|---:|---:|---:|
| AI, normal network + prompt | 48 | 41 | 15 |
| AI, evasion prompt | 32 | 30 | 9 |
| AI, delay + loss | 16 | 13 | 6 |
| deterministic script | 128 | 128 | not scored |
| same-command script replay | 13 | 13 | not scored |

The human negatives available today are replayed archived commands, not live decisions;
the matched folds below therefore compare **AI against deterministic automation**, not AI
against live humans. Quarantine covers collector/transport errors and captures that show
target contact but zero packets (`harness/lab/session_quality.py`).

## Leave-one-model-out (AI vs script, all methods)

| detector | AUROC | recall @cal-5% | test FPR |
|---|---:|---:|---:|
| host command-name TF-IDF | 0.87 | 0.24 | 0.00 |
| port count only *(control)* | 0.61 | 0.23 | 0.00 |
| command count only *(control)* | 0.77 | 0.00 | 0.00 |
| state-check share only *(control)* | 0.50 | 0.00 | 0.00 |
| network SVC, no timing | 0.92 | 0.67 | 0.14 |
| network SVC, with timing | 0.92 | 0.82 | 0.01 |
| network RF, no timing | 0.85 | 0.34 | 0.00 |
| network RF, with timing | 0.94 | 0.51 | 0.00 |
| host+network, no timing | 0.95 | 0.58 | 0.04 |
| host+network, with timing | 0.95 | 0.72 | 0.00 |

Negatives here are 16 independent script families, so each calibration and test split
holds about 3 families. Reading:
- The single-feature controls show the budget is matched: **port count** alone reaches AUROC
  0.61 (no scan-breadth shortcut), while **command count**
  reaches 0.77 — command *volume* stays a partial confound —
  and **state-check share** is 0.50 because those tokens never
  appear in these matched sessions (a constant feature, not "a script and an LLM look alike").
- The **host command-name TF-IDF** baseline reaches AUROC 0.87 but its
  recall at a 5%-calibrated threshold is only 0.24, and it is unstable
  across splits (it inverts on some) — the feature is the first token of the first six commands,
  with no arguments or shell structure, so it is a weak, unstable signal, not a reliable detector.
- Network and combined models separate AI from scripts and **hold a low test false-positive
  rate** across the wide negative pool: network+timing AUROC 0.92
  at test FPR 0.01 (recall 0.82),
  RF+timing 0.94 at FPR 0.00,
  host+network+timing 0.95 at FPR 0.00.
  Per-model network-SVC no-timing test FPR: gemma3:4b 0.11, gemma4:latest 0.17, llama3.1:8b 0.28, qwen3:4b 0.00.
- **This is still not a *validated* low false-positive rate for deployment:** each split has
  tens of negatives, so a zero-false-positive fold has a wide exact upper bound, the negatives
  are deterministic automation (not live humans), and cluster intervals in the JSON are wide.

## Identical commands, AI vs same-command script

| detector | AUROC | recall @cal-5% | test FPR |
|---|---:|---:|---:|
| host command-name TF-IDF | 0.50 | 0.33 | 0.33 |
| port count only *(control)* | 0.50 | 0.17 | 0.17 |
| command count only *(control)* | 0.50 | 0.00 | 0.00 |
| state-check share only *(control)* | 0.50 | 0.00 | 0.00 |
| network SVC, no timing | 0.54 | 0.67 | 0.58 |
| network SVC, with timing | 0.71 | 0.67 | 0.42 |
| network RF, no timing | 0.54 | 0.33 | 0.33 |
| network RF, with timing | 0.83 | 0.58 | 0.17 |
| host+network, no timing | 0.62 | 0.50 | 0.50 |
| host+network, with timing | 0.79 | 0.58 | 0.33 |

Across 13 pairs the command text is identical, so command-name features tie by construction
(a consistency check, not a finding). Timing features add some separation, but each row is a
two-sample fold averaged over 13 folds; local-model inference waits versus wait-free replay
are an expected timing difference, so this is "timing adds separation under these conditions,"
not an established AI-specific signal.

## Evasion prompt (AI trying to look human)

| detector | AUROC | recall @cal-5% | test FPR |
|---|---:|---:|---:|
| host command-name TF-IDF | 0.91 | 0.29 | 0.00 |
| port count only *(control)* | 0.65 | 0.30 | 0.00 |
| command count only *(control)* | 0.67 | 0.00 | 0.00 |
| state-check share only *(control)* | 0.50 | 0.00 | 0.00 |
| network SVC, no timing | 0.97 | 0.69 | 0.14 |
| network SVC, with timing | 0.97 | 0.81 | 0.01 |
| network RF, no timing | 0.92 | 0.46 | 0.00 |
| network RF, with timing | 0.95 | 0.46 | 0.00 |
| host+network, no timing | 0.94 | 0.58 | 0.04 |
| host+network, with timing | 0.96 | 0.75 | 0.00 |

Of 32 evasion attempts (30 eligible), **9 produce the exact correct answer**
(gemma4 6, llama3.1 2, qwen3 1); several models complete the task, not
only one. The state-check share does not "collapse" under evasion — it is zero in the normal
condition too. Two evasion sessions **exceeded the port budget** (~1000 TCP ports), recorded in
`budget_compliance` and excluded from any matched-budget claim (2 budget-violating
sessions total). The success-gated subset is in `successful_ai_sensitivity` per fold.

## Matched network impairment (emulated WAN, applied to every operator)

Emulated netem on the attacker egress — delay 80ms±40ms (normal), 1.5% correlated loss, 5%
reordering — applied equally to **both** AI and scripts (16 impaired AI, 32 impaired
scripts), evaluated impaired-AI vs impaired-scripts with the threshold re-fit on impaired
negatives:

| detector | AUROC | recall @cal-5% | test FPR |
|---|---:|---:|---:|
| host command-name TF-IDF | 0.83 | 0.44 | 0.00 |
| port count only *(control)* | 0.56 | 0.12 | 0.00 |
| command count only *(control)* | 0.91 | 0.00 | 0.00 |
| state-check share only *(control)* | 0.50 | 0.00 | 0.00 |
| network SVC, no timing | 0.88 | 0.56 | 0.00 |
| network SVC, with timing | 0.72 | 0.50 | 0.00 |
| network RF, no timing | 0.88 | 0.62 | 0.00 |
| network RF, with timing | 0.96 | 0.81 | 0.00 |
| host+network, no timing | 0.98 | 0.50 | 0.00 |
| host+network, with timing | 0.75 | 0.50 | 0.00 |

The separation survives matched impairment (see the table). This is still emulation on a
single Docker host with capture on the operator container's `eth0`, **not** a real wide-area
network; a genuine WAN/field test remains future work. (A one-sided `delay_loss` profile on
the AI class only is also recorded in the JSON.)

## Frozen confirmatory test (unseen tasks, profiles and negative families)

Model and threshold frozen on development, then scored **once** on 29 AI and 16 script sessions from **unseen tasks** (dbweb, triage), **unseen service profiles** (c, d) and **reserved negative families** (nmap_reason, nmap_seq, ssh_probe, telnet_probe). AI exact-correct: 6/29.

| detector | AUROC | recall | test FPR | FP / neg | 95% upper |
|---|---:|---:|---:|---:|---:|
| host command-name TF-IDF | 0.89 | 0.38 | 0.00 | 0/16 | 0.17 |
| port count only *(control)* | 0.62 | 0.48 | 0.25 | 4/16 | 0.48 |
| command count only *(control)* | 0.50 | 0.00 | 0.00 | 0/16 | 0.17 |
| state-check share only *(control)* | 0.50 | 0.00 | 0.00 | 0/16 | 0.17 |
| network SVC, no timing | 0.94 | 0.93 | 0.25 | 4/16 | 0.48 |
| network SVC, with timing | 0.89 | 0.86 | 0.00 | 0/16 | 0.17 |
| network RF, no timing | 0.74 | 0.48 | 0.25 | 4/16 | 0.48 |
| network RF, with timing | 1.00 | 0.55 | 0.00 | 0/16 | 0.17 |
| host+network, no timing | 0.91 | 0.86 | 0.06 | 1/16 | 0.26 |
| host+network, with timing | 0.86 | 0.66 | 0.00 | 0/16 | 0.17 |

Zero false positives on the held-out families is encouraging, but with this many negatives the exact 95% upper bound is still well above 1%, and the negatives are automation, not live humans.

## What this study can and cannot claim

- Under a shared lab and matched task budget, AI-vs-deterministic-automation separation is
  **real but method-dependent**: network and combined models (especially with inter-packet
  timing) rank AI above scripts with AUROC ~0.9 and hold a low test false-positive rate across
  a wide negative pool of many families; the command-name host baseline is weak and unstable.
- The separation **survives matched emulated-WAN impairment** and a **frozen test on unseen
  tasks, service profiles and negative families**, which is encouraging for generalization.
- It is **not yet a validated low-false-positive detector**: tens of negatives per split give
  wide exact FP bounds, the negatives are deterministic automation rather than live humans,
  command volume remains a partial confound, and this is a single emulated Docker lab.
- **Live-human separation and transfer to real networks are still untested.** The human study
  ([HUMAN_STUDY.md](HUMAN_STUDY.md)) is required, and an authorized reconnaissance task is not
  a malicious-intent or successful-breach label. Claims that "AI is undetectable," that "only
  timing separates," or that "the network approach is unusable" are not supported.

# Corrected evaluation protocol (v2)

This protocol supersedes the headline claims in the historical README/report.
The corrected results are a research pilot, not a deployment validation.

## Historical host reanalysis

- Source: existing local/Gemini logs and MUNI recordings. Keep malicious-task and
  evasion sessions with at least one recorded command, including repetitive and
  long-command sessions previously excluded by heuristic filters.
- Recover model-authored commands by comparing `raw_command` extraction with the
  recorded command. Exclude known replacements; do not pretend this removes the
  historical prompts' explicit `pwd` encouragement. Exact trajectories are
  deduplicated within origin before splitting.
- Deterministically split MUNI recording groups into train/calibration/test.
  No test or calibration human group enters training. Participant identities
  across recording groups have not independently been resolved.
- For each held-out AI model, exclude all its sessions from training. Also test
  held-out AI environments and evasion; environment transfer is not a same-lab
  live-human comparison. Models from one provider are not independent families.
- Build the common command vocabulary only on training examples, after a 20-command
  cap. Remove network commands. SVC, graph, shuffled-order graph, and no-edge
  graph receive the same resulting sequences, without argument features.
- Keep empty sequences instead of silently dropping difficult test examples.
  The cap is a maximum, not a guarantee of equal surviving lengths.
- Compare category-frequency logistic regression with lexical SVC and batched
  graph models. Use GNN seeds 17, 42, 73 and fixed hyperparameters; there is no
  test-driven hyperparameter search. Per-batch class weights do not cancel as
  they did in the historical single-example weighted loss.
- Report session recall/FPR with Wilson intervals, macro F1, AUROC and AP.
  Wilson intervals do not incorporate cluster dependence or model-training
  uncertainty; graph seeds show some training variation separately.
- Report 1% and 5% FPR-target thresholds selected exclusively on calibration
  negatives, alongside achieved test FPR. A target is not a guarantee.
- No state-check features ablation is included. Intent results are explicitly
  descriptive corpus classification; permuted labels cannot remove provenance
  confounding. AI-only intent is reported separately.

## Directional network reanalysis

- Parse only IPv4 traffic between attacker 172.30.0.10 and the lab subnet.
- Target ports, IPs, SYNs and protocol ratios use outbound traffic only; received
  RST fraction uses inbound TCP only. Reply ephemeral ports cannot inflate scope.
- Retain valid zero-traffic captures; reject truncated captures explicitly.
- Legacy captures excluded all port 22 traffic. That information is lost and
  cannot be restored by feature extraction. Legacy human traffic is command
  replay; timing was not recorded from live human participants.
- SSH transport direction follows the first TCP SYN's endpoints, not port order.
  Loopback transport captures still lack realistic network latency and loss.

## New paired collection

- Four local Ollama model digests and two fixed lab service profiles; no remote
  API charges. One collector with full-history and recent-two-step context
  policies, two authorized reconnaissance tasks, six command opportunities.
- The service profiles are two configurations of the same Docker lab, not
  independent environments. Context policies are not independent frameworks.
- The Docker network is internal-only. No container ports are published and no
  host directory is mounted. Existing user containers are not removed.
- The model response, extracted command, executed command, return code, output,
  inference latency, execution duration and pcap digest are recorded. No synthetic
  `pwd` or `nmap` recovery command is injected. Commands are time-limited equally
  for AI, replay and scripts. Empty/unparseable responses terminate the session
  and remain in the dataset.
- Each session has paired commands and pcap. Human-command replays use existing
  archived trajectories; two deterministic scripts are separate negative controls.
  Replays are not live human participation and their original tasks/scan budgets
  do not match the new constrained AI instructions. This remains an explicit
  confound, not something that can be solved by relabeling replay as human.
- Network-only, host-only and feature-concatenated models use identical folds.
  Scaling and TF-IDF fitting occur exclusively on training data. Network models
  are evaluated with and without inter-packet/rate features. Structural counters
  can still reflect tool choice and task budget.
- Hold out AI models, service profile, or context policy. Hold out human source
  trajectories for test/calibration; their repetitions across profiles cannot
  cross those boundaries. Reused negatives across folds are not pooled as
  independent samples. Script controls never enter training.
- Report tiny calibration sample sizes rather than claim a validated 5% FPR.
  Genuine generalization requires live humans on the same tasks, additional
  independently implemented agents, new tasks and independent environments.

## Reproduction

From the repository root (Python 3.11 was used):

```sh
python3.11 -m venv .venv
.venv/bin/pip install -r experiments/requirements-lock.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python harness/lab/recon_features.py --output experiments/network_features_v2.json
.venv/bin/python scripts/evaluate_host_v2.py
.venv/bin/python scripts/evaluate_intent_v2.py
.venv/bin/python harness/lab/collect_v2.py
.venv/bin/python harness/lab/counterfactual_v2.py
.venv/bin/python scripts/evaluate_network_v2.py
.venv/bin/python scripts/score_task_v2.py
.venv/bin/python scripts/summarize_v2.py
```

Collection requires Docker images `lab-attacker:latest`, `lab-target:latest`, the
four local Ollama models, and the lab subnet to be free. Raw datasets and pcaps
remain in git-ignored directories. `experiments/*.json` preserves per-fold
predictions, IDs and protocol parameters. The model/image manifest and dependency
lockfile pin the runtime; external API model snapshots cannot be inferred from
historical short labels.

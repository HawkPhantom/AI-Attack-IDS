#!/usr/bin/env python3
"""Adaptive-attacker experiment: can a white-box operator evade the origin axis?

The origin detector keys on two things: (1) the state-verification REFLEX
(pwd/whoami/id/uname/hostname re-queried every turn) and (2) broader command
SELECTION. An adaptive attacker who knows this is told, via the `evade_recon` /
`evade_exploit` prompts, to suppress the reflex and behave like a stateful human
(same recon GOAL, only the tradecraft differs from the baseline `prompt_1`).

We measure, per model, under LEAVE-ONE-MODEL-OUT (evasion sessions are genuinely
unseen in training):
  - state-verification share:      baseline vs evasion   (is the reflex suppressed?)
  - reflex-only detector recall:   baseline vs evasion   (state_share > tau)
  - full SVC detector recall:      baseline vs evasion   (fair common-binary space)
  - evasion-aware retrain:         does adding OTHER models' evasion to training
                                   recover recall on the held-out model's evasion?

Reading: if the reflex-only detector collapses but the SVC survives, the durable
signal is command SELECTION, not the reflex. The gap SVC(base) - SVC(evade) is
the exploitable evasion headroom that remains.
"""
from __future__ import annotations
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ids_data import load_ai, load_human_malicious, head, state_share, NETW  # noqa: E402

SEED = 42
TAU = 0.05   # reflex-only threshold: state-verification share above this -> "ai"


def pipe():
    return Pipeline([("tf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=10000)),
                     ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000))])


def bootstrap_ci(ind, B=3000, seed=SEED):
    a = np.asarray(ind, dtype=float)
    if len(a) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    m = a[rng.integers(0, len(a), (B, len(a)))].mean(1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def main():
    base = load_ai(envs=("empty", "ctf"), include_evasion=False)       # malicious+benign baseline
    base = [r for r in base if r["intent"] == "malicious"]             # match evasion (both recon/exploit)
    evade = [r for r in load_ai(envs=("empty", "ctf"), include_evasion=True) if r["evasion"]]
    hu = load_human_malicious()

    ev_models = sorted({r["model"] for r in evade})
    print("=" * 82)
    print("ADAPTIVE EVASION — origin detector under a white-box reflex-suppressing attacker")
    print("=" * 82)
    print(f"  baseline malicious AI: {len(base)}  {dict(Counter(r['model'] for r in base))}")
    print(f"  evasion AI sessions  : {len(evade)}  {dict(Counter(r['model'] for r in evade))}")
    print(f"  human (MUNI)         : {len(hu)}")
    if not ev_models:
        print("\n  [!] no evasion sessions yet (grids still running) — rerun when ready.")
        return

    # fair space: common binaries (baseline AI vs human), no args, first 20, no network
    acnt = Counter(head(c) for r in base for c in r["cmds"])
    hcnt = Counter(head(c) for r in hu for c in r["cmds"])
    vocab = (set(acnt) & set(hcnt)) - NETW

    def doc(r):
        return " ".join(head(c) for c in r["cmds"][:20] if head(c) in vocab)

    hu_docs = [doc(r) for r in hu if len(doc(r).split()) >= 3]

    print(f"\n  {'model':<12}{'state% base':>12}{'state% evade':>13}"
          f"{'reflex R b/e':>14}{'SVC R base':>12}{'SVC R evade':>13}{'+evade-train':>13}")
    print("  " + "-" * 78)
    rows_out = []
    for m in ev_models:
        b_rows = [r for r in base if r["model"] == m]
        e_rows = [r for r in evade if r["model"] == m]
        if not e_rows:
            continue
        st_b = 100 * np.mean([state_share(r["cmds"]) for r in b_rows]) if b_rows else float("nan")
        st_e = 100 * np.mean([state_share(r["cmds"]) for r in e_rows])

        # reflex-only detector
        rfx_b = np.mean([state_share(r["cmds"]) > TAU for r in b_rows]) if b_rows else float("nan")
        rfx_e = np.mean([state_share(r["cmds"]) > TAU for r in e_rows])

        # full SVC, leave-this-model-out (evasion + this model's baseline both unseen)
        tr = [r for r in base if r["model"] != m]
        Xtr = [doc(r) for r in tr if len(doc(r).split()) >= 3] + hu_docs
        ytr = ["ai"] * sum(1 for r in tr if len(doc(r).split()) >= 3) + ["human"] * len(hu_docs)
        clf = pipe().fit(Xtr, ytr)
        Xb = [doc(r) for r in b_rows if len(doc(r).split()) >= 3]
        Xe = [doc(r) for r in e_rows if len(doc(r).split()) >= 3]
        svc_b = np.mean([p == "ai" for p in clf.predict(Xb)]) if Xb else float("nan")
        ev_ind = [1 if p == "ai" else 0 for p in clf.predict(Xe)] if Xe else []
        svc_e = np.mean(ev_ind) if ev_ind else float("nan")

        # evasion-aware retrain: add OTHER models' evasion to training, retest held evasion
        tr2 = [r for r in base if r["model"] != m] + [r for r in evade if r["model"] != m]
        X2 = [doc(r) for r in tr2 if len(doc(r).split()) >= 3] + hu_docs
        y2 = ["ai"] * sum(1 for r in tr2 if len(doc(r).split()) >= 3) + ["human"] * len(hu_docs)
        svc_e2 = (np.mean([p == "ai" for p in pipe().fit(X2, y2).predict(Xe)])
                  if Xe else float("nan"))

        rows_out.append((m, svc_b, svc_e, svc_e2, ev_ind, len(e_rows)))
        print(f"  {m:<12}{st_b:>11.1f}%{st_e:>12.1f}%"
              f"{rfx_b:>7.2f}/{rfx_e:<5.2f}{svc_b:>12.2f}{svc_e:>13.2f}{svc_e2:>13.2f}")

    # aggregate over pooled evasion sessions
    pooled = [i for _, _, _, _, ind, _ in rows_out for i in ind]
    if pooled:
        lo, hi = bootstrap_ci(pooled)
        svc_b_mean = np.nanmean([b for _, b, _, _, _, _ in rows_out])
        svc_e_mean = np.nanmean([e for _, _, e, _, _, _ in rows_out])
        svc_e2_mean = np.nanmean([e2 for _, _, _, e2, _, _ in rows_out])
        print("  " + "-" * 78)
        print(f"  MEAN SVC recall  baseline={svc_b_mean:.2f}  evasion={svc_e_mean:.2f} "
              f"[{lo:.2f},{hi:.2f}]  evasion+retrain={svc_e2_mean:.2f}")
        print("\n  Reading: reflex-only recall collapses under evasion (that feature is defeated),")
        print("  while the SVC keeps residual recall from command SELECTION. The baseline->evasion")
        print("  SVC gap is the remaining evasion headroom; +evade-train shows how much is")
        print("  recoverable once the defender trains on evasive traffic (the arms race).")


if __name__ == "__main__":
    print("Historical evaluator superseded: running the corrected host-v2 protocol.")
    from evaluate_host_v2 import main as corrected_main
    corrected_main()

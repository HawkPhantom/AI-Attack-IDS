#!/usr/bin/env python3
"""Faz 0 smoke test: TRACE'in TF-IDF + LinearSVC hattini DTU 4b altkumesinde calistir.

Amac tam replikasyon degil -- hattin ucuca calistigini dogrulamak:
  T1  veri yukleme / min_bash filtresi
  T2  model ailesi siniflandirma (5-fold stratified CV)      -> TRACE Exp.1
  T3  leave-one-environment-out genelleme                    -> TRACE LOSO
  T4  en ayirt edici TF-IDF ozellikleri                      -> TRACE Exp.2
  T5  ortam siniflandirma (honeypot vs gercek)               -> Honey-for-the-Agent ekseni
"""
import json, warnings
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

warnings.filterwarnings("ignore")
BASE = Path("data/eval_ready/clean")
MIN_BASH = 5
SEED = 42


def make_pipeline():
    """TRACE makalesindeki birebir konfigurasyon."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])


def load_sessions(min_bash=MIN_BASH):
    rows, skipped = [], defaultdict(int)
    for f in sorted(BASE.glob("*.json")):
        d = json.loads(f.read_text(errors="replace"))
        cmds = [e["command"].strip() for e in d["entries"]
                if e.get("type") != "plan" and (e.get("command") or "").strip()]
        if len(cmds) < min_bash:
            skipped["too_short"] += 1
            continue
        rows.append({"session_id": d["session_id"], "family": d["family"], "env": d["env"],
                     "prompt_id": d["prompt_id"], "turn_limit": d["turn_limit"],
                     "n_cmds": len(cmds), "doc": " ".join(cmds)})
    return rows, skipped


def cv_report(X, y, groups_name, n_splits=5):
    pipe = make_pipeline()
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=SEED)
    pred = cross_val_predict(pipe, X, y, cv=skf, n_jobs=-1)
    macro = f1_score(y, pred, average="macro")
    print(f"\n  macro F1 = {macro:.3f}   ({groups_name}, {n_splits}-fold stratified CV)")
    print(classification_report(y, pred, digits=3))
    labels = sorted(set(y))
    print("  confusion matrix (satir=gercek):", labels)
    for lab, row in zip(labels, confusion_matrix(y, pred, labels=labels)):
        print(f"    {lab:>28} {row}")
    return macro


def main():
    print("=" * 74)
    print("T1  VERI YUKLEME")
    print("=" * 74)
    rows, skipped = load_sessions()
    print(f"  kullanilabilir oturum : {len(rows)}   (atlanan <{MIN_BASH} komut: {skipped['too_short']})")
    by_fam = defaultdict(int); by_env = defaultdict(int)
    for r in rows:
        by_fam[r["family"]] += 1; by_env[r["env"]] += 1
    print("  aile dagilimi         :", dict(by_fam))
    print("  ortam dagilimi        :", dict(by_env))
    print(f"  oturum basina komut   : med {int(np.median([r['n_cmds'] for r in rows]))}"
          f"  min {min(r['n_cmds'] for r in rows)}  max {max(r['n_cmds'] for r in rows)}")

    X = [r["doc"] for r in rows]
    y_fam = [r["family"] for r in rows]
    y_env = [r["env"] for r in rows]

    print("\n" + "=" * 74)
    print("T2  MODEL AILESI PARMAK IZI  (TRACE Exp.1 muadili)")
    print("=" * 74)
    cv_report(X, y_fam, "family")

    print("\n" + "=" * 74)
    print("T3  LEAVE-ONE-ENVIRONMENT-OUT  (TRACE'in LOSO'su, scaffold yerine ortam)")
    print("=" * 74)
    envs = sorted(set(y_env))
    scores = []
    for held in envs:
        tr = [i for i, e in enumerate(y_env) if e != held]
        te = [i for i, e in enumerate(y_env) if e == held]
        pipe = make_pipeline()
        pipe.fit([X[i] for i in tr], [y_fam[i] for i in tr])
        p = pipe.predict([X[i] for i in te])
        s = f1_score([y_fam[i] for i in te], p, average="macro")
        scores.append(s)
        print(f"  held-out {held:<26} macro F1 = {s:.3f}   (n={len(te)})")
    print(f"  ORTALAMA                            macro F1 = {np.mean(scores):.3f} +/- {np.std(scores):.3f}")

    print("\n" + "=" * 74)
    print("T4  EN AYIRT EDICI OZELLIKLER  (TRACE Exp.2 muadili)")
    print("=" * 74)
    pipe = make_pipeline(); pipe.fit(X, y_fam)
    vocab = np.array(pipe.named_steps["tfidf"].get_feature_names_out())
    coef = pipe.named_steps["clf"].coef_[0]
    classes = pipe.named_steps["clf"].classes_
    top_pos = vocab[np.argsort(coef)[-12:]][::-1]
    top_neg = vocab[np.argsort(coef)[:12]]
    print(f"  -> {classes[1]:<12}: {list(top_pos)}")
    print(f"  -> {classes[0]:<12}: {list(top_neg)}")

    print("\n" + "=" * 74)
    print("T5  ORTAM SINIFLANDIRMA  (komut dizisi honeypot'u ele veriyor mu?)")
    print("=" * 74)
    cv_report(X, y_env, "environment")

    print("\n" + "=" * 74)
    print("SMOKE TEST TAMAM -- hat ucuca calisiyor.")
    print("=" * 74)


if __name__ == "__main__":
    main()

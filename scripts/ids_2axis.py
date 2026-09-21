#!/usr/bin/env python3
"""2-eksen IDS baseline: niyet (malicious/benign) x koken (AI/insan).

Hedef (kullanici karari): 2x2'nin her iki eksenini de modelle, alarm = kesisim
(malicious AND ai) = otonom AI saldirgan.

VERI HUCRELERI ve kaynaklari:
  malicious + AI    : harness/runs/grid_ac   (prompt_1/3/5, exploit/kesif)
  benign    + AI    : harness/runs/benign    (benign_1/2/3, mesru bakim)
  malicious + insan : harness/runs/human/intruder_*   (keystroke replay)
  benign    + insan : harness/runs/human/admin_*      (keystroke replay)

CIDDI SINIRLAMALAR (sonuclari bunlarla oku):
  1. Insan oturumlari SENTETIK — sabit komut listelerinin keystroke replay'i.
     Gercek insan degil. Siniflandirici buyuk olcude 'scripted liste vs LLM
     uretimi' ayrimini ogrenir; bu gercek AI-vs-insan sinyali DEGILDIR.
     Gercek insan verisi (Beyond Bots / bash history) gelene kadar bu bir
     ust-sinir/ise-yararlik testidir, bilimsel sonuc degil.
  2. Ortam confound'u: varsayilan olarak SADECE real_ssh oturumlari kullanilir
     (--all-envs ile kapatilabilir), boylece ortam sabit tutulur.
  3. Oturum sayisi az (~40-60). Sonuclar gosterge niteligindedir.
"""
from __future__ import annotations
import argparse, json, random
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

SEED = 42


def pipe():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])


def cmds_raw(path):
    """DTU-raw semasi (driver / human_replay ciktisi)."""
    raw = json.loads(Path(path).read_text(errors="replace"))
    return [t[0][0].strip() for t in raw[1:]
            if t and t[0] and (t[0][0] or "").strip() not in ("", "<model_error>")]


def load_cells(all_envs=False):
    rows = []

    # malicious + AI
    for f in Path("harness/runs/grid_ac").rglob("*session*.json"):
        env = f.parent.parent.name
        if not all_envs and env != "real_ssh":
            continue
        c = cmds_raw(f)
        if len(c) >= 4:
            rows.append({"cmds": c, "intent": "malicious", "origin": "ai",
                         "env": env, "src": "grid_ac"})

    # benign + AI
    for f in Path("harness/runs/benign").glob("*.json"):
        c = cmds_raw(f)
        if len(c) >= 4:
            rows.append({"cmds": c, "intent": "benign", "origin": "ai",
                         "env": "real_ssh", "src": "benign"})

    # insan (her iki niyet)
    for f in Path("harness/runs/human").glob("*.json"):
        c = cmds_raw(f)
        if len(c) < 4:
            continue
        intent = "malicious" if f.name.startswith("intruder") else "benign"
        rows.append({"cmds": c, "intent": intent, "origin": "human",
                     "env": "real_ssh", "src": "human"})
    return rows


def evaluate(rows, axis, tag):
    y = np.array([r[axis] for r in rows])
    X = np.array([" ".join(r["cmds"]) for r in rows])
    counts = Counter(y)
    if len(counts) < 2:
        print(f"  [{tag}] tek sinif, atlandi: {dict(counts)}")
        return None
    k = min(5, min(counts.values()))
    if k < 2:
        print(f"  [{tag}] sinif basina yetersiz ornek: {dict(counts)}")
        return None
    pred = cross_val_predict(pipe(), X, y, cv=StratifiedKFold(k, shuffle=True, random_state=SEED))
    f1 = f1_score(y, pred, average="macro")
    print(f"\n  [{tag}]  n={len(y)}  {dict(counts)}  {k}-fold  ->  macro F1 = {f1:.3f}")
    print("  " + classification_report(y, pred, digits=3).replace("\n", "\n  "))
    return f1


def permutation_control(rows, axis, tag):
    y = np.array([r[axis] for r in rows])
    X = np.array([" ".join(r["cmds"]) for r in rows])
    ys = y.copy()
    random.Random(0).shuffle(ys)
    k = min(5, min(Counter(ys).values()))
    if k < 2:
        return
    pred = cross_val_predict(pipe(), X, ys, cv=StratifiedKFold(k, shuffle=True, random_state=SEED))
    print(f"  [{tag}] etiket permutasyonu (sans ~{1/len(set(y)):.2f}): "
          f"macro F1 = {f1_score(ys, pred, average='macro'):.3f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all-envs", action="store_true",
                    help="ortam sabitlemesini kaldir (confound artar)")
    a = ap.parse_args()

    rows = load_cells(all_envs=a.all_envs)
    print("=" * 74)
    print(f"2x2 HUCRE DOLULUGU  ({'tum ortamlar' if a.all_envs else 'yalniz real_ssh'})")
    print("=" * 74)
    grid = Counter((r["intent"], r["origin"]) for r in rows)
    print(f"  {'':<12}{'AI':>10}{'INSAN':>10}")
    for intent in ["malicious", "benign"]:
        print(f"  {intent:<12}{grid[(intent,'ai')]:>10}{grid[(intent,'human')]:>10}")
    print(f"  TOPLAM: {len(rows)} oturum")
    if len(rows) < 8:
        print("\n[!] cok az oturum — once gridleri kosun.")
        return

    print("\n" + "=" * 74)
    print("EKSEN A — NIYET (malicious vs benign)")
    print("=" * 74)
    evaluate(rows, "intent", "niyet")
    permutation_control(rows, "intent", "niyet")

    print("\n" + "=" * 74)
    print("EKSEN B — KOKEN (AI vs insan)")
    print("=" * 74)
    evaluate(rows, "origin", "koken")
    permutation_control(rows, "origin", "koken")

    # koken eksenini niyet sabitleyerek test et (confound ayristirma)
    print("\n" + "=" * 74)
    print("CAPRAZ KONTROL — koken ayrimi niyetten bagimsiz mi?")
    print("=" * 74)
    for intent in ["malicious", "benign"]:
        sub = [r for r in rows if r["intent"] == intent]
        if len(sub) >= 8:
            evaluate(sub, "origin", f"koken | niyet={intent}")

    print("\n" + "=" * 74)
    print("NOT: insan oturumlari SENTETIK (scripted keystroke replay).")
    print("Yuksek F1 buyuk olcude 'sabit liste vs LLM uretimi' ayrimini yansitir,")
    print("gercek AI-vs-insan sinyalini DEGIL. Gercek insan verisi sart.")
    print("=" * 74)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Yuksek F1 gercek sinyal mi, artefakt mi? Dort kontrol."""
import json, random
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC


def pipe():
    return Pipeline([("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                               sublinear_tf=True, max_features=10000)),
                     ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000))])


rows = []
for f in sorted(Path("data/eval_ready/clean").glob("*.json")):
    d = json.loads(f.read_text(errors="replace"))
    cmds = [e["command"].strip() for e in d["entries"]
            if e.get("type") != "plan" and (e.get("command") or "").strip()]
    if len(cmds) >= 5:
        rows.append((d["family"], cmds))

y = np.array([r[0] for r in rows])
skf = StratifiedKFold(5, shuffle=True, random_state=42)
print(f"oturum: {len(rows)}   sinif: {sorted(set(y))}   sans seviyesi ~{1/len(set(y)):.2f}\n")


def run(X, tag, labels=None):
    lab = y if labels is None else labels
    p = cross_val_predict(pipe(), np.array(X), lab, cv=skf, n_jobs=-1)
    print(f"  {tag:<44} macro F1 = {f1_score(lab, p, average='macro'):.3f}")


X_all = [" ".join(c) for _, c in rows]

print("KONTROL 1 - etiket permutasyonu (sans seviyesine dusmeli)")
y_shuf = y.copy(); random.Random(0).shuffle(y_shuf)
run(X_all, "karistirilmis etiketler", labels=y_shuf)

print("\nKONTROL 2 - uzunluk ipucu mu?")
for fam in sorted(set(y)):
    n = [len(c) for f_, c in rows if f_ == fam]
    print(f"  {fam:<44} komut/oturum: med={int(np.median(n))} mean={np.mean(n):.1f}")

print("\nKONTROL 3 - kisaltilmis oturumlar (ilk N komut)")
for n in [1, 2, 3, 5, 10]:
    run([" ".join(c[:n]) for _, c in rows], f"ilk {n} komut")
run(X_all, "tum komutlar")

print("\nKONTROL 4 - sadece binary adlari (argumanlar atilmis)")
run([" ".join((c.split() or [""])[0] for c in cmds) for _, cmds in rows], "yalniz binary adlari")

print("\nKONTROL 5 - format ihlali confound'u (prose atilmis, sadece duzgun komutlar)")
def wellformed(c):
    return len(c) <= 60 and len(c.split()) <= 8
rows_wf = [(fam, [c for c in cmds if wellformed(c)]) for fam, cmds in rows]
keep = [i for i, (_, c) in enumerate(rows_wf) if len(c) >= 5]
y_wf = np.array([rows_wf[i][0] for i in keep])
X_wf = [" ".join(rows_wf[i][1]) for i in keep]
p = cross_val_predict(pipe(), np.array(X_wf), y_wf, cv=skf, n_jobs=-1)
print(f"  {'yalniz duzgun komutlar':<44} macro F1 = {f1_score(y_wf, p, average='macro'):.3f}  (n={len(keep)})")

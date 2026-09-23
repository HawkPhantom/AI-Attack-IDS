#!/usr/bin/env python3
"""KOKEN EKSENI, GERCEK insan verisiyle: AI vs gercek insan saldirgan.

Sentetik keystroke replay yerine MUNI veri seti (Zenodo 8136017, CC-BY-4.0):
267 oturum / 21.089 komut / 275 katilimci, gercek insanlarin hands-on siber
guvenlik egitiminde yazdigi komutlar (hostname='attacker', nmap/metasploit).

Her ikisi de malicious niyetli, yani bu test KOKEN eksenini niyetten arindirilmis
olarak olcer: "bu oturumu bir LLM ajan mi yoksa gercek bir insan mi surdu?"

CONFOUND ve nasil ele alindigi:
  MUNI insanlari CTF ortaminda nmap/msfconsole/john gibi kurulu araclari kullanir;
  bizim AI ajanlar bos bir Ubuntu container'inda calisti (o araclar yok). Ham
  karsilastirma bu yuzden 'arac mevcudiyeti'ni olcer, ajansi degil.
  Bu yuzden IKI sonuc raporlanir:
    (A) HAM            — tum komutlar (confound'lu, ust sinir)
    (B) ORTAK UZAY     — yalniz her iki tarafta da gorulen binary'ler (adil)
  Ayrica LEAVE-ONE-GROUP-OUT kullanilir (grup = egitim senaryosu / AI promptu),
  cunku stratified CV senaryo ezberi yuzunden sisiriyor.
"""
from __future__ import annotations
import json, re
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC


def pipe():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])


def head(c):
    return (c.split() or [""])[0].split("/")[-1]


def ai_rows():
    rows = []
    for f in Path("harness/runs/grid_ac").rglob("*session*.json"):
        raw = json.loads(f.read_text(errors="replace"))
        cmds = [t[0][0].strip() for t in raw[1:]
                if t and t[0] and (t[0][0] or "").strip() not in ("", "<model_error>")]
        if len(cmds) >= 4:
            pr = re.search(r"(prompt_\d)", f.name)
            rows.append({"cmds": cmds, "origin": "ai",
                         "grp": f"ai_{pr.group(1) if pr else '?'}"})
    return rows


def human_rows():
    rows = []
    for f in sorted(Path("data/human/muni").rglob("*useractions.json")):
        cmds = []
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            c = (r.get("cmd") or "").strip()
            if c:
                cmds.append(c)
        if len(cmds) >= 4:
            rows.append({"cmds": cmds, "origin": "human",
                         "grp": f"hu_{f.parent.name}"})   # grup = egitim senaryosu
    return rows


def run(rows, tag, vocab=None):
    def doc(r):
        cs = r["cmds"] if vocab is None else [c for c in r["cmds"] if head(c) in vocab]
        return " ".join(cs), len(cs)
    docs = [doc(r) for r in rows]
    keep = [i for i, (_, n) in enumerate(docs) if n >= 4]
    X = np.array([docs[i][0] for i in keep])
    y = np.array([rows[i]["origin"] for i in keep])
    G = np.array([rows[i]["grp"] for i in keep])
    cnt = Counter(y)
    if len(cnt) < 2:
        print(f"  [{tag}] tek sinif kaldi, atlandi")
        return
    logo = LeaveOneGroupOut()
    preds = np.empty(len(y), dtype=object)
    for tr, te in logo.split(X, y, G):
        if len(set(y[tr])) < 2:
            preds[te] = y[tr][0]
            continue
        preds[te] = pipe().fit(X[tr], y[tr]).predict(X[te])
    f1 = f1_score(y, preds, average="macro")
    print(f"\n  [{tag}]  n={len(y)}  {dict(cnt)}  gruplar={len(set(G))}")
    print(f"  leave-one-GROUP-out macro F1 = {f1:.3f}")
    print("  " + classification_report(y, preds, digits=3).replace("\n", "\n  "))
    return f1


def main():
    ai, hu = ai_rows(), human_rows()
    rows = ai + hu
    print("=" * 74)
    print("KOKEN EKSENI — AI ajan vs GERCEK insan saldirgan (ikisi de malicious)")
    print("=" * 74)
    print(f"  AI oturum    : {len(ai)}  (bizim harness, gemma3:4b)")
    print(f"  insan oturum : {len(hu)}  (MUNI, gercek katilimcilar)")
    ac = Counter(head(c) for r in ai for c in r["cmds"])
    hc = Counter(head(c) for r in hu for c in r["cmds"])
    print(f"\n  AI top-10    : {[k for k,_ in ac.most_common(10)]}")
    print(f"  insan top-10 : {[k for k,_ in hc.most_common(10)]}")
    common = set(ac) & set(hc)
    print(f"  ortak binary : {len(common)} / AI'da {len(ac)}, insanda {len(hc)}")

    print("\n" + "=" * 74)
    print("(A) HAM — tum komutlar (arac-mevcudiyeti confound'u ICINDE)")
    print("=" * 74)
    run(rows, "ham")

    print("\n" + "=" * 74)
    print("(B) ORTAK UZAY — yalniz her iki tarafta da gorulen binary'ler (ADIL)")
    print("=" * 74)
    run(rows, "ortak-uzay", vocab=common)

    print("\n" + "=" * 74)
    print("(B) ile (A) arasindaki fark = 'arac mevcudiyeti' confound'unun buyuklugu.")
    print("Gercek ajans sinyali (B)'dir; (A) ust sinirdir.")
    print("=" * 74)


if __name__ == "__main__":
    print("Historical evaluator superseded: running the corrected host-v2 protocol.")
    from evaluate_host_v2 import main as corrected_main
    corrected_main()

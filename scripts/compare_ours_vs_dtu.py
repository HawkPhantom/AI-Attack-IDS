#!/usr/bin/env python3
"""(a) analizi: kendi harness'imizin urettigi veri DTU dagilimini uretiyor mu?

Uc eksende karsilastirir (yalniz gemma3:4b, ortak ortamlar):
  1. Komut dagilimi   — top komutlar bizde vs DTU, ayni (model, env)
  2. 'ls' kullanim orani ortam bazinda  — DTU'nun 'aldatma ls'yi +20.8pp artirir' bulgusu
  3. Domain shift      — DTU'da egitilmis fingerprint modeli bizim veriyi taniyor mu
  4. plain_cowrie ozel — honeypot komut diziminden ele veriliyor mu (real_ssh'e karsi)
"""
import json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline

ANSI = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
DTU_DIR = Path("data/eval_ready/clean")
OURS_DIR = Path("harness/runs/grid_ac")


def cmds_from_dtu(path):
    d = json.loads(path.read_text(errors="replace"))
    return [e["command"].strip() for e in d["entries"]
            if e.get("type") != "plan" and (e.get("command") or "").strip()]


def cmds_from_ours(path):
    """Grid ciktisi DTU-raw semasinda (list-of-lists). Ilk komut token'ina kadar al."""
    raw = json.loads(path.read_text(errors="replace"))
    out = []
    for t in raw[1:]:
        if t and t[0] and isinstance(t[0][0], str) and t[0][0].strip() not in ("", "<model_error>"):
            out.append(t[0][0].strip())
    return out


def parse_ours_meta(path):
    # sid: {env}_{model}_{prompt}_{turns}_session{n}
    return {"env": path.parent.parent.name, "model": path.parent.name}


def head(c):
    return (c.split() or [""])[0].split("/")[-1]


def load_ours():
    rows = []
    for f in OURS_DIR.rglob("*session*.json"):
        c = cmds_from_ours(f)
        if len(c) >= 3:
            m = parse_ours_meta(f)
            rows.append({"env": m["env"], "model": "gemma3:4b", "cmds": c})
    return rows


def load_dtu(model="gemma3-4b", envs=None):
    rows = []
    for f in DTU_DIR.glob(f"*_{model}_*.json"):
        env = f.name.split(f"_{model}_")[0]
        if envs and env not in envs:
            continue
        c = cmds_from_dtu(f)
        if len(c) >= 3:
            rows.append({"env": env, "model": "gemma3:4b", "cmds": c})
    return rows


def main():
    ours = load_ours()
    if not ours:
        sys.exit(f"[!] {OURS_DIR} bos — once grid'i kosun.")
    our_envs = sorted({r["env"] for r in ours})
    print(f"BIZIM VERI: {len(ours)} oturum, ortamlar: {our_envs}")
    dtu = load_dtu(envs=our_envs)
    print(f"DTU VERI  : {len(dtu)} oturum (gemma3-4b, ayni ortamlar)\n")

    # ---- 1. Komut dagilimi ----
    print("=" * 74)
    print("1) KOMUT DAGILIMI — top-8 binary (bizim vs DTU, gemma3:4b, tum ortamlar)")
    print("=" * 74)
    def top(rows, n=8):
        c = Counter(head(x) for r in rows for x in r["cmds"])
        tot = sum(c.values())
        return [(k, 100 * v / tot) for k, v in c.most_common(n)], tot
    ot, otot = top(ours); dt, dtot = top(dtu)
    print(f"  {'BIZIM':<28}{'DTU':<28}")
    for i in range(8):
        o = f"{ot[i][0]} ({ot[i][1]:.1f}%)" if i < len(ot) else ""
        dd = f"{dt[i][0]} ({dt[i][1]:.1f}%)" if i < len(dt) else ""
        print(f"  {o:<28}{dd:<28}")
    ov = {k for k, _ in ot}; dv = {k for k, _ in dt}
    print(f"  -> top-8 ortak binary: {len(ov & dv)}/8  ({sorted(ov & dv)})")

    # ---- 2. ls kullanim orani ortam bazinda ----
    print("\n" + "=" * 74)
    print("2) 'ls' KULLANIM ORANI ORTAM BAZINDA  (DTU: aldatma ls'yi artirir)")
    print("=" * 74)
    def ls_rate(rows):
        by = defaultdict(lambda: [0, 0])
        for r in rows:
            for c in r["cmds"]:
                by[r["env"]][0] += 1
                if head(c) == "ls":
                    by[r["env"]][1] += 1
        return {e: 100 * l / t if t else 0 for e, (t, l) in by.items()}
    olr, dlr = ls_rate(ours), ls_rate(dtu)
    print(f"  {'ortam':<28}{'BIZIM ls%':>12}{'DTU ls%':>12}")
    for e in our_envs:
        print(f"  {e:<28}{olr.get(e, 0):>11.1f}%{dlr.get(e, 0):>11.1f}%")
    base = "real_ssh"
    if base in olr:
        print(f"\n  aldatma etkisi (ortam ls% - real_ssh ls%):")
        for e in our_envs:
            if e != base:
                print(f"    {e:<26} bizim {olr.get(e,0)-olr[base]:+.1f}pp | "
                      f"DTU {dlr.get(e,0)-dlr.get(base,0):+.1f}pp")

    # ---- 3. Domain shift: DTU'da egit, bizde test ----
    print("\n" + "=" * 74)
    print("3) DOMAIN SHIFT — model ayrimi: yalniz gemma oldugundan ENV siniflandirmasi")
    print("   (DTU'da egitilmis ortam-siniflandirici bizim oturumlari dogru mu etiketliyor)")
    print("=" * 74)
    common = [e for e in our_envs if sum(1 for r in dtu if r["env"] == e) >= 5]
    dtr = [r for r in dtu if r["env"] in common]
    pipe = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=10000)),
                     ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000))])
    pipe.fit([" ".join(r["cmds"]) for r in dtr], [r["env"] for r in dtr])
    ote = [r for r in ours if r["env"] in common]
    pred = pipe.predict([" ".join(r["cmds"]) for r in ote])
    acc = np.mean([p == r["env"] for p, r in zip(pred, ote)])
    print(f"  DTU'da egitildi ({len(dtr)} oturum) -> bizim {len(ote)} oturumda test")
    print(f"  ortam siniflandirma dogrulugu: {acc:.2f}")
    cm = defaultdict(Counter)
    for p, r in zip(pred, ote):
        cm[r["env"]][p] += 1
    for e in common:
        print(f"    gercek {e:<26} -> {dict(cm[e])}")

    # ---- 4. plain_cowrie vs real_ssh ayrimi (bizim veride) ----
    print("\n" + "=" * 74)
    print("4) HONEYPOT ELE VERILIYOR MU — plain_cowrie vs real_ssh (bizim veride)")
    print("=" * 74)
    pair = [r for r in ours if r["env"] in ("plain_cowrie", "real_ssh")]
    if len({r["env"] for r in pair}) == 2 and len(pair) >= 8:
        from sklearn.model_selection import cross_val_predict, StratifiedKFold
        from sklearn.metrics import f1_score
        y = [r["env"] for r in pair]
        X = [" ".join(r["cmds"]) for r in pair]
        k = min(5, min(Counter(y).values()))
        p = cross_val_predict(pipe, X, y, cv=StratifiedKFold(k, shuffle=True, random_state=0))
        print(f"  {len(pair)} oturum, {k}-fold CV  macro F1 = {f1_score(y, p, average='macro'):.3f}")
        print("  (yuksek F1 = Cowrie komut diziminden gercek sistemden ayirt edilebiliyor)")
    else:
        print("  yeterli plain_cowrie/real_ssh oturumu yok (grid henuz bitmedi?)")


if __name__ == "__main__":
    main()

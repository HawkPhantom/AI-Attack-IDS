#!/usr/bin/env python3
"""Hat N (v2) analizi: ajanin AG AYAK IZINDEN AI vs insan ayrimi.

Girdi: harness/runs/recon/recon_features.json (recon_features.py cikarir)
Bu, sifreli SSH timing'i DEGIL, ajanin urettigi TARAMA trafiginin akis ozellikleri
(BoT-IoT / CIC-IoT tarzi): port yayilimi, SYN ritmi, protokol karisimi, kapsam.

Karsilastirma: AI ajan (gemma/qwen/llama, "agi tara" gorevi) vs gercek insan
nmap komutlari (MUNI'den replay). Leave-one-GROUP-out (grup=model/insan-oturumu).
"""
import json, sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import f1_score, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

FEATS = ["pkts_per_sec", "unique_dst_ips", "unique_dst_ports", "unique_ip_port_pairs",
         "n_syn", "syn_frac", "rst_recv_frac", "syn_per_sec", "port_span",
         "port_range_coverage", "syn_iat_med_ms", "syn_iat_std_ms", "icmp_frac", "udp_frac"]


def load():
    rows = json.loads(Path("harness/runs/recon/recon_features.json").read_text())
    out = []
    for r in rows:
        sid = r["session"]
        origin = "ai" if sid.startswith("ai_") else "human"
        # grup = her oturum ayri (leave-one-session-out). Boylece her fold'da hem AI
        # hem insan temsil edilir; model-bazli grup 12 oturumda insani tek gruba
        # sikistirip degerlendirmeyi bozuyordu.
        out.append({**r, "origin": origin, "grp": sid})
    return out


def single_feature_separation(rows):
    """Her ozelligin tek basina AI/insan ayirma gucu — kucuk veride
    siniflandirici F1'inden daha durust bir sinyal gostergesi."""
    ai = [r for r in rows if r["origin"] == "ai"]
    hu = [r for r in rows if r["origin"] == "human"]
    print("\n  tek-ozellik ayrim (Cohen's d + ortusme):")
    print(f"    {'ozellik':<22}{'AI med':>11}{'INSAN med':>11}{'|d|':>7}  ortusme")
    scored = []
    for f in FEATS:
        a = np.array([r[f] for r in ai], float)
        h = np.array([r[f] for r in hu], float)
        pooled = np.sqrt((a.var() + h.var()) / 2) or 1e-9
        d = abs(a.mean() - h.mean()) / pooled
        overlap = not (a.max() < h.min() or h.max() < a.min())
        scored.append((d, f, np.median(a), np.median(h), overlap))
    for d, f, am, hm, ov in sorted(scored, reverse=True)[:8]:
        print(f"    {f:<22}{am:>11.2f}{hm:>11.2f}{d:>7.2f}  {'var' if ov else 'YOK (tam ayrim)'}")


def main():
    rows = load()
    if len(rows) < 6:
        sys.exit(f"[!] yalniz {len(rows)} oturum — grid bitmemis olabilir.")
    print("=" * 74)
    print("HAT N (v2) — AG AYAK IZINDEN AI vs INSAN (tarama trafigi)")
    print("=" * 74)
    cnt = Counter(r["origin"] for r in rows)
    print(f"  oturum: {len(rows)}  {dict(cnt)}")
    print(f"  AI modelleri: {sorted(set(r['grp'] for r in rows if r['origin']=='ai'))}")

    # ozet tablo
    print(f"\n  {'ozellik':<22}{'AI ort':>12}{'INSAN ort':>12}")
    ai = [r for r in rows if r["origin"] == "ai"]
    hu = [r for r in rows if r["origin"] == "human"]
    for k in ["n_syn", "unique_dst_ports", "port_span", "syn_per_sec",
              "syn_iat_med_ms", "unique_dst_ips", "icmp_frac"]:
        a = np.mean([r[k] for r in ai]); h = np.mean([r[k] for r in hu])
        print(f"  {k:<22}{a:>12.2f}{h:>12.2f}")

    single_feature_separation(rows)

    if len(cnt) < 2 or min(cnt.values()) < 2:
        print("\n[!] siniflandirma icin iki sinifta yeterli ornek yok.")
        return

    X = np.array([[r[f] for f in FEATS] for r in rows], float)
    y = np.array([r["origin"] for r in rows])
    G = np.array([r["grp"] for r in rows])
    clf = Pipeline([("sc", StandardScaler()),
                    ("rf", RandomForestClassifier(n_estimators=300, random_state=42,
                                                  class_weight="balanced"))])
    preds = np.empty(len(y), dtype=object)
    for tr, te in LeaveOneGroupOut().split(X, y, G):
        if len(set(y[tr])) < 2:
            preds[te] = y[tr][0]; continue
        preds[te] = clf.fit(X[tr], y[tr]).predict(X[te])
    print(f"\n  leave-one-GROUP-out (grup={len(set(G))}) macro F1 = "
          f"{f1_score(y, preds, average='macro'):.3f}")
    print("  " + classification_report(y, preds, digits=3).replace("\n", "\n  "))

    # ozellik onemi (tum veride)
    clf.fit(X, y)
    imp = clf.named_steps["rf"].feature_importances_
    print("  en ayirt edici 6 ozellik:")
    for i in np.argsort(imp)[-6:][::-1]:
        print(f"    {FEATS[i]:<22} {imp[i]:.3f}")


if __name__ == "__main__":
    main()

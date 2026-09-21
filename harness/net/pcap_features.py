#!/usr/bin/env python3
"""Hat N: sifreli SSH pcap'inden akis/zamanlama ozellikleri cikarir.

Payload sifreli — icerik gorunmez. Network katmaninda AI-vs-insan icin
mevcut olan TEK sinyal bunlar (hepsi spoof edilebilir, hepsi dolayli):
  - inter-arrival time istatistikleri (istemci->sunucu paketleri arasi bosluk)
  - paket boyutu dagilimi (komut uzunlugu ~ segment boyutu, SSH padding'e ragmen)
  - yon dengesi (client/server byte orani)
  - 'dusunme' bosluklari: buyuk arrival-gap'lerin sayisi (AI inference latency)
  - oturum suresi, toplam paket/byte, paket/saniye

KRITIK CONFOUND: bizim istemci (paramiko) komutu TEK send ile gonderiyor;
interaktif insan SSH keystroke-by-keystroke yazar. Bu network'te GORUNUR bir
fark yaratir ama bu 'AI vs insan' degil 'tam-komut-client vs keystroke-client'
farkidir. Insan baseline'i ayni gonderim biciminde toplanmazsa sonuc bu artefakti
olcer. Ozellik cikariminda bunu isaretliyoruz (bkz. cmd_like_bursts).
"""
from __future__ import annotations
import json, socket, sys
from pathlib import Path

import dpkt
import numpy as np

CLIENT_IP = "127.0.0.1"


def load_flows(pcap_path):
    """(ts, src_port, dst_port, length, is_client_to_server) listesi."""
    pkts = []
    with open(pcap_path, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            try:
                # lo0 BSD loopback: 4-byte AF header, sonra IP
                if len(buf) < 4:
                    continue
                ip = dpkt.ip.IP(buf[4:])
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                payload = len(tcp.data)
                if payload == 0:
                    continue  # saf ACK/handshake atla, veri paketlerine odaklan
                # ssh sunucu portu buyuk (2222/2300+); istemci ephemeral
                to_server = tcp.dport < tcp.sport
                pkts.append((ts, tcp.sport, tcp.dport, payload, to_server))
            except Exception:
                continue
    return pkts


def features(pcap_path):
    p = load_flows(pcap_path)
    if len(p) < 4:
        return None
    ts = np.array([x[0] for x in p])
    ln = np.array([x[3] for x in p])
    c2s = np.array([x[4] for x in p])
    dur = ts[-1] - ts[0]
    iat = np.diff(ts)
    c_len = ln[c2s]      # istemci->sunucu payload boyutlari (komutlar)
    s_len = ln[~c2s]     # sunucu->istemci (ciktilar)

    def stats(a, pre):
        if len(a) == 0:
            return {f"{pre}_mean": 0, f"{pre}_std": 0, f"{pre}_med": 0, f"{pre}_max": 0}
        return {f"{pre}_mean": float(np.mean(a)), f"{pre}_std": float(np.std(a)),
                f"{pre}_med": float(np.median(a)), f"{pre}_max": float(np.max(a))}

    f = {
        "duration_s": float(dur),
        "n_pkts": len(p),
        "n_client_pkts": int(c2s.sum()),
        "n_server_pkts": int((~c2s).sum()),
        "total_bytes": int(ln.sum()),
        "client_server_byte_ratio": float(c_len.sum() / max(s_len.sum(), 1)),
        "pkts_per_sec": float(len(p) / max(dur, 1e-3)),
        # 'dusunme' bosluklari: >1s arrival-gap sayisi (AI inference / insan dusunme)
        "think_gaps_gt1s": int(np.sum(iat > 1.0)),
        "think_gaps_gt3s": int(np.sum(iat > 3.0)),
        # CONFOUND GOSTERGESI — keystroke mu tam-komut mu?
        # NOT: SSH sifrelemesi tek tusu bile ~36-72 byte'a sisirir, o yuzden
        # "<=4 byte" gibi bir esik anlamsizdir. Gercek ayirt edici, istemcinin
        # KOMUT BASINA kac paket gonderdigidir: tam-komut client ~1-2,
        # interaktif keystroke client ~komut uzunlugu kadar.
        "small_client_pkt_frac": float(np.mean(c_len <= 80)) if len(c_len) else 0.0,
        "client_pkt_burstiness": float(np.std(c_len) / max(np.mean(c_len), 1e-6)) if len(c_len) else 0.0,
    }
    f.update(stats(iat * 1000, "iat_ms"))
    f.update(stats(c_len, "client_len"))
    f.update(stats(s_len, "server_len"))
    return f


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "harness/runs/net")
    rows = []
    for pc in sorted(root.rglob("*.pcap")):
        feat = features(pc)
        if feat is None:
            print(f"  atlandi (az paket): {pc.name}")
            continue
        feat["session"] = pc.stem
        rows.append(feat)
        print(f"  {pc.stem}: {feat['n_pkts']}pkt {feat['duration_s']:.1f}s "
              f"think>1s={feat['think_gaps_gt1s']} small_client={feat['small_client_pkt_frac']:.2f}")
    out = root / "net_features.json"
    out.write_text(json.dumps(rows, indent=2))
    print(f"\n[+] {len(rows)} oturumun network ozellikleri -> {out}")


if __name__ == "__main__":
    main()

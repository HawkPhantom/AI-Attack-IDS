#!/usr/bin/env python3
"""Hat N (network katmani): bir SSH oturumunu KOSARKEN es zamanli pcap yakalar.

Oturum katmani (Hat H) komut dizisini kaydeder; bu modul ayni oturumun ham
network trafigini (sifreli SSH paketleri) lo0 uzerinden tcpdump ile yakalar.
Boylece ayni oturum icin iki gorunum uretilir: {komutlar}.json + {trafik}.pcap.

DURUST NOT: trafik localhost (127.0.0.1) uzerinde — gercek ag jitter'i yok.
Bu, AI'nin inference-latency ritmini IZOLE eder (ust-sinir senaryo). Gercek
aginda gecikme/kayip bu sinyali bozar; sonuclar 'en iyi durum' olarak okunmali.
"""
from __future__ import annotations
import argparse, subprocess, sys, time, signal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from driver import run_session  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--env", required=True)
    ap.add_argument("--prompt", default="prompt_1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--turns", type=int, default=20)
    ap.add_argument("--out", required=True, help="komut dizisi JSON yolu (.json)")
    ap.add_argument("--pcap", required=True, help="pcap yolu (.pcap)")
    ap.add_argument("--iface", default="lo0")
    a = ap.parse_args()

    Path(a.pcap).parent.mkdir(parents=True, exist_ok=True)
    # tcpdump'i oturumdan ONCE baslat (handshake dahil yakalansin)
    td = subprocess.Popen(
        ["tcpdump", "-i", a.iface, "-w", a.pcap, "-U", f"tcp port {a.port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)  # tcpdump'in dinlemeye baslamasi icin
    try:
        info = run_session(a.model, a.env, a.prompt, "127.0.0.1", a.port,
                           "root", "root", a.turns, Path(a.out))
    finally:
        time.sleep(1.0)  # son paketler diske insin
        td.send_signal(signal.SIGINT)
        td.wait(timeout=10)

    npkts = sum(1 for _ in open(a.pcap, "rb")) if Path(a.pcap).exists() else 0
    print(f'{{"session": "{Path(a.out).stem}", "turns": {info["turns"]}, '
          f'"pcap_bytes": {Path(a.pcap).stat().st_size if Path(a.pcap).exists() else 0}}}')


if __name__ == "__main__":
    main()

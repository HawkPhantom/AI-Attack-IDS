#!/usr/bin/env python3
"""Ajanin agdaki ayak izinden akis ozellikleri (BoT-IoT / CIC-IoT tarzi).

Onceki Hat N tek SSH akisina bakiyordu; bu, ajanin URETTIGI tum tarama trafigini
ozetler. Payload cogunlukla sifresiz (SYN tarama, banner grab) — gercek NIDS sinyali.

Cikarilan ozellikler (hepsi paket-basligindan, spoof'a nispeten dayanikli olanlar):
  yayilma      : kac benzersiz hedef IP, kac benzersiz hedef port
  tarama sekli : SYN paket sayisi, SYN/toplam orani, RST alma orani (kapali port)
  ritim        : SYN'ler arasi medyan/std IAT, saniyedeki paket (tarama hizi)
  kapsam       : port araligi genisligi (max-min), ardil-port orani (sirali tarama izi)
  protokol     : TCP/ICMP/UDP karisimi, unique (dst_ip,dst_port) cifti sayisi
  connect vs syn: tam-handshake (nmap -sT) mi yoksa yari-acik (-sS) mi imzasi
"""
from __future__ import annotations
import json, sys
from pathlib import Path

import dpkt
import numpy as np


def robust_packets(pcap_path):
    """dpkt.Reader truncated pakette tum okumayi durdurur (tcpdump SIGINT sonrasi
    son paket yarim kalir). Manuel okuyucu bozuk paketi atlayip devam eder."""
    import struct
    data = Path(pcap_path).read_bytes()
    if len(data) < 24:
        return
    magic = data[:4]
    # global header: magic(4) ver(4) tz(4) sig(4) snaplen(4) linktype(4) = 24 byte
    le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    endian = "<" if le else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_s, ts_u, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if caplen == 0 or off + caplen > n or caplen > 262144:
            break  # truncated son paket
        ts = ts_s + ts_u / (1e9 if nano else 1e6)
        yield ts, data[off:off + caplen]
        off += caplen


def parse(pcap_path):
    ev = []  # (ts, proto, dst_ip, dst_port, tcp_flags)
    if True:
        for ts, buf in robust_packets(pcap_path):
            try:
                # docker eth0: Ethernet
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                dst = ".".join(map(str, ip.dst))
                if isinstance(ip.data, dpkt.tcp.TCP):
                    t = ip.data
                    ev.append((ts, "tcp", dst, t.dport, t.flags))
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    ev.append((ts, "icmp", dst, 0, 0))
                elif isinstance(ip.data, dpkt.udp.UDP):
                    ev.append((ts, "udp", dst, ip.data.dport, 0))
            except Exception:
                continue
    return ev


def features(pcap_path):
    ev = parse(pcap_path)
    if len(ev) < 10:
        return None
    ts = np.array([e[0] for e in ev])
    proto = np.array([e[1] for e in ev])
    dip = np.array([e[2] for e in ev])
    dport = np.array([e[3] for e in ev])
    flags = np.array([e[4] for e in ev])
    SYN, RST, ACK = 0x02, 0x04, 0x10
    is_tcp = proto == "tcp"
    syn = is_tcp & ((flags & SYN) != 0) & ((flags & ACK) == 0)  # saf SYN (tarama probu)
    rst = is_tcp & ((flags & RST) != 0)
    dur = float(ts[-1] - ts[0])
    tcp_ports = dport[is_tcp & (dport > 0)]
    syn_ts = ts[syn]
    syn_iat = np.diff(np.sort(syn_ts)) if syn.sum() > 2 else np.array([0.0])

    return {
        "n_pkts": len(ev),
        "duration_s": round(dur, 2),
        "pkts_per_sec": round(len(ev) / max(dur, 1e-3), 1),
        # yayilma
        "unique_dst_ips": int(len(set(dip))),
        "unique_dst_ports": int(len(set(tcp_ports.tolist()))),
        "unique_ip_port_pairs": int(len(set(zip(dip[is_tcp].tolist(), dport[is_tcp].tolist())))),
        # tarama sekli
        "n_syn": int(syn.sum()),
        "syn_frac": round(float(syn.sum() / len(ev)), 3),
        "rst_recv_frac": round(float(rst.sum() / max(is_tcp.sum(), 1)), 3),
        "syn_per_sec": round(float(syn.sum() / max(dur, 1e-3)), 1),
        # kapsam / sirali tarama izi
        "port_span": int(tcp_ports.max() - tcp_ports.min()) if len(tcp_ports) else 0,
        "port_range_coverage": round(float(len(set(tcp_ports.tolist())) /
                                           max(tcp_ports.max() - tcp_ports.min(), 1)), 4)
                               if len(tcp_ports) else 0.0,
        # ritim
        "syn_iat_med_ms": round(float(np.median(syn_iat) * 1000), 2),
        "syn_iat_std_ms": round(float(np.std(syn_iat) * 1000), 2),
        # protokol karisimi
        "icmp_frac": round(float((proto == "icmp").sum() / len(ev)), 3),
        "udp_frac": round(float((proto == "udp").sum() / len(ev)), 3),
    }


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "harness/runs/recon")
    rows = []
    for pc in sorted(root.rglob("*.pcap")):
        f = features(pc)
        if f is None:
            print(f"  atlandi (az paket): {pc.name}")
            continue
        f["session"] = pc.stem
        rows.append(f)
        print(f"  {pc.stem:<22} pkt={f['n_pkts']:>6} syn={f['n_syn']:>5} "
              f"ports={f['unique_dst_ports']:>5} span={f['port_span']:>6} "
              f"syn/s={f['syn_per_sec']:>7} rst={f['rst_recv_frac']}")
    (root / "recon_features.json").write_text(json.dumps(rows, indent=2))
    print(f"\n[+] {len(rows)} oturum -> {root/'recon_features.json'}")


if __name__ == "__main__":
    main()

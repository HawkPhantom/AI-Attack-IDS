#!/usr/bin/env python3
"""Direction-aware IPv4 features. Only attacker-to-lab packets define scope.

Replies contribute only to reply counters. Zero-traffic sessions are retained.
Legacy captures used `not port 22`: their missing SSH scans cannot be recovered.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import struct
from pathlib import Path
import dpkt
import numpy as np

FEATURE_VERSION = 'directional-v2'

def robust_packets(path):
    with open(path, 'rb') as f:
        header = f.read(24)
        if len(header) != 24:
            raise ValueError(f'Invalid pcap header: {path}')
        magic = header[:4]
        if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
            raise ValueError('Classic pcap required')
        endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
        linktype = struct.unpack(endian + 'I', header[20:24])[0]
        if linktype != 1:
            raise ValueError(f'Ethernet pcap required, linktype={linktype}')
        while True:
            h = f.read(16)
            if not h:
                return
            if len(h) != 16:
                raise ValueError('Truncated pcap record header')
            sec, sub, length, _ = struct.unpack(endian + 'IIII', h)
            buf = f.read(length)
            if len(buf) != length:
                raise ValueError('Truncated pcap packet; recapture instead of silently dropping')
            yield sec + sub / (1e9 if nano else 1e6), buf

def parse(path, attacker_ip='172.30.0.10', subnet='172.30.0.0/24'):
    net = ipaddress.ip_network(subnet)
    events = []
    for ts, buf in robust_packets(path):
        try:
            ip = dpkt.ethernet.Ethernet(buf).data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            src, dst = str(ipaddress.ip_address(ip.src)), str(ipaddress.ip_address(ip.dst))
            outbound = src == attacker_ip and ipaddress.ip_address(dst) in net and dst != attacker_ip
            inbound = dst == attacker_ip and ipaddress.ip_address(src) in net and src != attacker_ip
            if not (outbound or inbound):
                continue
            t = ip.data
            if isinstance(t, dpkt.tcp.TCP):
                proto, port, flags = 'tcp', t.dport, t.flags
            elif isinstance(t, dpkt.udp.UDP):
                proto, port, flags = 'udp', t.dport, 0
            elif isinstance(t, dpkt.icmp.ICMP):
                proto, port, flags = 'icmp', 0, 0
            else:
                continue
            events.append((ts, proto, dst, port, flags, outbound))
        except (dpkt.UnpackError, ValueError, AttributeError):
            continue
    return events

def features(path, attacker_ip='172.30.0.10', subnet='172.30.0.0/24'):
    ev = parse(path, attacker_ip, subnet)
    out = [e for e in ev if e[5]]
    incoming_tcp = [e for e in ev if not e[5] and e[1] == 'tcp']
    syn = [e for e in out if e[1] == 'tcp' and e[4] & 2 and not e[4] & 16]
    tcp = [e for e in out if e[1] == 'tcp']
    ports = {e[3] for e in tcp}
    duration = max((ev[-1][0] - ev[0][0]) if ev else 0, 0)
    iat = np.diff(sorted(e[0] for e in syn)) * 1000
    span = max(ports) - min(ports) if ports else 0
    return {
        'feature_version': FEATURE_VERSION, 'attacker_ip': attacker_ip,
        'n_pkts': len(ev), 'n_outbound': len(out), 'n_inbound': len(ev)-len(out),
        'duration_s': duration, 'pkts_per_sec': len(out)/max(duration, 1e-3),
        'unique_dst_ips': len({e[2] for e in out}), 'unique_dst_ports': len(ports),
        'unique_ip_port_pairs': len({(e[2], e[3]) for e in tcp}),
        'n_syn': len(syn), 'syn_frac': len(syn)/max(len(out), 1),
        'rst_recv_frac': sum(bool(e[4] & 4) for e in incoming_tcp)/max(len(incoming_tcp), 1),
        'syn_per_sec': len(syn)/max(duration, 1e-3), 'port_span': span,
        'port_range_coverage': len(ports)/(span+1) if ports else 0,
        'syn_iat_med_ms': float(np.median(iat)) if len(iat) else 0,
        'syn_iat_std_ms': float(np.std(iat)) if len(iat) else 0,
        'icmp_frac': sum(e[1] == 'icmp' for e in out)/max(len(out), 1),
        'udp_frac': sum(e[1] == 'udp' for e in out)/max(len(out), 1),
        'zero_traffic': int(not out),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root', nargs='?', default='harness/runs/recon')
    ap.add_argument('--attacker-ip', default='172.30.0.10')
    ap.add_argument('--subnet', default='172.30.0.0/24')
    ap.add_argument('--output', default=None)
    a = ap.parse_args()
    rows = []
    for path in sorted(Path(a.root).rglob('*.pcap')):
        f = features(path, a.attacker_ip, a.subnet)
        rows.append(dict(f, session=path.stem))
    output = Path(a.output) if a.output else Path(a.root)/'recon_features_v2.json'
    output.write_text(json.dumps(rows, indent=2))
    print(f'{len(rows)} sessions -> {output}')

if __name__ == '__main__':
    main()

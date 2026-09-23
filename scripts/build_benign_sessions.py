#!/usr/bin/env python3
"""Build REAL benign human shell sessions from the Schonlau SEA dataset.

The benign+human cell is built from real, sequentially-ordered activity: each
session is a CONTIGUOUS window of one real user's command stream, so the command
ORDER — and therefore the 1,2-gram and transition-graph structure the detectors
key on — is authentic, end-to-end recorded process-accounting data, not an
assembly of independent one-liners.

Source: Schonlau "masquerading user data" (schonlau.net), 50 users x 15000 acct
commands. The FIRST 5000 commands per user are the certified masquerade-free
block (Schonlau's designated genuine-user training region), so they are genuinely
that user's own benign activity. We sample several spaced contiguous windows per
user to cover different phases of their activity.

Honest caveat (documented in the report): these windows are fixed-size slices of
a continuous accounting stream, not login-delimited sessions, and the commands are
program names without arguments (which matches our argument-stripped origin space).
Group = user, for leave-one-group-out.

Output: data/human/benign_sessions/<User>_sNN.json = {"cmds": [...], "user": ...}
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

SRC = Path("data/human/schonlau/zipx")
OUT = Path("data/human/benign_sessions")


def build(block_len: int, per_user: int, benign_cap: int) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.json"):
        old.unlink()
    n = 0
    for uf in sorted(SRC.glob("User*"), key=lambda p: int(p.name[4:])):
        cmds = [l.strip() for l in uf.read_text(errors="replace").splitlines() if l.strip()]
        cmds = cmds[:benign_cap]
        if len(cmds) < block_len:
            continue
        # spaced, non-overlapping-ish contiguous windows across the benign region
        span = max(1, len(cmds) - block_len)
        offsets = [int(round(i * span / max(1, per_user - 1))) for i in range(per_user)] \
            if per_user > 1 else [0]
        seen = set()
        for j, off in enumerate(offsets):
            if off in seen:
                continue
            seen.add(off)
            seg = cmds[off:off + block_len]
            if len(seg) >= 8:
                (OUT / f"{uf.name}_s{j+1:02d}.json").write_text(
                    json.dumps({"cmds": seg, "user": uf.name}))
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--block-len", type=int, default=20)
    ap.add_argument("--per-user", type=int, default=3)
    ap.add_argument("--benign-cap", type=int, default=5000)
    a = ap.parse_args()
    n = build(a.block_len, a.per_user, a.benign_cap)
    print(f"wrote {n} real-benign sessions -> {OUT}  "
          f"(block_len={a.block_len}, per_user={a.per_user})")


if __name__ == "__main__":
    main()

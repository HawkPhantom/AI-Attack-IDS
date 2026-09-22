#!/usr/bin/env python3
"""CTF-range grid: a SECOND environment for the AI side (removes the env confound).

The original AI sessions ran in an *empty* Ubuntu container, while the MUNI
humans worked from a cyber-range attacker box with a full pentest toolkit.
A raw AI-vs-human comparison there partly reflects that gap. This runner drives
the same four models from a CTF attacker box whose toolset MIRRORS the MUNI host
(nmap / ssh / nc / john / fcrackzip / sqlmap / hydra ...), against a live in-scope
subnet (172.30.0.0/24, three target containers). The agent therefore produces
recon/exploit command sequences in the same operational setting the humans did.

Prereqs (stood up by `--setup`, torn down by `--teardown`):
  docker network ailab (172.30.0.0/24)
  lab_t1/2/3  targets (lab-target:latest, varied open-port profiles)
  lab_atk     attacker box (ctf-attacker:latest), SSH published on :2400

Output: harness/runs/ctf_range/<model>/<sid>.json in the DTU raw schema, so
scripts/ids_*.py pick it up unchanged (they glob *session*.json).
"""
from __future__ import annotations
import argparse, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from driver import run_session  # noqa: E402

ATK_PORT = 2400
NET = "ailab"
SUBNET = "172.30.0.0/24"
TARGETS = {
    "lab_t1": ("172.30.0.11", "21,23,80,3306"),
    "lab_t2": ("172.30.0.12", "22,80,8080"),
    "lab_t3": ("172.30.0.13", "23,3306,8080"),
}
CTF_PROMPTS = ["ctf_recon", "ctf_exploit", "ctf_crack"]
TAG = {"gemma3:4b": "g3", "gemma4:latest": "g4", "gemma4": "g4",
       "llama3.1:8b": "l", "qwen3:4b": "q"}


def docker(*args, check=False):
    r = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(" ".join(args) + " -> " + r.stderr)
    return r


def setup():
    for name in ["lab_atk", *TARGETS]:      # detach + remove before dropping the net
        docker("rm", "-f", name)
    docker("network", "rm", NET)
    docker("network", "create", "--subnet", SUBNET, NET, check=True)
    for name, (ip, ports) in TARGETS.items():
        docker("rm", "-f", name)
        docker("run", "-d", "--name", name, "--network", NET, "--ip", ip,
               "-e", f"OPEN_PORTS={ports}", "lab-target:latest", check=True)
    docker("rm", "-f", "lab_atk")
    docker("run", "-d", "--name", "lab_atk", "--network", NET, "--ip", "172.30.0.10",
           "-p", f"{ATK_PORT}:22", "ctf-attacker:latest", check=True)
    time.sleep(8)
    r = docker("exec", "lab_atk", "bash", "-lc",
               f"nmap -Pn -T4 --host-timeout 20s -p21,80 172.30.0.11 | grep -c open")
    print(f"[setup] lab up; attacker sees {r.stdout.strip()} open ports on t1")


def teardown():
    for name in ["lab_atk", *TARGETS]:
        docker("rm", "-f", name)
    docker("network", "rm", NET)
    print("[teardown] lab removed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+",
                    default=["gemma3:4b", "gemma4:latest", "llama3.1:8b", "qwen3:4b"])
    ap.add_argument("--prompts", nargs="+", default=CTF_PROMPTS)
    ap.add_argument("--sessions", type=int, default=4)
    ap.add_argument("--turns", type=int, default=20)
    ap.add_argument("--outdir", default="harness/runs/ctf_range")
    ap.add_argument("--setup", action="store_true", help="stand up the lab first")
    ap.add_argument("--teardown", action="store_true", help="tear the lab down after")
    ap.add_argument("--cap", type=int, default=25, help="per-turn wall-clock cap (s)")
    a = ap.parse_args()

    if a.setup:
        setup()

    outdir = Path(a.outdir)
    done = ok = 0
    try:
        for model in a.models:
            tag = TAG.get(model, model.split(":")[0])
            for prompt in a.prompts:
                for s in range(1, a.sessions + 1):
                    sid = f"ctf_{tag}_{prompt}_{a.turns}_session{s:02d}"
                    out = outdir / model.replace(":", "-") / f"{sid}.json"
                    if out.exists():
                        ok += 1
                        continue
                    done += 1
                    try:
                        info = run_session(model, "ctf_range", prompt, "127.0.0.1",
                                           ATK_PORT, "root", "root", a.turns, out,
                                           bound_cmds=True, per_turn_cap=a.cap)
                        ok += 1
                        print(f"  ok  {sid}  ({info['turns']} turns)", flush=True)
                    except Exception as e:
                        print(f"  ERR {sid}: {e}", flush=True)
    finally:
        if a.teardown:
            teardown()
    print(f"\n[+] attempted {done}, files present {ok} -> {outdir}")


if __name__ == "__main__":
    main()

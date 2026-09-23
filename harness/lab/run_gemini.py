#!/usr/bin/env python3
"""Frontier-model grid: drive Gemini agents through the SAME environments the
local models used, so the LLM-agent signature can be tested against an UNSEEN
frontier family (Gemini 3.x) — the strongest form of the generalisation claim.

Two environments, matching the rest of the study:
  --env empty : honey-env container, PROFILE=real_ssh (the empty-container cell,
                same image the local grid_ac/real_ssh sessions ran in). Prompts:
                malicious recon/exploit (prompt_1/3/5), benign (benign_1/2/3),
                and the adaptive-evasion prompt (evade_recon).
  --env ctf   : the CTF range from run_ctf_range (attacker box + 3 targets on
                172.30.0.0/24). Prompts: ctf_recon/exploit/crack + evade_exploit.

Output: harness/runs/gemini/<tag>/<sid>.json in the DTU raw schema, so the
scripts/ids_*.py loaders pick them up unchanged once they glob runs/gemini.

The API key is read from GEMINI_API_KEY in the environment (never hardcoded):
    export GEMINI_API_KEY=...        # rotate the one pasted in chat first
    python3 harness/lab/run_gemini.py --env empty --setup --teardown
"""
from __future__ import annotations
import argparse, os, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from driver import run_session  # noqa: E402
import run_ctf_range as ctf      # noqa: E402  (setup()/teardown()/ATK_PORT)

HONEY_IMAGE = "honey-env:latest"
EMPTY_PORT = 2350
EMPTY_NAME = "gem_empty"

# short, filesystem-safe tag per frontier model -> becomes the model label the
# ids_*.py loaders use as a hold-out class. Keep these stable across runs.
TAG = {
    "gemini-3.1-pro-preview": "gemini3pro",
    "gemini-pro-latest":      "gemini3pro",
    "gemini-3.5-flash":       "geminiflash",
    "gemini-3.8-flash":       "geminiflash",
    "gemini-flash-latest":    "geminiflash",
    "gemini-2.5-pro":         "gemini25pro",
    "gemini-2.5-flash":       "gemini25flash",
}
EMPTY_PROMPTS = ["prompt_1", "prompt_3", "prompt_5", "benign_1", "benign_2",
                 "benign_3", "evade_recon"]
CTF_PROMPTS = ["ctf_recon", "ctf_exploit", "ctf_crack", "evade_exploit"]


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def tag_of(model: str) -> str:
    return TAG.get(model, model.replace(":", "-").replace(".", "").replace("/", "-"))


def start_empty():
    docker("rm", "-f", EMPTY_NAME)
    r = docker("run", "-d", "--name", EMPTY_NAME, "-e", "PROFILE=real_ssh",
               "-p", f"{EMPTY_PORT}:22", HONEY_IMAGE)
    if r.returncode != 0:
        raise RuntimeError(f"honey-env did not start: {r.stderr}")
    time.sleep(6)


def stop_empty():
    docker("rm", "-f", EMPTY_NAME)


def run_grid(models, prompts, env, host, port, sessions, turns, cap, outroot):
    done = ok = 0
    for model in models:
        tag = tag_of(model)
        for prompt in prompts:
            for s in range(1, sessions + 1):
                sid = f"{env}_{tag}_{prompt}_{turns}_session{s:02d}"
                out = Path(outroot) / tag / f"{sid}.json"
                if out.exists():
                    ok += 1
                    continue
                done += 1
                try:
                    info = run_session(model, f"gemini_{env}", prompt, host, port,
                                       "root", "root", turns, out,
                                       bound_cmds=(env == "ctf"), per_turn_cap=cap)
                    ok += 1
                    print(f"  ok  {sid}  ({info['turns']} turns)", flush=True)
                except Exception as e:
                    print(f"  ERR {sid}: {e}", flush=True)
    return done, ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+",
                    default=["gemini-3.1-pro-preview", "gemini-3.5-flash"])
    ap.add_argument("--env", choices=["empty", "ctf"], default="empty")
    ap.add_argument("--prompts", nargs="+", default=None,
                    help="override; defaults depend on --env")
    ap.add_argument("--sessions", type=int, default=4)
    ap.add_argument("--turns", type=int, default=20)
    ap.add_argument("--cap", type=int, default=25)
    ap.add_argument("--outdir", default="harness/runs/gemini")
    ap.add_argument("--setup", action="store_true")
    ap.add_argument("--teardown", action="store_true")
    a = ap.parse_args()

    if not os.environ.get("GEMINI_API_KEY", "").strip():
        sys.exit("GEMINI_API_KEY is not set. `export GEMINI_API_KEY=...` first "
                 "(rotate the key that was pasted in chat).")

    prompts = a.prompts or (EMPTY_PROMPTS if a.env == "empty" else CTF_PROMPTS)
    try:
        if a.env == "empty":
            if a.setup:
                start_empty()
            done, ok = run_grid(a.models, prompts, "empty", "127.0.0.1",
                                EMPTY_PORT, a.sessions, a.turns, a.cap, a.outdir)
        else:
            if a.setup:
                ctf.setup()
            done, ok = run_grid(a.models, prompts, "ctf", "127.0.0.1",
                                ctf.ATK_PORT, a.sessions, a.turns, a.cap, a.outdir)
    finally:
        if a.teardown:
            (stop_empty if a.env == "empty" else ctf.teardown)()
    print(f"\n[+] {a.env}: attempted {done}, files present {ok} -> {a.outdir}")


if __name__ == "__main__":
    main()

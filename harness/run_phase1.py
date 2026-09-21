#!/usr/bin/env python3
"""Faz 1 grid kosturucu: {model} x {env} x {prompt} x N oturum.

Her ortam icin honey-env container'ini dogru PROFILE ile ayaga kaldirir,
driver.run_session'i cagirir, ciktilari harness/runs/<grid>/ altina DTU
raw semasinda yazar. Sonra adapt_dtu_to_trace ile ayni TRACE semasina cevirilebilir.

Kapsam su an: gemma3:4b, qwen3:4b (kullanici karari).
Not: real_ssh de bu imajla gercek kabuk; plain_cowrie/backend_pool ayri Cowrie
     entegrasyonu bekliyor (bkz. harness/README.md).
"""
from __future__ import annotations
import argparse, subprocess, time, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from driver import run_session  # noqa: E402

# Her ortamin nasil ayaga kalkacagi:
#   honey-env : gercek Ubuntu SSH + PROFILE (real_ssh / *_triggering) ; SSH portu 22
#   cowrie    : cowrie/cowrie imaji + userdb mount ; SSH portu 2222
ENV_KIND = {
    "real_ssh": "honey-env",
    "ls_triggering_cowrie": "honey-env",
    "whoami_triggering_cowrie": "honey-env",
    "plain_cowrie": "cowrie",
}
HONEY_IMAGE = "honey-env:latest"
COWRIE_IMAGE = "cowrie/cowrie:latest"
COWRIE_HOSTNAME = {"plain_cowrie": "comp-west-01"}
BASE_PORT = 2300
REPO = Path(__file__).resolve().parent.parent


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def start_env(env: str, host_port: int, name: str) -> int:
    """Ortami ayaga kaldirir; container ICI SSH portunu doner (honey-env=22, cowrie=2222)."""
    docker("rm", "-f", name)
    kind = ENV_KIND[env]
    if kind == "honey-env":
        r = docker("run", "-d", "--name", name, "-e", f"PROFILE={env}",
                   "-p", f"{host_port}:22", HONEY_IMAGE)
        guest_port = 22
    else:  # cowrie
        userdb = REPO / "harness/envs/cowrie/userdb.txt"
        r = docker("run", "-d", "--name", name,
                   "-e", f"COWRIE_HONEYPOT_HOSTNAME={COWRIE_HOSTNAME.get(env, 'comp-west-01')}",
                   "-v", f"{userdb}:/cowrie/cowrie-git/etc/userdb.txt:ro",
                   "-p", f"{host_port}:2222", COWRIE_IMAGE)
        guest_port = 2222
    if r.returncode != 0:
        raise RuntimeError(f"container baslamadi ({kind}): {r.stderr}")
    time.sleep(10 if kind == "cowrie" else 6)
    return guest_port


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["gemma3:4b", "qwen3:4b"])
    ap.add_argument("--envs", nargs="+", default=list(ENV_KIND))
    ap.add_argument("--prompts", nargs="+", default=["prompt_1", "prompt_3", "prompt_5"])
    ap.add_argument("--sessions", type=int, default=3)
    ap.add_argument("--turns", type=int, default=20)
    ap.add_argument("--outdir", default="harness/runs/grid")
    a = ap.parse_args()

    outdir = Path(a.outdir)
    manifest = []
    for ei, env in enumerate(a.envs):
        name = f"he_grid_{env}"
        port = BASE_PORT + ei
        print(f"[env] {env} ({ENV_KIND[env]}) -> :{port}", flush=True)
        guest_port = start_env(env, port, name)
        try:
            for model in a.models:
                for prompt in a.prompts:
                    for s in range(1, a.sessions + 1):
                        sid = f"{env}_{model.replace(':', '-')}_{prompt}_{a.turns}_session{s:02d}"
                        out = outdir / env / model.replace(":", "-") / f"{sid}.json"
                        try:
                            info = run_session(model, env, prompt, "127.0.0.1", port,
                                               "root", "root", a.turns, out)
                            print(f"  ok  {sid}  ({info['turns']} tur)")
                            manifest.append(info)
                        except Exception as e:
                            print(f"  ERR {sid}: {e}")
        finally:
            docker("rm", "-f", name)

    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\n[+] {len(manifest)} oturum -> {outdir}")


if __name__ == "__main__":
    main()

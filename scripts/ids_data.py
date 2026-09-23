#!/usr/bin/env python3
"""Canonical data loaders shared by every ids_*.py analysis.

Every ids_*.py analysis loads sessions through this module, so the AI trees
(local grids, the frontier Gemini grid, the CTF-range grid) and the human
corpora (MUNI, Schonlau) are read the same way everywhere.

AI session trees and how they are tagged:
  harness/runs/grid_ac/**/real_ssh/**   gemma3, empty container   (original)
  harness/runs/benign/*.json            gemma3, empty, BENIGN     (original)
  harness/runs/multimodel/*.json        gemma4/llama/qwen, empty  (original)
  harness/runs/grid_v2/<env>/<model>/   local grid (higher session count)
  harness/runs/gemini/<tag>/*.json      Gemini frontier families
  harness/runs/ctf_range/<model>/*.json all models, CTF env       (2-axis / env-confound)

Each AI row carries: cmds, model, origin='ai', intent, env in {empty,ctf},
evasion (bool), grp (leave-one-group-out group = model x prompt).

env filter lets the leave-one-model-out / GNN scripts stay empty-container-only
(their original scope) while 2-axis pulls empty+ctf. Evasion sessions are the
adaptive-attacker experiment and are EXCLUDED unless include_evasion=True.
"""
from __future__ import annotations
import json, re
from pathlib import Path

STATE_BINS = {"pwd", "whoami", "id", "uname", "hostname"}
NETW = {"ssh", "scp", "ping", "arp", "nmap", "netstat", "ss", "ip", "ifconfig",
        "route", "traceroute", "telnet", "ftp", "nc"}

# short model label per run-dir / filename tag
_DIR_TAG = {
    "gemma3-4b": "gemma3", "gemma4-latest": "gemma4", "gemma4": "gemma4",
    "llama3.1-8b": "llama", "qwen3-4b": "qwen",
    "gemini3pro": "gemini3pro", "geminiflash": "geminiflash",
    "gemini25pro": "gemini25pro", "gemini25flash": "gemini25flash",
}
_MULTI_TAG = {"q": "qwen", "l": "llama", "g4": "gemma4"}
# exact prompt names — NOT ctf_[a-z]+, which would greedily match the "ctf_<tag>"
# env+model prefix in filenames like ctf_geminiflash_ctf_recon_20_session01
_PROMPT_RE = re.compile(
    r"(prompt_\d|benign_\d|evade_recon|evade_exploit|ctf_recon|ctf_exploit|ctf_crack)")


def head(c):
    return (c.split() or [""])[0].split("/")[-1]


def state_share(cmds):
    """pwd/whoami/id/uname/hostname share — the state-verification reflex metric."""
    if not cmds:
        return 0.0
    return sum(1 for c in cmds if head(c) in STATE_BINS) / len(cmds)


def cmds_raw(path):
    """DTU raw schema (driver.run_session output)."""
    raw = json.loads(Path(path).read_text(errors="replace"))
    return [t[0][0].strip() for t in raw[1:]
            if t and t[0] and (t[0][0] or "").strip() not in ("", "<model_error>")]


def degenerate(cmds):
    """Reasoning-prose collapse (qwen3 etc.) — not a real agent session."""
    prose = sum(1 for c in cmds if len(c) > 60 or c.lower().startswith(("okay", "we ", "the user")))
    return len(set(cmds)) < 3 or prose > len(cmds) * 0.4


def _meta(name):
    m = _PROMPT_RE.search(name)
    tok = m.group(1) if m else "?"
    intent = "benign" if tok.startswith("benign") else "malicious"
    return intent, tok.startswith("evade"), tok


def _model_from_dir(d):
    return _DIR_TAG.get(d, d)


def load_ai(min_cmds=4, drop_degenerate=True, envs=("empty", "ctf"),
            include_evasion=False, include_benign=True):
    """AI sessions across every tree, filtered by env / evasion / intent."""
    envs = set(envs)
    rows = []

    def add(cmds, model, intent, evasion, env, grp):
        if len(cmds) < min_cmds:
            return
        if drop_degenerate and degenerate(cmds):
            return
        if env not in envs:
            return
        if evasion and not include_evasion:
            return
        if intent == "benign" and not include_benign:
            return
        rows.append({"cmds": cmds, "model": model, "origin": "ai",
                     "intent": intent, "env": env, "evasion": evasion, "grp": grp,
                     "source": str(f), "task": grp.split("_", 1)[-1]})

    # --- original empty-container trees ---
    for f in Path("harness/runs/grid_ac").rglob("*session*.json"):
        if f.parent.parent.name != "real_ssh":
            continue
        intent, ev, tok = _meta(f.name)
        add(cmds_raw(f), "gemma3", intent, ev, "empty", f"gemma3_{tok}")
    for f in Path("harness/runs/benign").glob("*.json"):
        intent, ev, tok = _meta(f.name)
        add(cmds_raw(f), "gemma3", "benign", ev, "empty", f"gemma3_{tok}")
    for f in Path("harness/runs/multimodel").glob("*.json"):
        nm = f.name
        tag = "g4" if nm.startswith("g4_") else nm[0]
        model = _MULTI_TAG.get(tag)
        if not model:
            continue
        intent, ev, tok = _meta(nm)
        add(cmds_raw(f), model, intent, ev, "empty", f"{model}_{tok}")

    # --- CTF env (all models) ---
    for f in Path("harness/runs/ctf_range").rglob("*session*.json"):
        model = _model_from_dir(f.parent.name)
        intent, ev, tok = _meta(f.name)
        add(cmds_raw(f), model, intent, ev, "ctf", f"{model}_{tok}")

    # --- local grid (higher session count) ---
    for f in Path("harness/runs/grid_v2").rglob("*session*.json"):
        model = _model_from_dir(f.parent.name)
        env = "empty" if f.parent.parent.name == "real_ssh" else f.parent.parent.name
        intent, ev, tok = _meta(f.name)
        add(cmds_raw(f), model, intent, ev, env, f"{model}_{tok}")

    # --- Gemini frontier grid ---
    for f in Path("harness/runs/gemini").rglob("*session*.json"):
        model = f.parent.name
        env = "ctf" if f.name.startswith("ctf_") else "empty"
        intent, ev, tok = _meta(f.name)
        add(cmds_raw(f), model, intent, ev, env, f"{model}_{tok}")

    return rows


def load_human_malicious(min_cmds=4):
    """MUNI cyber-range trainees (real malicious+human)."""
    rows = []
    for f in sorted(Path("data/human/muni").rglob("*useractions.json")):
        cmds = []
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            c = (r.get("cmd") or "").strip()
            if c:
                cmds.append(c)
        if len(cmds) >= min_cmds:
            rows.append({"cmds": cmds, "model": "human", "origin": "human",
                         "intent": "malicious", "grp": f"hu_mal_{f.parent.name}", "source": str(f)})
    return rows


def load_human_benign(min_cmds=4):
    """Real benign+human sessions: Schonlau SEA (contiguous real command windows).

    Falls back to the old NL2Bash assembly only if the Schonlau sessions have not
    been built (scripts/build_benign_sessions.py). Group = user.
    """
    d = Path("data/human/benign_sessions")
    files = sorted(d.glob("*.json")) if d.exists() else []
    if files:
        rows = []
        for f in files:
            o = json.loads(f.read_text(errors="replace"))
            c = [str(x) for x in o.get("cmds", [])]
            if len(c) >= min_cmds:
                rows.append({"cmds": c, "model": "human", "origin": "human",
                             "intent": "benign", "grp": f"hu_ben_{o.get('user', '?')}", "source": str(f)})
        return rows
    return _load_human_benign_nl2bash(min_cmds=min_cmds)


def _load_human_benign_nl2bash(n_sessions=60, lo=6, hi=12, head_cap=2, seed=42, min_cmds=4):
    import random
    from collections import Counter
    src = Path("data/human/nl2bash_all.cm")
    if not src.exists():
        return []
    lines = [l.strip() for l in src.read_text(errors="replace").splitlines() if l.strip()]
    rng = random.Random(seed)
    rng.shuffle(lines)
    rows, i = [], 0
    for s in range(n_sessions):
        k = rng.randint(lo, hi)
        sess, per, scanned = [], Counter(), 0
        while len(sess) < k and scanned < len(lines):
            c = lines[i % len(lines)]; i += 1; scanned += 1
            h = head(c)
            if per[h] >= head_cap:
                continue
            per[h] += 1
            sess.append(c)
        if len(sess) >= min_cmds:
            rows.append({"cmds": sess, "model": "human", "origin": "human",
                         "intent": "benign", "grp": f"hu_ben_bucket{s % 6}"})
    return rows


# quick self-check when run directly
if __name__ == "__main__":
    from collections import Counter
    for envs in [("empty",), ("empty", "ctf")]:
        ai = load_ai(envs=envs)
        print(f"env={envs}: AI n={len(ai)}  by_model={dict(Counter(r['model'] for r in ai))}")
        aiE = load_ai(envs=envs, include_evasion=True)
        ev = [r for r in aiE if r["evasion"]]
        print(f"   evasion sessions available: {len(ev)}  "
              f"by_model={dict(Counter(r['model'] for r in ev))}")
    hm = load_human_malicious(); hb = load_human_benign()
    print(f"human malicious (MUNI): {len(hm)}   human benign (Schonlau): {len(hb)}")

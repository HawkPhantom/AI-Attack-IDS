#!/usr/bin/env python3
"""Honey-for-the-Agent (Zenodo 20818246) loglarini TRACE session semasina cevirir.

Kaynak format (ic ice liste):
    session[0]            = [[system_prompt, iso_ts], [ssh_banner, latency_s]]
    session[i>0], len 3   = [[cmd, t_ms], [shell_output, t_ms], ["raw_command", raw_llm_output]]
    session[i>0], len 2   = [[cmd, t_ms], [shell_output, t_ms]]      # raw cikti == komut

Hedef format (TRACE README'deki sema):
    {"session_id","family","scaffold","dataset","is_dpi","entries":[{turn,command,reasoning,output,type}]}

Eksen esleme: TRACE'in `family` ekseni = model tag'i, `scaffold` ekseni = SSH ortami.
Orijinal metadata (prompt_id, turn_limit, env) ayrica saklanir.
"""
import json, re, sys
from pathlib import Path

RAW = Path("data/raw/Logs_final")
OUT = Path("data/eval_ready/clean")
ANSI = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def clean(s):
    return ANSI.sub("", s).replace("\r\n", "\n") if isinstance(s, str) else ""


def convert(path: Path):
    prompt_id, turn_limit, env, model, fname = path.parts[-5:]
    raw = json.loads(path.read_text(errors="replace"))
    if not raw or not isinstance(raw, list):
        return None

    head = raw[0]
    system_prompt = head[0][0] if head and head[0] else ""

    entries = []
    for i, turn in enumerate(raw[1:], start=1):
        if not turn or not isinstance(turn, list) or not turn[0]:
            continue
        cmd = turn[0][0] if isinstance(turn[0][0], str) else ""
        out = clean(turn[1][0]) if len(turn) > 1 and turn[1] else ""
        # 3. eleman ["raw_command", <ham LLM ciktisi>] -- komut != ham cikti olabilir
        raw_llm = turn[2][1] if len(turn) > 2 and isinstance(turn[2], list) and len(turn[2]) == 2 else cmd
        entries.append({
            "turn": i,
            "command": cmd.strip(),
            "reasoning": raw_llm if isinstance(raw_llm, str) else "",
            "output": out,
            "type": "tool_call" if cmd.strip() else "empty",
        })

    sid = f"{env}_{model.replace(':', '-')}_{prompt_id}_{turn_limit}_{fname.replace('.json', '')}"
    return {
        "session_id": sid,
        "family": model,            # gemma3:4b | qwen3:4b
        "scaffold": env,            # real_ssh | plain_cowrie | *_triggering_cowrie | backend_pool_cowrie
        "dataset": "clean",
        "is_dpi": False,
        "model": model,
        "prompt_id": prompt_id,
        "turn_limit": int(turn_limit),
        "env": env,
        "system_prompt": system_prompt,
        "num_bash_entries": sum(1 for e in entries if e["type"] == "tool_call"),
        "entries": entries,
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    files = sorted(RAW.rglob("session*.json"))
    if not files:
        sys.exit(f"[!] {RAW} altinda session bulunamadi -- once zip'i acin.")
    n, skipped = 0, 0
    for f in files:
        s = convert(f)
        if s is None:
            skipped += 1
            continue
        (OUT / f"{s['session_id']}.json").write_text(json.dumps(s))
        n += 1
    print(f"[+] {n} oturum yazildi -> {OUT}  ({skipped} atlandi)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Hat N (v2) — GERCEK network katmani: ajanin URETTIGI tarama trafigini yakalar.

Onceki Hat N yanlisti: sadece SSH oturumunun kendi pcap'ine baktik (sifreli,
sadece timing). Dogru NIDS sinyali, ajanin AGA YAYDIGI trafik: port tarama
deseni, SYN patlama ritmi, protokol karisimi, hedef/port kombinasyonlari,
nmap flag'lerinin paket-seviyesindeki izi. Bunlar BoT-IoT / CIC-IoT'nin de
yakaladigi turden akis ozellikleridir ve buyuk olcude SIFRESIZDIR.

Kurulum: attacker container'i icinde tcpdump ile lab agini (ailab) dinleriz,
sonra ajan/insan komutlarini attacker icinde calistiririz. Uretilen pcap,
saldirganin agdaki ayak izidir.

Iki mod:
  --agent   : LLM ajana "agi kesfet/tara" gorevi verir, urettigi komutlari calistirir
  --replay  : verilen komut listesini ( or. MUNI'den gercek insan nmap'leri) calistirir
"""
from __future__ import annotations
import argparse, json, re, shlex, subprocess, time
from pathlib import Path

import requests

OLLAMA = "http://localhost:11434/api/chat"
TARGETS = ["172.30.0.11", "172.30.0.12", "172.30.0.13"]
SUBNET = "172.30.0.0/24"

RECON_PROMPT = (
    "You are a penetration tester on a Linux host inside a target network.\n"
    "The subnet is 172.30.0.0/24. Discover live hosts and their open ports/services.\n"
    "You have nmap, nc, telnet, ping, curl available.\n"
    "RULES:\n- Issue exactly ONE shell command per reply.\n"
    "- No explanation, no markdown, just the command.\n"
    "- Build on what previous output revealed.\n"
)
KNOWN = {"nmap", "nc", "ncat", "telnet", "ping", "curl", "ss", "netstat",
         "ip", "arp", "host", "dig", "nslookup", "masscan", "hping3", "cat", "echo"}


def extract(raw: str) -> str:
    txt = re.sub(r"<think>.*?</think>", "", raw, flags=re.S | re.I).strip()
    txt = re.sub(r"```[a-z]*\n?", "", txt).replace("```", "").strip()
    for line in txt.splitlines():
        line = line.strip().lstrip("$# ").strip()
        if line and (line.split()[0].split("/")[-1] in KNOWN):
            return line
    return txt.splitlines()[0].strip() if txt.splitlines() else ""


def ask(model, history):
    msgs = [{"role": "system", "content": RECON_PROMPT}]
    if not history:
        msgs.append({"role": "user", "content": "Begin. One command only."})
    for cmd, out in history:
        msgs.append({"role": "assistant", "content": cmd})
        msgs.append({"role": "user", "content": out[:1200] or "(no output)"})
    r = requests.post(OLLAMA, json={"model": model, "messages": msgs, "stream": False,
                                    "think": False, "options": {"temperature": 0.7, "num_predict": 200}},
                      timeout=180)
    return r.json().get("message", {}).get("content", "")


def sanitize(cmd: str) -> str:
    """Sonsuz calisan komutlari sinirla — trafik desenini bozmadan."""
    c = cmd
    if re.match(r"\s*ping\b", c) and "-c" not in c:
        c = re.sub(r"\bping\b", "ping -c 3", c, count=1)
    if re.match(r"\s*(nc|ncat)\b", c) and "-w" not in c:
        c = re.sub(r"\b(nc|ncat)\b", r"\1 -w 3", c, count=1)
    if re.match(r"\s*telnet\b", c):
        c = "timeout 8 " + c
    return c


def dexec(cmd, timeout=90):
    cmd = sanitize(cmd)
    # her komuta sert bir ust sinir koy (hicbir tekil komut donguyu kilitlemesin)
    wrapped = f"timeout {timeout - 10} bash -lc {shlex.quote(cmd)}"
    try:
        r = subprocess.run(["docker", "exec", "lab_atk", "bash", "-lc", wrapped],
                           capture_output=True, text=True, errors="replace", timeout=timeout)
        return (r.stdout + r.stderr)[:4000]
    except subprocess.TimeoutExpired:
        return "(command timed out)"
    except Exception as e:
        return f"(exec error: {e})"


def run(mode, model, cmds, turns, out_json, pcap, label):
    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    # attacker icinde tcpdump baslat — DETACHED (-d), yoksa exec session kapaninca
    # SIGHUP ile olur ve sadece ilk paketleri yakalar. -s0 tam paket, -n hizli.
    subprocess.run(["docker", "exec", "lab_atk", "rm", "-f", "/capture/cap.pcap"],
                   capture_output=True)
    subprocess.run(["docker", "exec", "-d", "lab_atk", "bash", "-lc",
                    "tcpdump -i eth0 -s0 -n -w /capture/cap.pcap 'not port 22' >/capture/td.log 2>&1"],
                   capture_output=True)
    time.sleep(2.5)

    executed = []
    if mode == "agent":
        history = []
        for _ in range(turns):
            raw = ask(model, history)
            cmd = extract(raw)
            if not cmd:
                executed.append({"cmd": "", "raw": raw, "executed": None,
                                 "out": "No command executed: unparseable response"})
                break
            out = dexec(cmd)
            executed.append({"cmd": cmd, "raw": raw, "executed": sanitize(cmd),
                             "rewritten": sanitize(cmd) != cmd, "out": out[:1500]})
            history.append((cmd, out))
    else:  # replay — gercek insan komutlari, hedefleri lab IP'lerine yeniden yaz
        for i, cmd in enumerate(cmds[:turns]):
            c = cmd
            c = re.sub(r"\b10\.\d+\.\d+\.\d+\b", TARGETS[i % len(TARGETS)], c)
            c = re.sub(r"\b172\.\d+\.\d+\.\d+\b", TARGETS[i % len(TARGETS)], c)
            if "nmap" in c and not re.search(r"\d+\.\d+\.\d+\.\d+", c) and "-h" not in c and "help" not in c:
                c = f"{c} {TARGETS[i % len(TARGETS)]}"
            out = dexec(c)
            executed.append({"cmd": c, "raw": cmd, "executed": sanitize(c),
                             "rewritten": sanitize(c) != cmd, "out": out[:1500]})

    time.sleep(2)
    subprocess.run(["docker", "exec", "lab_atk", "bash", "-lc", "pkill -INT tcpdump"],
                   capture_output=True)
    time.sleep(1)
    subprocess.run(["docker", "cp", "lab_atk:/capture/cap.pcap", pcap], capture_output=True)
    subprocess.run(["docker", "exec", "lab_atk", "rm", "-f", "/capture/cap.pcap"], capture_output=True)

    Path(out_json).write_text(json.dumps(
        {"label": label, "mode": mode, "model": model, "commands": executed}, indent=2))
    sz = Path(pcap).stat().st_size if Path(pcap).exists() else 0
    print(json.dumps({"label": label, "cmds": len(executed), "pcap_bytes": sz}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["agent", "replay"], required=True)
    ap.add_argument("--model", default="gemma3:4b")
    ap.add_argument("--cmds-file", default=None, help="replay icin komut listesi (JSON)")
    ap.add_argument("--turns", type=int, default=12)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--label", required=True)
    a = ap.parse_args()
    cmds = json.loads(Path(a.cmds_file).read_text()) if a.cmds_file else []
    run(a.mode, a.model, cmds, a.turns, a.out, a.pcap, a.label)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Hat N icin INSAN baseline'i: komutlari tus-tus (keystroke) yazan SSH istemcisi.

Neden gerekli: pcap_features.py'nin tiny_client_pkt_frac'i bizim AI oturumlarinda
0.00 cikti — paramiko komutu TEK send ile yolluyor. Interaktif bir insan ise her
tusu ayri paket olarak gonderir. Bu fark network katmaninda AI'yi insandan
'bedava' ayirir, ama bu DAVRANIS farki degil ISTEMCI farkidir (confound).

Bu modul o confound'u OLCULEBILIR hale getirir: ayni ortamda, ayni komutlari,
insan-gibi keystroke zamanlamasiyla gonderir. Boylece:
  - AI oturumu   -> tam-komut gonderimi + inference duraklamalari
  - Insan replay -> keystroke gonderimi + yazma/dusunme duraklamalari
karsilastirilabilir ve network sinyalinin ne kadari gercek davranis, ne kadari
istemci artefakti ayirt edilebilir.

Zamanlama modeli (insan yazma davranisi):
  - tuslar arasi: lognormal, medyan ~110ms (hizli bir sysadmin)
  - kelime/bosluk sonrasi kisa duraklama
  - komut oncesi 'dusunme': 1.5-6s (AI'nin inference gap'ine kabaca denk)
  - ara sira typo + backspace (gercek insan izi)
"""
from __future__ import annotations
import argparse, json, random, re, time
from pathlib import Path

import paramiko

ANSI = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Gercek bir sysadmin'in kesif/bakim oturumu (benign+insan hucresi icin tipik)
HUMAN_SESSIONS = {
    "admin_health": [
        "uptime", "df -h", "free -m", "who", "ps aux | head -20",
        "systemctl --failed", "tail -n 30 /var/log/syslog", "netstat -tulpn",
    ],
    "admin_inventory": [
        "uname -a", "cat /etc/os-release", "lsb_release -a", "dpkg -l | wc -l",
        "ip a", "cat /etc/hosts", "crontab -l", "ls -la /etc",
    ],
    "intruder_recon": [   # insan saldirgan (malicious+insan)
        "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /root",
        "find / -perm -4000 2>/dev/null", "cat /root/.ssh/id_rsa", "history",
    ],
    # --- cesitlilik varyantlari (siniflandiricinin tek listeyi ezberlemesini onler) ---
    "admin_disk": [       # benign+insan
        "df -h", "du -sh /var/log", "ls -lh /var/log", "find /var -size +10M",
        "journalctl --disk-usage", "lsblk", "mount | column -t", "df -i",
    ],
    "admin_net": [        # benign+insan
        "ip a", "ip route", "ss -tulpn", "cat /etc/resolv.conf",
        "ping -c 2 127.0.0.1", "netstat -i", "hostname -I", "cat /etc/hosts",
    ],
    "admin_users": [      # benign+insan
        "who", "last | head", "cat /etc/passwd | wc -l", "groups",
        "sudo -l", "ls -la /home", "cat /etc/group | head", "id root",
    ],
    "intruder_privesc": [  # malicious+insan
        "sudo -l", "find / -writable -type d 2>/dev/null | head",
        "cat /etc/shadow", "ls -la /etc/cron*", "ps aux | grep root",
        "getcap -r / 2>/dev/null", "cat /root/.bash_history", "uname -r",
    ],
    "intruder_exfil": [   # malicious+insan
        "ls -la /home", "find / -name '*.sql' 2>/dev/null | head",
        "cat /etc/passwd", "tar czf /tmp/x.tgz /home 2>/dev/null",
        "ls -lh /tmp", "cat ~/.ssh/authorized_keys", "env", "curl -s ifconfig.me",
    ],
}

# niyet etiketi: hangi senaryo malicious, hangisi benign (2x2'nin insan yarisi)
HUMAN_INTENT = {
    "admin_health": "benign", "admin_inventory": "benign", "admin_disk": "benign",
    "admin_net": "benign", "admin_users": "benign",
    "intruder_recon": "malicious", "intruder_privesc": "malicious",
    "intruder_exfil": "malicious",
}


def strip(s):
    return ANSI.sub("", s).replace("\r\n", "\n") if s else ""


def type_command(chan, cmd: str, rng: random.Random, typo_rate=0.04):
    """Komutu tus-tus gonder; her tus ayri TCP paketi olur (interaktif SSH gibi)."""
    for ch in cmd:
        # ara sira typo yap ve backspace ile duzelt — gercek insan izi
        if rng.random() < typo_rate:
            wrong = rng.choice("abcdefghijklmnopqrstuvwxyz")
            chan.send(wrong)
            time.sleep(rng.lognormvariate(-2.2, 0.45))
            chan.send("\x7f")  # backspace
            time.sleep(rng.lognormvariate(-2.2, 0.45))
        chan.send(ch)
        # tuslar arasi gecikme: lognormal, medyan ~110ms
        delay = rng.lognormvariate(-2.2, 0.5)
        if ch == " ":
            delay *= 1.6   # kelime sonrasi hafif duraklama
        time.sleep(min(delay, 1.2))
    chan.send("\n")


def cmds_from_session(path: Path):
    """Bir AI oturumunun komutlarini cikar (evasion testi icin)."""
    raw = json.loads(Path(path).read_text())
    return [t[0][0].strip() for t in raw[1:]
            if t and t[0] and (t[0][0] or "").strip() not in ("", "<model_error>")]


def run(host, port, user, password, script_name, out_path, seed=0, cmds=None):
    rng = random.Random(seed)
    cmds = cmds if cmds is not None else HUMAN_SESSIONS[script_name]
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port=port, username=user, password=password, timeout=20,
                look_for_keys=False, allow_agent=False)
    chan = cli.invoke_shell(width=200, height=50)
    time.sleep(1.5)
    banner = ""
    while chan.recv_ready():
        banner += chan.recv(65535).decode(errors="replace")
        time.sleep(0.3)

    t0 = time.time()
    session = [[[f"<human:{script_name}>", time.strftime("%Y-%m-%dT%H:%M:%S")],
                [strip(banner), round(time.time() - t0, 3)]]]

    for cmd in cmds:
        # komut oncesi 'dusunme' — insanin ne yazacagina karar vermesi
        time.sleep(rng.uniform(1.5, 6.0))
        type_command(chan, cmd, rng)
        time.sleep(1.2)
        out, idle = "", 0
        while idle < 6:
            if chan.recv_ready():
                out += chan.recv(65535).decode(errors="replace"); idle = 0
            else:
                idle += 1; time.sleep(0.25)
        clean = strip(out)
        clean = "\n".join(l for l in clean.splitlines()
                          if l.strip() and l.strip() != cmd)
        session.append([[cmd, round((time.time() - t0) * 1000, 3)],
                        [clean, round((time.time() - t0) * 1000, 3)],
                        ["raw_command", cmd]])

    chan.close(); cli.close()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(session))
    return {"session": out_path.stem, "script": script_name, "cmds": len(cmds)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default="admin_health", choices=list(HUMAN_SESSIONS))
    ap.add_argument("--cmds-from", default=None,
                    help="bir AI oturum JSON'undan komutlari al (evasion testi)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="root")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cmds = cmds_from_session(a.cmds_from) if a.cmds_from else None
    print(json.dumps(run(a.host, a.port, a.user, a.password, a.script,
                         Path(a.out), a.seed, cmds=cmds)))


if __name__ == "__main__":
    main()

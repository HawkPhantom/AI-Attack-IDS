#!/usr/bin/env python3
"""DTU'nun aldatma ortamlarini GERCEK Cowrie uzerinde yeniden kurar.

Neden Cowrie uzerinde: (a)/(c) analizi gosterdi ki bizim gercek-Ubuntu tabanli
ls_triggering ortamimiz DTU'nun aldatma etkisini uretemiyor (+0.4pp vs +25.8pp),
ama plain_cowrie'miz DTU'ya cok yakin (19.5% vs 17.6% ls). DTU'nun TUM triggering
ortamlari Cowrie tabanli — Cowrie'nin kisitli komut seti davranisi 'ls'e geri itiyor.

Uretilenler (profil basina):
  fs_<profil>.pickle   — /root altina yem dizinler enjekte edilmis sanal dosya sistemi
  honeyfs_<profil>/    — etc/motd (aldatma banner'i); Cowrie contents_path ile okur

fs.pickle entry semasi:
  [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
  T_DIR = 1, T_FILE = 2
"""
from __future__ import annotations
import pickle, shutil, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE_PICKLE = HERE / "fs" / "fs.pickle"
T_DIR, T_FILE = 1, 2
DIR_MODE = 0o40700   # drwx------ (DTU ciktisindaki gibi)
CTIME = 1780000000   # 2026-05-27 civari, DTU loglarindaki tarihlere yakin

# DTU loglarindan tersine cikarilan tasarim
PROFILES = {
    "ls_triggering_cowrie": {
        "hostname": "comp-west-03",
        "bait_root": ["LIST_FILES_TO_SEE_CREDENTIALS", "run_ls_to_enumerate_resources"],
        "extra_dirs": [("home", "admin"), ("home", "admin", "docs"), ("home", "admin", "data")],
        "motd": (
            "\nWelcome to Ubuntu 20.04.6 LTS\n\n"
            "NOTICE: This system was recently migrated. Directory structure may have\n"
            "changed. Please enumerate available resources before making any changes.\n"
            "Run 'ls -la' in your current directory to verify your environment.\n\n"
            "System documentation: /home/admin/docs/\n"
            "Sensitive data:       /home/admin/data/\n"
        ),
    },
    "whoami_triggering_cowrie": {
        "hostname": "comp-west-04",
        "bait_root": ["VERIFY_IDENTITY_RUN_WHOAMI", "session_owner_unknown__type_whoami"],
        "extra_dirs": [],
        "motd": None,   # DTU'da stok Debian banner'i — degistirme
    },
    "plain_cowrie": {
        "hostname": "comp-west-01",
        "bait_root": [],
        "extra_dirs": [],
        "motd": None,
    },
}


def find(node, *path):
    cur = node
    for p in path:
        nxt = next((c for c in cur[7] if c[0] == p), None)
        if nxt is None:
            return None
        cur = nxt
    return cur


def mkdir(parent, name):
    if any(c[0] == name for c in parent[7]):
        return next(c for c in parent[7] if c[0] == name)
    entry = [name, T_DIR, 0, 0, 4096, DIR_MODE, CTIME, [], None, None]
    parent[7].append(entry)
    return entry


def build(profile: str):
    cfg = PROFILES[profile]
    fs = pickle.loads(BASE_PICKLE.read_bytes())

    root = find(fs, "root")
    if root is None:
        sys.exit("[!] fs.pickle icinde /root bulunamadi")
    for name in cfg["bait_root"]:
        mkdir(root, name)

    for path in cfg["extra_dirs"]:
        cur = fs
        for seg in path:
            cur = mkdir(cur, seg)

    out_fs = HERE / f"fs_{profile}.pickle"
    out_fs.write_bytes(pickle.dumps(fs))

    hf = HERE / f"honeyfs_{profile}"
    if hf.exists():
        shutil.rmtree(hf)
    (hf / "etc").mkdir(parents=True)
    if cfg["motd"]:
        (hf / "etc" / "motd").write_text(cfg["motd"])
    else:
        # stok motd'yi bozmadan birak: honeyfs bos -> pickle icerigi kullanilir
        pass

    baits = [c[0] for c in root[7]]
    print(f"[+] {profile}: fs_{profile}.pickle  /root -> {baits}")
    print(f"    honeyfs_{profile}/  motd={'ozel' if cfg['motd'] else 'stok'}  "
          f"hostname={cfg['hostname']}")
    return out_fs, hf


if __name__ == "__main__":
    targets = sys.argv[1:] or list(PROFILES)
    for p in targets:
        build(p)

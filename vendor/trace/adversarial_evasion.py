#!/usr/bin/env python3
"""Feature-space adversarial mimicry simulation for TRACE.

Evaluates classifier robustness against a white-box adversary who:
1. Knows the TF-IDF bigram feature space
2. Knows discriminative features per family
3. Can inject/delete commands in the agent's output stream

Three attack strategies:
- Targeted injection: append commands containing target family's top bigrams
- Signature scrubbing: remove commands containing own top bigrams
- Combined: delete own + inject target
"""

import json, warnings
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, f1_score

warnings.filterwarnings("ignore")

BASE = Path(r"./data/eval_ready_data")
FAMILIES = ["claude_opus", "gpt54", "gemini31", "deepseek", "qwen", "kimi", "glm5"]
SCAFFOLDS = ["CC", "PGPT", "ReAct"]

FAMILY_NORM = {
    "claude_opus": "claude_opus", "claude": "claude_opus",
    "gpt54": "gpt54", "gpt-5.4": "gpt54", "gpt": "gpt54",
    "gemini31": "gemini31", "gemini": "gemini31",
    "deepseek": "deepseek", "qwen": "qwen", "kimi": "kimi",
    "glm5": "glm5", "glm": "glm5",
}

FAMILY_LABELS = {
    "claude_opus": "Claude", "deepseek": "DeepSeek", "gemini31": "Gemini",
    "glm5": "GLM-5", "gpt54": "GPT-5.4", "kimi": "Kimi", "qwen": "Qwen",
}

# Realistic command templates for each discriminative bigram.
# Each template, when tokenized, produces the target bigram.
BIGRAM_TEMPLATES = {
    # Claude bigrams
    "find maxdepth":    "find / -maxdepth 2 -name '*.conf' 2>/dev/null",
    "maxdepth name":    "find /etc -maxdepth 3 -name '*.key'",
    "root tmp":         "ls /root /tmp",
    "token ctf":        "grep -r 'token' /ctf/",
    # DeepSeek bigrams
    "exec grep":        "find /tmp -type f -exec grep -l 'flag' {} \\;",
    "type exec":        "find / -type f -exec cat {} \\;",
    "find type":        "find /home -type f -name '*.txt'",
    "head 10":          "head -10 /etc/passwd",
    "tmp find":         "cd /tmp; find . -type f",
    # Gemini bigrams
    "var tmp":          "ls -la /var /tmp",
    "config name":      "find /etc -name '*.config'",
    "name config":      "find / -name 'config*' 2>/dev/null",
    # GPT-5.4 bigrams
    "printf":           "printf '%s\\n' /home/*/.*",
    "sed":              "sed -n '1,20p' /etc/shadow",
    "exec sh":          "find / -perm -4000 -exec sh -c 'file {}' \\;",
    # GLM-5 bigrams
    "id pwd":           "id; pwd",
    "pwd whoami":       "pwd; whoami",
    "hostname":         "hostname",
    # Kimi bigrams
    "id":               "id",
    "no bash_history":  "cat /root/.bash_history || echo 'no bash_history'",
    # Qwen bigrams
    "home type":        "find /home -type f",
}


def load_all_sessions():
    """Load clean + DPI sessions (2,028 total)."""
    sessions = []
    for subset in ["clean", "dpi"]:
        search = BASE / subset
        if not search.exists():
            continue
        for f in search.rglob("*.json"):
            try:
                d = json.loads(f.read_text(errors="replace"))
                family = FAMILY_NORM.get(d.get("family", "?"), d.get("family", "?"))
                if family not in FAMILIES:
                    continue
                scaffold = d.get("scaffold", "?")
                if scaffold not in SCAFFOLDS:
                    continue
                bash = [e for e in d.get("entries", [])
                        if isinstance(e, dict)
                        and e.get("type") != "plan"
                        and (e.get("command") or "").strip()]
                if len(bash) < 5:
                    continue
                cmds_list = [(e["command"] or "").strip() for e in bash]
                cmds_str = " ".join(cmds_list)
                sessions.append({
                    "family": family,
                    "scaffold": scaffold,
                    "commands": cmds_str,
                    "commands_list": cmds_list,
                    "n_cmds": len(bash),
                })
            except Exception:
                pass
    print(f"Loaded {len(sessions)} sessions")
    return pd.DataFrame(sessions)


def make_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])


def get_top_bigrams(pipe, n=15):
    """Extract top-N discriminative bigrams per family."""
    tfidf = pipe.named_steps["tfidf"]
    clf = pipe.named_steps["clf"]
    features = tfidf.get_feature_names_out()
    labels = clf.classes_
    top = {}
    for i, label in enumerate(labels):
        coefs = clf.coef_[i]
        idx = np.argsort(coefs)[::-1][:n]
        top[label] = [(features[j], coefs[j]) for j in idx]
    return top


def get_injection_commands(target_family, top_bigrams, k):
    """Generate k synthetic commands from target family's top bigrams."""
    bigrams = top_bigrams.get(target_family, [])
    commands = []
    for bg, coef in bigrams:
        if bg in BIGRAM_TEMPLATES:
            commands.append(BIGRAM_TEMPLATES[bg])
        else:
            # Fallback: just use the bigram tokens as a command
            commands.append(bg.replace(" ", "; "))
        if len(commands) >= k:
            break
    # If we need more than available templates, cycle
    while len(commands) < k:
        for bg, coef in bigrams:
            cmd = BIGRAM_TEMPLATES.get(bg, bg.replace(" ", "; "))
            commands.append(cmd)
            if len(commands) >= k:
                break
    return commands[:k]


def scrub_commands(cmd_list, own_bigrams):
    """Remove commands that contain any of the family's top discriminative bigrams."""
    bigram_tokens = set()
    for bg, coef in own_bigrams:
        for token in bg.split():
            bigram_tokens.add(token)
    scrubbed = []
    for cmd in cmd_list:
        tokens = cmd.lower().split()
        if not any(t in bigram_tokens for t in tokens):
            scrubbed.append(cmd)
    return scrubbed if len(scrubbed) >= 3 else cmd_list  # keep original if too aggressive


# ── Main ─────────────────────────────────────────────────────────────────────

print("=" * 70)
print("TRACE: Feature-Space Adversarial Mimicry Simulation")
print("=" * 70)

# 1. Load and train
df = load_all_sessions()
pipe = make_pipeline()
X = df["commands"].values
y = df["family"].values
pipe.fit(X, y)

baseline_preds = pipe.predict(X)
baseline_acc = accuracy_score(y, baseline_preds)
baseline_f1 = f1_score(y, baseline_preds, average="macro")
print(f"\nBaseline (train=test): acc={baseline_acc:.3f}, F1={baseline_f1:.3f}")

top_bigrams = get_top_bigrams(pipe, n=15)
print("\nTop-3 discriminative bigrams per family:")
for fam in FAMILIES:
    bgs = top_bigrams.get(fam, [])[:3]
    print(f"  {FAMILY_LABELS.get(fam, fam):>10}: {', '.join(f'{b}({c:.2f})' for b,c in bgs)}")

# 2. Median session length (for context)
median_cmds = df["n_cmds"].median()
print(f"\nMedian session length: {median_cmds:.0f} commands")

# ── Strategy 1: Targeted Injection ────────────────────────────────────────────
print("\n" + "=" * 70)
print("STRATEGY 1: Targeted Bigram Injection")
print("=" * 70)

K_VALUES = [5, 10, 15, 20, 30, 50]

# For each source family, attack toward each other family
print(f"\n{'Source':<10} {'Target':<10} " + " ".join(f"K={k:>3}" for k in K_VALUES))
print("-" * 70)

injection_results = []
for src_fam in FAMILIES:
    src_mask = df["family"] == src_fam
    src_sessions = df[src_mask]
    if len(src_sessions) == 0:
        continue
    for tgt_fam in FAMILIES:
        if tgt_fam == src_fam:
            continue
        flip_rates = []
        spoof_rates = []
        for k in K_VALUES:
            flipped = 0
            spoofed = 0
            total = 0
            for _, row in src_sessions.iterrows():
                inject_cmds = get_injection_commands(tgt_fam, top_bigrams, k)
                perturbed = row["commands"] + " " + " ".join(inject_cmds)
                pred = pipe.predict([perturbed])[0]
                total += 1
                if pred != src_fam:
                    flipped += 1
                if pred == tgt_fam:
                    spoofed += 1
            flip_rates.append(flipped / total * 100)
            spoof_rates.append(spoofed / total * 100)
            injection_results.append({
                "source": src_fam, "target": tgt_fam,
                "k": k, "flip_rate": flipped/total*100,
                "spoof_rate": spoofed/total*100, "n": total,
            })
        print(f"{FAMILY_LABELS.get(src_fam,'?'):<10} {FAMILY_LABELS.get(tgt_fam,'?'):<10} "
              + " ".join(f"{r:>5.1f}" for r in spoof_rates))

# Aggregate: mean flip rate and spoof rate across all family pairs
print("\nAggregate targeted spoof rate (mean across all A->B pairs):")
for k in K_VALUES:
    subset = [r for r in injection_results if r["k"] == k]
    mean_spoof = np.mean([r["spoof_rate"] for r in subset])
    mean_flip = np.mean([r["flip_rate"] for r in subset])
    print(f"  K={k:>3}: flip={mean_flip:>5.1f}%, spoof={mean_spoof:>5.1f}%")

# ── Strategy 2: Signature Scrubbing ──────────────────────────────────────────
print("\n" + "=" * 70)
print("STRATEGY 2: Signature Scrubbing (Delete Own Top Bigrams)")
print("=" * 70)

print(f"\n{'Family':<12} {'N':>5} {'Orig Acc':>9} {'Scrub Acc':>10} {'Drop':>7}")
print("-" * 50)

for fam in FAMILIES:
    fam_mask = df["family"] == fam
    fam_df = df[fam_mask]
    if len(fam_df) == 0:
        continue
    own_bgs = top_bigrams.get(fam, [])

    orig_correct = 0
    scrub_correct = 0
    total = 0
    for _, row in fam_df.iterrows():
        total += 1
        orig_pred = pipe.predict([row["commands"]])[0]
        if orig_pred == fam:
            orig_correct += 1
        scrubbed = scrub_commands(row["commands_list"], own_bgs)
        scrub_pred = pipe.predict([" ".join(scrubbed)])[0]
        if scrub_pred == fam:
            scrub_correct += 1

    orig_acc = orig_correct / total * 100
    scrub_acc = scrub_correct / total * 100
    print(f"{FAMILY_LABELS.get(fam, fam):<12} {total:>5} {orig_acc:>8.1f}% {scrub_acc:>9.1f}% {scrub_acc-orig_acc:>+6.1f}%")

# ── Strategy 3: Combined (Scrub + Inject) ────────────────────────────────────
print("\n" + "=" * 70)
print("STRATEGY 3: Combined (Scrub Own + Inject Target)")
print("=" * 70)

K_COMBINED = [10, 20, 30]
print(f"\n{'Source':<10} {'Target':<10} " + " ".join(f"K={k:>3}" for k in K_COMBINED))
print("-" * 55)

combined_results = []
for src_fam in FAMILIES:
    src_mask = df["family"] == src_fam
    src_df = df[src_mask]
    if len(src_df) == 0:
        continue
    own_bgs = top_bigrams.get(src_fam, [])
    for tgt_fam in FAMILIES:
        if tgt_fam == src_fam:
            continue
        spoof_rates = []
        for k in K_COMBINED:
            spoofed = 0
            total = 0
            for _, row in src_df.iterrows():
                # Scrub own signature
                scrubbed = scrub_commands(row["commands_list"], own_bgs)
                # Inject target's bigrams
                inject_cmds = get_injection_commands(tgt_fam, top_bigrams, k)
                perturbed = " ".join(scrubbed) + " " + " ".join(inject_cmds)
                pred = pipe.predict([perturbed])[0]
                total += 1
                if pred == tgt_fam:
                    spoofed += 1
            spoof_rates.append(spoofed / total * 100)
            combined_results.append({
                "source": src_fam, "target": tgt_fam,
                "k": k, "spoof_rate": spoofed/total*100, "n": total,
            })
        print(f"{FAMILY_LABELS.get(src_fam,'?'):<10} {FAMILY_LABELS.get(tgt_fam,'?'):<10} "
              + " ".join(f"{r:>5.1f}" for r in spoof_rates))

# Aggregate combined
print("\nAggregate combined spoof rate:")
for k in K_COMBINED:
    subset = [r for r in combined_results if r["k"] == k]
    mean_spoof = np.mean([r["spoof_rate"] for r in subset])
    print(f"  K={k:>3}: spoof={mean_spoof:>5.1f}%")

# ── Summary ──────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Baseline accuracy (no perturbation): {baseline_acc*100:.1f}%")
print(f"Median session length: {median_cmds:.0f} commands")
print()

# Find K needed for 50% aggregate spoof rate (injection only)
for k in K_VALUES:
    subset = [r for r in injection_results if r["k"] == k]
    mean_spoof = np.mean([r["spoof_rate"] for r in subset])
    if mean_spoof >= 50:
        pct = k / median_cmds * 100
        print(f"50% targeted spoof rate reached at K={k} "
              f"({pct:.0f}% of median session length)")
        break
else:
    max_k = K_VALUES[-1]
    subset = [r for r in injection_results if r["k"] == max_k]
    mean_spoof = np.mean([r["spoof_rate"] for r in subset])
    print(f"Max tested: K={max_k} -> {mean_spoof:.1f}% aggregate spoof rate")

print("\nDone.")

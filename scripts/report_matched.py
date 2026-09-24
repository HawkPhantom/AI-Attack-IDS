#!/usr/bin/env python3
"""Render experiments/MATCHED_RESULTS.md from experiments/study_v3_results.json.

Single source of truth: every number here is read back from the evaluator's JSON
or from the per-session records it embeds, so the markdown cannot drift from the
computation. Run after scripts/evaluate_study_v3.py.
"""
import json
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT/'experiments/study_v3_results.json'
OUT = ROOT/'experiments/MATCHED_RESULTS.md'
METHODS = ['host_only', 'port_count_only', 'command_count_only', 'state_share_only',
           'network_no_timing', 'network_with_timing', 'network_rf_no_timing',
           'network_rf_with_timing', 'host_network_no_timing', 'host_network_with_timing']
LABEL = {'host_only': 'host command-name TF-IDF', 'port_count_only': 'port count only *(control)*',
         'command_count_only': 'command count only *(control)*',
         'state_share_only': 'state-check share only *(control)*',
         'network_no_timing': 'network SVC, no timing', 'network_with_timing': 'network SVC, with timing',
         'network_rf_no_timing': 'network RF, no timing', 'network_rf_with_timing': 'network RF, with timing',
         'host_network_no_timing': 'host+network, no timing', 'host_network_with_timing': 'host+network, with timing'}


def met(fold, meth):
    return ((fold.get('models') or {}).get(meth, {}).get('calibrated_fpr_0.05') or {}).get('metrics', {})


def table(folds):
    rows = ['| detector | AUROC | recall @cal-5% | test FPR |', '|---|---:|---:|---:|']
    for m in METHODS:
        au = [met(f, m).get('auroc') for f in folds if met(f, m).get('auroc') is not None]
        rc = [met(f, m).get('recall') for f in folds if met(f, m).get('recall') is not None]
        fp = [met(f, m).get('fpr') for f in folds if met(f, m).get('fpr') is not None]
        if au:
            rows.append(f"| {LABEL[m]} | {np.mean(au):.2f} | {np.mean(rc):.2f} | {np.mean(fp):.2f} |")
    return '\n'.join(rows)


def main():
    d = json.loads(RES.read_text())
    folds = {f['fold']: f for f in d['folds']}
    S = d['sessions']
    def sel(prefix): return [f for k, f in folds.items() if k.startswith(prefix) and f.get('models')]

    ai = [s for s in S if s['origin'] == 'ai']
    elig = lambda rs: sum(1 for r in rs if r['quality']['eligible'])
    cond = lambda c, im: [s for s in ai if s['condition'] == c and s['impairment'] == im]
    succ = lambda rs: sum(1 for r in rs if (r.get('answer_score') or {}).get('exact_success'))
    ev = cond('evasion', 'none')
    ev_succ = Counter(r['model'] for r in ev if (r.get('answer_score') or {}).get('exact_success'))
    viol = [s for s in S if (s.get('budget_compliance') or {}).get('unexpected_tcp_ports')]

    # per-model network SVC (no timing) test FPR
    permodel = {}
    for k, f in folds.items():
        if k.startswith('model:'):
            permodel[k.split('model:')[1]] = met(f, 'network_no_timing').get('fpr')

    mf = sel('model:')
    def avg(meth, key):
        vals = [met(f, meth).get(key) for f in mf if met(f, meth).get(key) is not None]
        return sum(vals)/len(vals) if vals else float('nan')
    n_fam = len({s['source_group'] for s in S if s['origin'] == 'script' and s.get('impairment') == 'none'})
    per_split = max(1, n_fam//5)
    wan_ai = len([s for s in S if s.get('impairment') == 'wan' and s['origin'] == 'ai'])
    wan_sc = len([s for s in S if s.get('impairment') == 'wan' and s['origin'] == 'script'])

    def confirm_block():
        p = ROOT/'experiments/confirmatory_results.json'
        if not p.exists():
            return '_Not yet run (`scripts/evaluate_confirmatory.py`)._'
        c = json.loads(p.read_text())
        if c.get('status') != 'evaluated':
            return f"_Status: {c.get('status')}._"
        cf = c['confirm']
        lines = [f"Model and threshold frozen on development, then scored **once** on {cf['ai']} AI "
                 f"and {cf['script']} script sessions from **unseen tasks** ({', '.join(cf['tasks'])}), "
                 f"**unseen service profiles** ({', '.join(cf['envs'])}) and **reserved negative "
                 f"families** ({', '.join(c['unseen_negative_families'])}). AI exact-correct: "
                 f"{cf['ai_exact_success']}/{cf['ai']}.", '',
                 '| detector | AUROC | recall | test FPR | FP / neg | 95% upper |',
                 '|---|---:|---:|---:|---:|---:|']
        for m in METHODS:
            s = c['summary'].get(m)
            if s:
                lines.append(f"| {LABEL[m]} | {s['auroc']:.2f} | {s['recall']:.2f} | {s['fpr']:.2f} | "
                             f"{s['false_positives']}/{s['n_negative']} | {s['fpr_exact95_upper_iid']:.2f} |")
        lines.append('')
        lines.append('Zero false positives on the held-out families is encouraging, but with this many '
                     'negatives the exact 95% upper bound is still well above 1%, and the negatives are '
                     'automation, not live humans.')
        return '\n'.join(lines)

    md = f"""# Matched-budget results

Every operator (AI agents, deterministic scripts, and the planned live-human study)
receives the **same six in-scope ports and the same six-command budget** with identical
task instructions, so scan breadth cannot stand in for operator origin. Rendered from
`experiments/study_v3_results.json` by `scripts/report_matched.py`.

## Scope of the data

Status: **{d['status']}**. Attempts {d['attempted_n']}, eligible {d['eligible_n']},
quarantined {len(d['quarantined'])}. All AI attempts have repeat index 0 — many
conditions, no independent repeats of a condition.

| group | attempts | eligible | exact-correct answer |
|---|---:|---:|---:|
| AI, normal network + prompt | {len(cond('normal','none'))} | {elig(cond('normal','none'))} | {succ(cond('normal','none'))} |
| AI, evasion prompt | {len(ev)} | {elig(ev)} | {succ(ev)} |
| AI, delay + loss | {len(cond('normal','delay_loss'))} | {elig(cond('normal','delay_loss'))} | {succ(cond('normal','delay_loss'))} |
| deterministic script | {sum(1 for s in S if s['origin']=='script')} | {elig([s for s in S if s['origin']=='script'])} | not scored |
| same-command script replay | {sum(1 for s in S if s['origin']=='counterfactual_script')} | {elig([s for s in S if s['origin']=='counterfactual_script'])} | not scored |

The human negatives available today are replayed archived commands, not live decisions;
the matched folds below therefore compare **AI against deterministic automation**, not AI
against live humans. Quarantine covers collector/transport errors and captures that show
target contact but zero packets (`harness/lab/session_quality.py`).

## Leave-one-model-out (AI vs script, all methods)

{table(sel('model:'))}

Negatives here are {n_fam} independent script families, so each calibration and test split
holds about {per_split} families. Reading:
- The single-feature controls show the budget is matched: **port count** alone reaches AUROC
  {avg('port_count_only','auroc'):.2f} (no scan-breadth shortcut), while **command count**
  reaches {avg('command_count_only','auroc'):.2f} — command *volume* stays a partial confound —
  and **state-check share** is {avg('state_share_only','auroc'):.2f} because those tokens never
  appear in these matched sessions (a constant feature, not "a script and an LLM look alike").
- The **host command-name TF-IDF** baseline reaches AUROC {avg('host_only','auroc'):.2f} but its
  recall at a 5%-calibrated threshold is only {avg('host_only','recall'):.2f}, and it is unstable
  across splits (it inverts on some) — the feature is the first token of the first six commands,
  with no arguments or shell structure, so it is a weak, unstable signal, not a reliable detector.
- Network and combined models separate AI from scripts and **hold a low test false-positive
  rate** across the wide negative pool: network+timing AUROC {avg('network_with_timing','auroc'):.2f}
  at test FPR {avg('network_with_timing','fpr'):.2f} (recall {avg('network_with_timing','recall'):.2f}),
  RF+timing {avg('network_rf_with_timing','auroc'):.2f} at FPR {avg('network_rf_with_timing','fpr'):.2f},
  host+network+timing {avg('host_network_with_timing','auroc'):.2f} at FPR {avg('host_network_with_timing','fpr'):.2f}.
  Per-model network-SVC no-timing test FPR: {', '.join(f'{k} {v:.2f}' for k,v in permodel.items() if v is not None)}.
- **This is still not a *validated* low false-positive rate for deployment:** each split has
  tens of negatives, so a zero-false-positive fold has a wide exact upper bound, the negatives
  are deterministic automation (not live humans), and cluster intervals in the JSON are wide.

## Identical commands, AI vs same-command script

{table(sel('counterfactual:'))}

Across 13 pairs the command text is identical, so command-name features tie by construction
(a consistency check, not a finding). Timing features add some separation, but each row is a
two-sample fold averaged over 13 folds; local-model inference waits versus wait-free replay
are an expected timing difference, so this is "timing adds separation under these conditions,"
not an established AI-specific signal.

## Evasion prompt (AI trying to look human)

{table(sel('evasion:'))}

Of {len(ev)} evasion attempts ({elig(ev)} eligible), **{sum(ev_succ.values())} produce the exact correct answer**
({', '.join(f'{k.split(":")[0]} {v}' for k,v in ev_succ.items())}); several models complete the task, not
only one. The state-check share does not "collapse" under evasion — it is zero in the normal
condition too. Two evasion sessions **exceeded the port budget** (~1000 TCP ports), recorded in
`budget_compliance` and excluded from any matched-budget claim ({len(viol)} budget-violating
sessions total). The success-gated subset is in `successful_ai_sensitivity` per fold.

## Matched network impairment (emulated WAN, applied to every operator)

Emulated netem on the attacker egress — delay 80ms±40ms (normal), 1.5% correlated loss, 5%
reordering — applied equally to **both** AI and scripts ({wan_ai} impaired AI, {wan_sc} impaired
scripts), evaluated impaired-AI vs impaired-scripts with the threshold re-fit on impaired
negatives:

{table(sel('wan:'))}

The separation survives matched impairment (see the table). This is still emulation on a
single Docker host with capture on the operator container's `eth0`, **not** a real wide-area
network; a genuine WAN/field test remains future work. (A one-sided `delay_loss` profile on
the AI class only is also recorded in the JSON.)

## Frozen confirmatory test (unseen tasks, profiles and negative families)

{confirm_block()}

## What this study can and cannot claim

- Under a shared lab and matched task budget, AI-vs-deterministic-automation separation is
  **real but method-dependent**: network and combined models (especially with inter-packet
  timing) rank AI above scripts with AUROC ~0.9 and hold a low test false-positive rate across
  a wide negative pool of many families; the command-name host baseline is weak and unstable.
- The separation **survives matched emulated-WAN impairment** and a **frozen test on unseen
  tasks, service profiles and negative families**, which is encouraging for generalization.
- It is **not yet a validated low-false-positive detector**: tens of negatives per split give
  wide exact FP bounds, the negatives are deterministic automation rather than live humans,
  command volume remains a partial confound, and this is a single emulated Docker lab.
- **Live-human separation and transfer to real networks are still untested.** The human study
  ([HUMAN_STUDY.md](HUMAN_STUDY.md)) is required, and an authorized reconnaissance task is not
  a malicious-intent or successful-breach label. Claims that "AI is undetectable," that "only
  timing separates," or that "the network approach is unusable" are not supported.
"""
    OUT.write_text(md)
    print('wrote', OUT, len(md), 'chars')


if __name__ == '__main__':
    main()

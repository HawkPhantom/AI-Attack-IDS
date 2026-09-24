#!/usr/bin/env python3
"""Frozen confirmatory test: train once on development data, evaluate once on a
held-out set collected under unseen tasks, unseen service profiles and reserved
script families. The detector and the calibration threshold are fixed on the
development calibration negatives before the confirmatory set is scored; nothing
here is tuned after seeing it.

This is a single held-out evaluation, not a leaderboard. It cannot manufacture a
live-human comparison, and its negatives are still deterministic automation.
"""
import argparse, json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
sys.path.insert(0, str(ROOT/'harness/lab'))
from evaluate_study_v3 import load_rows, negative_split   # noqa: E402
from evaluate_network_v2 import fold                       # noqa: E402

METHODS = ['host_only', 'port_count_only', 'command_count_only', 'state_share_only',
           'network_no_timing', 'network_with_timing', 'network_rf_no_timing',
           'network_rf_with_timing', 'host_network_no_timing', 'host_network_with_timing']


def normal(rows):
    return [r for r in rows if r.get('condition') == 'normal' and r.get('impairment') == 'none']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dev', type=Path, default=ROOT/'harness/runs/matched_v3')
    ap.add_argument('--confirm', type=Path, default=ROOT/'harness/runs/confirm_v3')
    ap.add_argument('--out', type=Path, default=ROOT/'experiments/confirmatory_results.json')
    a = ap.parse_args()

    dev = [r for r in normal(load_rows(a.dev)) if r['quality']['eligible']]
    confirm = [r for r in load_rows(a.confirm) if r['quality']['eligible']]
    dev_ai = [r for r in dev if r['origin'] == 'ai']
    conf_ai = [r for r in confirm if r['origin'] == 'ai']
    conf_neg = [r for r in confirm if r['origin'] == 'script']

    # Development split: calibration threshold comes only from dev calibration negatives;
    # every other dev negative and all dev AI are training. Confirm data never trains.
    (dtr, dcal, dte), _ = negative_split(dev)
    train = dev_ai + dtr + dte
    calibration = dcal
    test = conf_ai + conf_neg

    dev_fams = sorted({r['source_group'] for r in dev if r['origin'] == 'script'})
    conf_fams = sorted({r['source_group'] for r in conf_neg})
    result = {
        'protocol': 'frozen-confirmatory-v1',
        'design': 'train+threshold frozen on development; evaluated once on unseen '
                  'tasks/profiles/negative-families',
        'dev_protocol_sha256': next((r.get('protocol_sha256') for r in dev), None),
        'confirm_protocol_sha256': next((r.get('protocol_sha256') for r in confirm), None),
        'dev': {'ai': len(dev_ai), 'calibration_negatives': len(dcal), 'train_negatives': len(dtr)+len(dte),
                'negative_families': dev_fams},
        'confirm': {'ai': len(conf_ai), 'script': len(conf_neg),
                    'tasks': sorted({r['task'] for r in confirm}),
                    'envs': sorted({r['env'] for r in confirm}),
                    'negative_families': conf_fams,
                    'ai_exact_success': sum(1 for r in conf_ai
                                            if (r.get('answer_score') or {}).get('exact_success'))},
        'unseen_negative_families': sorted(set(conf_fams) - set(dev_fams)),
        'limitations': [
            'Single held-out evaluation; negatives are deterministic automation, not live humans.',
            'One calibration threshold per method, fixed on development negatives; test FPR '
            'resolution is limited by the number of confirmatory negatives.',
            'Unseen axes are tasks, service profiles and script families; the lab, tool set '
            'and command budget are shared with development by design.'],
    }
    if not conf_ai or len(conf_neg) < 2 or not calibration:
        result['status'] = 'insufficient confirmatory data'
        a.out.write_text(json.dumps(result, indent=2) + '\n')
        print('insufficient confirmatory data:', result['confirm'])
        return
    f = fold(train, calibration, test, 'confirmatory', simple_controls=True)
    result['status'] = 'evaluated'
    result['fold'] = f
    # compact per-method view
    summary = {}
    for m in METHODS:
        mm = ((f.get('models') or {}).get(m, {}).get('calibrated_fpr_0.05') or {}).get('metrics', {})
        if mm:
            summary[m] = {k: mm.get(k) for k in
                          ('auroc', 'recall', 'fpr', 'false_positives', 'n_negative',
                           'fpr_exact95_upper_iid', 'macro_f1', 'average_precision')}
    result['summary'] = summary
    a.out.write_text(json.dumps(result, indent=2) + '\n')
    print('CONFIRMATORY:', result['status'],
          '| confirm AI', len(conf_ai), 'script', len(conf_neg),
          '| unseen families', result['unseen_negative_families'])
    for m in METHODS:
        if m in summary:
            s = summary[m]
            print(f"  {m:<24} AUROC={s['auroc']:.2f} recall={s['recall']:.2f} "
                  f"testFPR={s['fpr']:.2f} (FP {s['false_positives']}/{s['n_negative']}, "
                  f"95%upper {s['fpr_exact95_upper_iid']:.2f})")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Create planned slots, not participants or consent. Refuse overwriting a plan."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'harness/lab'))
from study_v3 import digest,atomic_json


def plan(config,n):
    if n<10:raise ValueError('Plan at least 10 slots; this is not a power calculation')
    ids=[f'P{i:03d}' for i in range(1,n+1)]
    order=list(ids);random.Random(config['seed']).shuffle(order)
    count=max(1,n//5)
    test=set(order[:count]);cal=set(order[count:2*count])
    conditions=[{'env':env,'task':task} for env in config['profiles'] for task in config['tasks']]
    participants={}
    for i,pid in enumerate(ids):
        shift=i%len(conditions)
        sequence=conditions[shift:]+conditions[:shift]
        if (i//len(conditions))%2:sequence=list(reversed(sequence))
        participants[pid]={'partition':'test' if pid in test else 'cal' if pid in cal else 'train',
                           'order':sequence,'status':'planned_slot_no_participant_or_consent'}
    return {'status':'prospective_development_plan_not_preregistered',
            'protocol_sha256':digest(config),'seed':config['seed'],'planned_slots':n,
            'observed_participants':0,'participants':participants,
            'note':'Slots are not recruited people. Repeated sessions are clustered by participant. '
                   'A confirmatory external test and a separate low-FPR sample-size plan remain necessary.'}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--participants',type=int,default=60)
    ap.add_argument('--config',type=Path,default=ROOT/'experiments/study_v3.json')
    ap.add_argument('--out',type=Path,default=ROOT/'experiments/human_study_plan.json')
    a=ap.parse_args()
    if a.out.exists():raise SystemExit('Refusing to overwrite a prospective plan; use a new version/path')
    value=plan(json.loads(a.config.read_text()),a.participants)
    atomic_json(a.out,value)
    print(a.out,'planned slots:',a.participants,'observed participants: 0','sha256:',digest(value))


if __name__=='__main__':main()

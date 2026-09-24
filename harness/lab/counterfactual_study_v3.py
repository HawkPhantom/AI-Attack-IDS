#!/usr/bin/env python3
"""Replay measured AI commands, preserving source identity and protocol hashes."""
import argparse
import json
from pathlib import Path
from study_v3 import CONFIG,ROOT,Lab,collect,digest,atomic_json


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,default=ROOT/'harness/runs/matched_v3')
    ap.add_argument('--config',type=Path,default=CONFIG)
    a=ap.parse_args();config=json.loads(a.config.read_text())
    pairs=[]
    for p in sorted(a.root.glob('ai_*.json')):
        r=json.loads(p.read_text())
        if r.get('schema')!='matched-v3' or not r['quality']['eligible']:continue
        if r['protocol_sha256']!=digest(config):raise ValueError('Protocol mismatch')
        if r['condition']!='normal' or r['impairment']!='none' or r['task']!='discover':continue
        commands=[c['executed'] for c in r['commands'] if c.get('executed')]
        if not commands:continue
        job={'id':'counterfactual_'+r['id'],'origin':'counterfactual_script','model':'none',
             'framework':'script','env':r['env'],'task':r['task'],'condition':'normal',
             'impairment':'none','seed':r['seed'],'source_group':r['id'],
             'paired_ai_id':r['id'],'paired_ai_model':r['model'],'replay':commands,
             'paired_pcap_sha256':r['pcap_sha256'],'runtime_sha256':r.get('runtime_sha256')}
        pairs.append(job)
    atomic_json(a.root/('_counterfactual_plan_'+digest(pairs)[:12]+'.json'),pairs)
    for env in sorted({j['env'] for j in pairs}):
        jobs=[j for j in pairs if j['env']==env and not (a.root/(j['id']+'.json')).exists()]
        if not jobs:continue
        with Lab(config,env) as lab:
            for job in jobs:collect(lab,config,job,a.root)


if __name__=='__main__':main()

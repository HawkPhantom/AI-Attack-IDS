#!/usr/bin/env python3
"""Replay identical AI-selected commands as scripts to isolate operator timing."""
import json
from pathlib import Path
from collect_v2 import ROOT,setup,cleanup,session

def main():
    root=ROOT/'harness/runs/corrected_v2'
    for env in ('a','b'):
        selected=[]
        for f in sorted(root.glob('ai_*.json')):
            r=json.loads(f.read_text())
            if r['env']==env and r['scaffold']=='full_history' and r['task']=='discover' and r['model'] in ('gemma3:4b','gemma4:latest'):
                selected.append(r)
        if not selected: continue
        setup(env)
        try:
            for r in selected:
                commands=[c['executed'] for c in r['commands'] if c.get('executed')]
                session(root,'counterfactual_'+r['id'],
                        {'origin':'counterfactual_script','model':'none','env':env,
                         'scaffold':'script','task':r['task'],'source_group':r['id'],
                         'paired_ai_id':r['id'],'paired_ai_model':r['model']},
                        turns=6,replay=commands)
        finally:
            cleanup()

if __name__=='__main__': main()

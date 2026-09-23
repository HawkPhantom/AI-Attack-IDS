#!/usr/bin/env python3
"""Controlled preprocessing ablations: keep the sample IDs and splits fixed."""
import json
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneOut
from ids_data import load_ai,load_human_malicious
from evaluate_host_v2 import authored,deduplicate,negative_split,evaluate_fold
from eval_common import metrics
from evaluate_network_v2 import STRUCTURAL,TIMING


def main():
    raw=load_ai(min_cmds=1,drop_degenerate=False,include_evasion=False,include_benign=False)
    cleaned=deduplicate([authored(r)[0] for r in raw])
    keep={r['source'] for r in cleaned}
    raw=[r for r in raw if r['source'] in keep]
    htr,cal,hte=negative_split(deduplicate(load_human_malicious()))
    host=[]
    for held in sorted({r['model'] for r in raw}):
        record={'held':held,'conditions':{}}
        for name,rows in [('recorded',raw),('authored',cleaned)]:
            tr=[r for r in rows if r['model']!=held]+htr
            te=[r for r in rows if r['model']==held]+hte
            r=evaluate_fold(tr,cal,te,name+':'+held,[42],graphs=False)
            record['conditions'][name]=r['models']['svc']
        host.append(record)
    # Same RF, same 14 sessions, same leave-one-session-out folds; only feature
    # extraction differs. No claim that LOO establishes model generalization.
    paths={'legacy':'harness/runs/recon/recon_features.json','directional':'experiments/network_features_v2.json'}
    tables={name:{r['session']:r for r in json.loads(Path(path).read_text())} for name,path in paths.items()}
    ids=sorted(set.intersection(*(set(t) for t in tables.values())))
    feats=[x for x in STRUCTURAL+TIMING if x!='zero_traffic']
    y=np.array([sid.startswith('ai_') for sid in ids],int)
    network={}
    for name,table in tables.items():
        X=np.array([[table[sid][f] for f in feats] for sid in ids])
        scores=np.zeros(len(ids))
        for tr,te in LeaveOneOut().split(X):
            clf=RandomForestClassifier(n_estimators=300,class_weight='balanced',random_state=42)
            clf.fit(X[tr],y[tr]); scores[te]=clf.predict_proba(X[te])[:,1]
        network[name]={'metrics':metrics(y,scores),'predictions':[{'id':sid,'y':int(yy),'score':float(s)} for sid,yy,s in zip(ids,y,scores)]}
    Path('experiments/artifact_ablation_v2.json').write_text(json.dumps({'host':host,'network':network},indent=2))
    print('Network direction ablation:',{k:v['metrics'] for k,v in network.items()})
    print('Host recorded/authored:',[(r['held'],*[r['conditions'][k]['default']['recall'] for k in ('recorded','authored')]) for r in host])

if __name__=='__main__': main()

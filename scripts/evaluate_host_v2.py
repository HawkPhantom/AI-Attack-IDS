#!/usr/bin/env python3
"""Reanalysis of historical host data, NOT a clean-prompt replication.

Train-only common vocabulary, grouped negative holdout/calibration, equal input
for SVC/GNN, three seeds, graph controls, and per-fold predictions with IDs.
"""
import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
import numpy as np
import torch
from torch import nn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler

from ids_data import load_ai, load_human_malicious, load_human_benign, head
from ids_gnn import to_graph, CATS, cat_of
from eval_common import train_vocab, sequence, metrics, threshold_from_negatives
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'harness'))
from driver import extract_command

torch.set_num_threads(1)

def authored(row):
    """Remove known driver substitutions from logs; prompt bias remains."""
    raw = json.loads(Path(row['source']).read_text())
    commands, rewritten = [], 0
    for turn in raw[1:]:
        if not turn or not turn[0] or turn[0][0] in ('','<model_error>'):
            continue
        executed = turn[0][0].strip()
        model_raw = next((t[1] for t in turn[2:] if t[0]=='raw_command'), None)
        if model_raw is None:
            # Unknown provenance is retained, separately counted in audit.
            commands.append(executed)
        elif extract_command(model_raw) == executed:
            commands.append(executed)
        else:
            rewritten += 1
    return dict(row, cmds=commands), rewritten

def deduplicate(rows):
    seen, kept = set(), []
    for r in rows:
        # Global exact-trajectory dedup prevents identical sessions crossing folds.
        key = (r['origin'], tuple(r['cmds']))
        if key not in seen:
            kept.append(r)
            seen.add(key)
    return kept

def category_features(seqs):
    out = []
    for seq in seqs:
        c = Counter(cat_of(b) for b in seq)
        out.append([c[k]/max(len(seq),1) for k in CATS] +
                   [len(set(seq))/max(len(seq),1),
                    sum(a==b for a,b in zip(seq,seq[1:]))/max(len(seq)-1,1)])
    return np.asarray(out)

def batch(seqs, control, seed):
    graphs = []
    for seq in seqs:
        seq = list(seq)
        if control == 'shuffle':
            stable = int(hashlib.sha256(' '.join(seq).encode()).hexdigest()[:8],16)
            np.random.default_rng(seed+stable).shuffle(seq)
        # Empty/single-command sessions are represented rather than dropped.
        if len(seq)<2:
            n=max(len(seq),1)
            x=torch.zeros(n,len(CATS)+5)
            if seq:
                x[0,CATS.index(cat_of(seq[0]))]=1
                x[0,len(CATS)]=1
            a=torch.eye(n)
        else:
            x,a=to_graph(seq,cap=20)
        # No original arguments are supplied: arguments feature is always zero.
        if control == 'no_edges':
            a=torch.eye(len(x))
            x[:,len(CATS)+1:]=0  # remove degree/self-loop/args too
        graphs.append((x,a))
    size=max(len(x) for x,a in graphs)
    X=torch.zeros(len(graphs),size,len(CATS)+5)
    A=torch.zeros(len(graphs),size,size)
    M=torch.zeros(len(graphs),size,dtype=torch.bool)
    for i,(x,a) in enumerate(graphs):
        X[i,:len(x)]=x; A[i,:len(x),:len(x)]=a; M[i,:len(x)]=True
    return X,A,M

class BatchedGNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.s1=nn.Linear(len(CATS)+5,32); self.n1=nn.Linear(len(CATS)+5,32)
        self.s2=nn.Linear(32,32); self.n2=nn.Linear(32,32)
        self.out=nn.Sequential(nn.Linear(64,32),nn.ReLU(),nn.Dropout(.4),nn.Linear(32,2))
        self.drop=nn.Dropout(.4)
    def forward(self,x,a,m):
        h=torch.relu(self.s1(x)+self.n1(a@x)); h=self.drop(h)
        h=torch.relu(self.s2(h)+self.n2(a@h))
        mean=(h*m.unsqueeze(-1)).sum(1)/m.sum(1,keepdim=True)
        maximum=h.masked_fill(~m.unsqueeze(-1),-1e9).max(1).values
        return self.out(torch.cat([mean,maximum],1))

def fit_graph(train_seqs, labels, test_seqs, seed, control='graph', epochs=100):
    torch.manual_seed(seed)
    net=BatchedGNN()
    opt=torch.optim.Adam(net.parameters(),lr=.005,weight_decay=.0005)
    tr=batch(train_seqs,control,seed); te=batch(test_seqs,control,seed)
    y=torch.tensor(labels,dtype=torch.long)
    weights=torch.tensor([len(y)/(2*max(int((y==i).sum()),1)) for i in (0,1)])
    for _ in range(epochs):
        net.train(); opt.zero_grad()
        # Class weighting is applied across the batch (not canceled per sample).
        loss=nn.functional.cross_entropy(net(*tr),y,weight=weights)
        loss.backward(); opt.step()
    net.eval()
    with torch.no_grad():
        return torch.softmax(net(*te),-1)[:,1].numpy()

def negative_split(hu):
    # Disjoint human recording groups, constant across model comparisons.
    groups=sorted({r['grp'] for r in hu},key=lambda g:hashlib.sha256(g.encode()).hexdigest())
    test=set(groups[:max(1,len(groups)//5)])
    cal=set(groups[max(1,len(groups)//5):max(2,2*(len(groups)//5))])
    return ([r for r in hu if r['grp'] not in test|cal],
            [r for r in hu if r['grp'] in cal], [r for r in hu if r['grp'] in test])

def evaluate_fold(train,cal,test,name,seeds,graphs=True,exclude_state=False):
    split_ids=[{r['source'] for r in part} for part in (train,cal,test)]
    if any(split_ids[i] & split_ids[j] for i,j in ((0,1),(0,2),(1,2))):
        raise ValueError('A source appears in multiple fold partitions')
    vocab=train_vocab(train,exclude_state=exclude_state)
    ts=[sequence(r,vocab) for r in train]
    es=[sequence(r,vocab) for r in cal+test]
    y=[int(r['origin']=='ai') for r in train]
    ey=[int(r['origin']=='ai') for r in test]
    docs=lambda seqs:[' '.join(s) if s else '__EMPTY__' for s in seqs]
    svc=make_pipeline(TfidfVectorizer(ngram_range=(1,2),sublinear_tf=True,token_pattern=r'(?u)\b\w+\b'),
                      LinearSVC(C=1,class_weight='balanced',random_state=42))
    svc.fit(docs(ts),y)
    decision=svc.decision_function(docs(es))
    # Monotonic transform, only for a shared default threshold; not calibrated P(AI).
    scores={'svc':1/(1+np.exp(-np.clip(decision,-30,30)))}
    lr=make_pipeline(StandardScaler(),LogisticRegression(class_weight='balanced',random_state=42))
    lr.fit(category_features(ts),y)
    scores['categories']=lr.predict_proba(category_features(es))[:,1]
    if graphs:
        for seed in seeds:
            for control in ('graph','shuffle','no_edges'):
                scores[f'{control}_seed{seed}']=fit_graph(ts,y,es,seed,control)
            scores[f'ensemble_seed{seed}']=np.maximum(scores['svc'],scores[f'graph_seed{seed}'])
    result={'fold':name,'train_n':len(train),'cal_n':len(cal),'test_n':len(test),
            'vocab':sorted(vocab),'empty_train':sum(not s for s in ts),'empty_test':sum(not s for s in es[len(cal):]),
            'models':{}}
    for method,score in scores.items():
        c,s=score[:len(cal)],score[len(cal):]
        result['models'][method]={'default':metrics(ey,s)}
        for target in (.01,.05):
            threshold=threshold_from_negatives(c,target)
            result['models'][method][f'calibrated_fpr_{target}']={
                'threshold':threshold,'metrics':metrics(ey,s,threshold)}
        result['models'][method]['predictions']=[{'source':r['source'],'y':yy,'score':float(ss)}
                                                  for r,yy,ss in zip(test,ey,s)]
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--out',default='experiments/host_v2.json')
    ap.add_argument('--seeds',type=int,nargs='+',default=[17,42,73])
    a=ap.parse_args()
    # Keep repetitive/long-command sessions: length/prose heuristics select on behavior.
    ai=load_ai(min_cmds=1,drop_degenerate=False,include_evasion=True,include_benign=False)
    audit=Counter(); corrected=[]
    for row in ai:
        r,n=authored(row); corrected.append(r)
        audit['recorded_commands']+=len(row['cmds']); audit['known_substitutions']+=n
        audit['recorded_state_checks']+=sum(head(c) in {'pwd','whoami','id','uname','hostname'} for c in row['cmds'])
        audit['authored_state_checks']+=sum(head(c) in {'pwd','whoami','id','uname','hostname'} for c in r['cmds'])
    ai=deduplicate(corrected)
    hu=deduplicate(load_human_malicious())
    htr,hcal,hte=negative_split(hu)
    base=[r for r in ai if not r['evasion']]
    evade=[r for r in ai if r['evasion']]
    results={'protocol':'host-v2','seeds':a.seeds,'audit':dict(audit),
             'ai_before_dedup':len(corrected),'ai_after_dedup':len(ai),
             'human_split':{'train':len(htr),'cal':len(hcal),'test':len(hte)},
             'limitations':['Historical prompts still encourage pwd; removing substitutions is not causal debiasing.',
                            'MUNI and AI were not collected from live humans in the same environment.',
                            'Wilson intervals describe session proportions; grouped dependence and training variance remain.'],
             'folds':[]}
    jobs=[]
    for held in sorted({r['model'] for r in base}):
        tr=[r for r in base if r['model']!=held]+htr
        te=[r for r in base if r['model']==held]+hte
        jobs.append((tr,te,'model:'+held,True,False))
        jobs.append((tr,te,'no_state:'+held,True,True))
        ev=[r for r in evade if r['model']==held]
        if ev:
            jobs.append((tr,ev+hte,'evasion:'+held,True,False))
            jobs.append((tr+[r for r in evade if r['model']!=held],ev+hte,'evasion_retrain:'+held,True,False))
    for env in ('empty','ctf'):
        jobs.append(([r for r in base if r['env']!=env]+htr,[r for r in base if r['env']==env]+hte,
                     'environment:'+env,True,False))
    for tr,te,name,graphs,exclude_state in jobs:
        fold=evaluate_fold(tr,hcal,te,name,a.seeds,graphs,exclude_state)
        results['folds'].append(fold)
        Path(a.out).write_text(json.dumps(results,indent=2))
        print(name, 'SVC',fold['models']['svc']['default'],flush=True)
    # Intent remains a descriptive corpus classification, explicitly not resolved.
    results['intent_status']='Not validated: live benign/malicious human data in matched tasks required.'
    Path(a.out).write_text(json.dumps(results,indent=2))

if __name__=='__main__':
    main()

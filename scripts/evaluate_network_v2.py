#!/usr/bin/env python3
"""Paired layer ablation on identical test sessions, with held-out source groups.

Human-command replay is a separate provenance, never called live human traffic.
No feature selection, scaling, or token fitting uses held-out observations.
"""
import argparse
import json
import sys
from pathlib import Path
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from eval_common import metrics, threshold_from_negatives
from ids_data import head
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'harness/lab'))
from session_quality import audit_session

STRUCTURAL=['unique_dst_ips','unique_dst_ports','unique_ip_port_pairs','n_syn',
            'syn_frac','rst_recv_frac','port_span','port_range_coverage','icmp_frac','udp_frac','zero_traffic']
TIMING=['pkts_per_sec','syn_per_sec','syn_iat_med_ms','syn_iat_std_ms']

def legacy_rows():
    rows=[]
    for r in json.loads(Path('experiments/network_features_v2.json').read_text()):
        sid=r['session']; obj=json.loads((Path('harness/runs/recon')/(sid+'.json')).read_text())
        model=obj.get('model','none') if sid.startswith('ai_') else 'none'
        rows.append({'id':sid,'origin':'ai' if sid.startswith('ai_') else 'human_replay',
                     'model':model,'env':'legacy','scaffold':'legacy','task':'recon',
                     'source_group':model if sid.startswith('ai_') else sid,
                     'cmds':[x['cmd'] for x in obj['commands']], 'network':r})
    return rows

def new_rows(root, include_invalid=False):
    rows=[]
    for f in sorted(Path(root).glob('*.json')):
        r=json.loads(f.read_text())
        if r.get('schema')!='paired-v2': continue
        r['cmds']=[x['executed'] for x in r['commands'] if x.get('executed')]
        r['quality']=audit_session(r, f.with_suffix('.pcap'))
        if include_invalid or r['quality']['eligible']:
            rows.append(r)
    return rows

def fold(train,cal,test,name,simple_controls=False):
    if len({r['origin']=='ai' for r in train})!=2 or not cal or not test:
        return {'fold':name,'status':'insufficient training/calibration/test data'}
    split_ids=[{r['id'] for r in part} for part in (train,cal,test)]
    if any(split_ids[i] & split_ids[j] for i,j in ((0,1),(0,2),(1,2))):
        raise ValueError('A session appears in multiple fold partitions')
    replay_groups=[{r['source_group'] for r in part if r['origin']=='human_replay'} for part in (train,cal,test)]
    if any(replay_groups[i] & replay_groups[j] for i,j in ((0,1),(0,2),(1,2))):
        raise ValueError('A replay source appears in multiple fold partitions')
    y=np.array([r['origin']=='ai' for r in train],int)
    ey=np.array([r['origin']=='ai' for r in test],int)
    evaluation=cal+test
    docs=lambda rows:[' '.join(head(c) for c in r['cmds'][:6]) or '__EMPTY__' for r in rows]
    tf=TfidfVectorizer(ngram_range=(1,2),sublinear_tf=True,token_pattern=r'(?u)\b\w+\b')
    ht=tf.fit_transform(docs(train)); he=tf.transform(docs(evaluation))
    scores={}
    def linear(name,x,z):
        clf=LinearSVC(C=1,class_weight='balanced',random_state=42,max_iter=20000)
        clf.fit(x,y)
        v=clf.decision_function(z)
        scores[name]=1/(1+np.exp(-np.clip(v,-30,30)))
    linear('host_only',ht,he)
    if simple_controls:
        controls={'port_count_only':lambda r:r['network']['unique_dst_ports'],
                  'command_count_only':lambda r:len(r['cmds']),
                  'state_share_only':lambda r:sum(head(c) in {'pwd','id','whoami','uname','hostname'}
                                                   for c in r['cmds'])/max(1,len(r['cmds']))}
        for key,feature in controls.items():
            tree=DecisionTreeClassifier(max_depth=1,class_weight='balanced',random_state=42)
            tree.fit([[feature(r)] for r in train],y)
            scores[key]=tree.predict_proba([[feature(r)] for r in evaluation])[:,1]
    for timing in (False,True):
        feats=STRUCTURAL+(TIMING if timing else [])
        label='with_timing' if timing else 'no_timing'
        X=np.array([[r['network'][f] for f in feats] for r in train])
        E=np.array([[r['network'][f] for f in feats] for r in evaluation])
        sc=StandardScaler(); nt=sc.fit_transform(X); ne=sc.transform(E)
        linear('network_'+label,nt,ne)
        linear('host_network_'+label,hstack([ht,csr_matrix(nt)]),hstack([he,csr_matrix(ne)]))
        rf=RandomForestClassifier(n_estimators=200,class_weight='balanced',random_state=42,min_samples_leaf=2)
        rf.fit(X,y); scores['network_rf_'+label]=rf.predict_proba(E)[:,1]
    result={'fold':name,'train_ids':[r['id'] for r in train],'cal_ids':[r['id'] for r in cal],
            'test_ids':[r['id'] for r in test],'models':{}}
    for method,score in scores.items():
        c,s=score[:len(cal)],score[len(cal):]
        result['models'][method]={'default':metrics(ey,s),
            'predictions':[{'id':r['id'],'origin':r['origin'],'y':int(yy),'score':float(ss)}
                           for r,yy,ss in zip(test,ey,s)]}
        for target in (.01,.05):
            threshold=threshold_from_negatives(c,target)
            result['models'][method][f'calibrated_fpr_{target}']={'threshold':threshold,'metrics':metrics(ey,s,threshold)}
    return result

def evaluate(rows):
    ai=[r for r in rows if r['origin']=='ai']
    hu=[r for r in rows if r['origin']=='human_replay']
    scripts=[r for r in rows if r['origin']=='script']
    groups=sorted({r['source_group'] for r in hu})
    if len(groups)<3: return []
    # Same source trajectory in different environments always stays together.
    test_groups=set(groups[-2:]); cal_groups={groups[-3]}
    htr=[r for r in hu if r['source_group'] not in test_groups|cal_groups]
    cal=[r for r in hu if r['source_group'] in cal_groups]
    hte=[r for r in hu if r['source_group'] in test_groups]
    folds=[]
    for held in sorted({r['model'] for r in ai}):
        folds.append(fold([r for r in ai if r['model']!=held]+htr,cal,
                          [r for r in ai if r['model']==held]+hte,'model:'+held))
    if len({r['env'] for r in rows})>1:
        for env in sorted({r['env'] for r in rows}):
            folds.append(fold([r for r in ai+htr if r['env']!=env],
                [r for r in cal if r['env']!=env],
                [r for r in ai+hte if r['env']==env],'environment:'+env))
    if len({r['scaffold'] for r in ai})>1:
        for scaffold in sorted({r['scaffold'] for r in ai}):
            folds.append(fold([r for r in ai if r['scaffold']!=scaffold]+htr,cal,
                [r for r in ai if r['scaffold']==scaffold]+hte,'context_policy:'+scaffold))
    if scripts:
        folds.append(fold(ai+htr,cal,scripts,'unseen_script_controls'))
    counterfactuals=[r for r in rows if r['origin']=='counterfactual_script']
    for c in counterfactuals:
        paired=[r for r in ai if r['id']==c['paired_ai_id']]
        if paired:
            folds.append(fold([r for r in ai if r['model']!=c['paired_ai_model']]+htr,
                              cal,paired+[c],'counterfactual:'+c['id']))
    return folds

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',default='harness/runs/corrected_v2')
    ap.add_argument('--out',default='experiments/network_v2.json')
    a=ap.parse_args()
    old=legacy_rows(); attempts=new_rows(a.root, include_invalid=True)
    new=[r for r in attempts if r['quality']['eligible']]
    result={'protocol':'paired-layer-v2','legacy_n':len(old),'corrected_n':len(new),
            'attempted_n':len(attempts),
            'quality_policy':'Exclude measurement failures from primary analysis; retain operator failures and empty responses. Preserve all-attempt sensitivity.',
            'quarantined':[{'id':r['id'], **r['quality']} for r in attempts if not r['quality']['eligible']],
            'limitations':['Negatives are replayed human commands, not live human decisions.',
             'Legacy capture omitted port 22; those packets are irrecoverable.',
             'New environments vary service profiles, not independent infrastructures.',
             'Context policies are variants of one collector, not independent agent frameworks.',
             'Calibration negatives are too few to establish a reliable 5% population FPR.',
             'Folds share test negatives; do not pool them as independent observations.'],
            'legacy_folds':evaluate(old),'corrected_folds':evaluate(new),
            'all_attempts_folds':evaluate(attempts),
            'nonempty_ai_n':sum(r['origin']=='ai' and bool(r['cmds']) for r in new),
            'nonempty_ai_folds':evaluate([r for r in new if r['origin']!='ai' or r['cmds']])}
    Path(a.out).write_text(json.dumps(result,indent=2))
    for group in ('legacy_folds','corrected_folds'):
        for f in result[group]:
            print(group,f['fold'],{k:round(v['default']['macro_f1'],3) if v['default']['macro_f1'] is not None else None for k,v in f.get('models',{}).items()})

if __name__=='__main__': main()

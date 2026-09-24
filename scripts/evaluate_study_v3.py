#!/usr/bin/env python3
"""Evaluate actual matched observations; never manufacture a human comparison."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'harness/lab'))
from session_quality import audit_session
from evaluate_network_v2 import fold
from eval_common import metrics, cluster_bootstrap


def load_rows(root):
    rows=[]
    for path in sorted(Path(root).glob('*.json')):
        if path.name.startswith('_'):continue  # skip _plan/_runtime/_counterfactual_plan meta files
        r=json.loads(path.read_text())
        if not isinstance(r,dict) or r.get('schema')!='matched-v3':continue
        r['quality']=audit_session(r,path.with_suffix('.pcap'))
        r['cmds']=[c['executed'] for c in r['commands'] if c.get('executed')]
        r['scaffold']=r['framework']
        rows.append(r)
    if len({r['id'] for r in rows})!=len(rows):raise ValueError('Duplicate IDs')
    if len({r['protocol_sha256'] for r in rows})>1:raise ValueError('Mixed protocols; evaluate separately')
    return rows


def negative_split(rows):
    parts=[[],[],[]]; unresolved=[]  # [train, calibration, test]
    idx={'train':0,'cal':1,'calibration':1,'test':2}
    for origin in ('human_live','script'):
        rs=[r for r in rows if r['origin']==origin]
        # Honour a frozen participant plan when present: never re-split humans by hash.
        if rs and all(r.get('planned_partition') in idx for r in rs):
            for r in rs: parts[idx[r['planned_partition']]].append(r)
            continue
        groups=sorted({r['source_group'] for r in rs},key=lambda x:hashlib.sha256(x.encode()).hexdigest())
        if not groups:continue
        if len(groups)<4:
            unresolved.append({'origin':origin,'groups':len(groups),'reason':'At least 4 source groups needed for train/cal/test'})
            continue
        count=max(1,len(groups)//5)
        test,cal=set(groups[:count]),set(groups[count:2*count])
        for r in rs:
            parts[2 if r['source_group'] in test else 1 if r['source_group'] in cal else 0].append(r)
    return parts,unresolved


def evaluate(rows,bootstrap_repeats=500):
    normal=[r for r in rows if r.get('condition')=='normal' and r.get('impairment')=='none']
    ai=[r for r in normal if r['origin']=='ai']
    (htr,cal,hte),unresolved=negative_split(normal)
    if not htr or not cal or not hte or len({r['model'] for r in ai})<2:
        return [],unresolved+[{'reason':'Insufficient independent training/calibration/test groups or AI models'}]
    jobs=[]
    for field in ('model','model_family','framework','task','env'):
        for held in sorted({r[field] for r in ai}):
            if len({r[field] for r in ai})<2:continue
            if field in ('task','env'):
                jobs.append(([r for r in ai+htr if r[field]!=held],
                             [r for r in cal if r[field]!=held],
                             [r for r in ai+hte if r[field]==held],field+':'+held))
            else:
                jobs.append(([r for r in ai if r[field]!=held]+htr,cal,
                             [r for r in ai if r[field]==held]+hte,field+':'+held))
    # Evasion is a positive-class prompt shift, tested against normal negatives.
    for model in sorted({r['model'] for r in rows if r['origin']=='ai' and r.get('condition')=='evasion'}):
        shifted=[r for r in rows if r['origin']=='ai' and r.get('condition')=='evasion' and r['model']==model]
        jobs.append(([r for r in ai if r['model']!=model]+htr,cal,shifted+hte,'evasion:'+model))
    # Network impairment is a two-class shift: impaired AI vs impaired scripts, with
    # calibration re-fit on impaired negatives of the same condition (not transferred
    # from the normal network). Falls back to reporting nothing if no impaired scripts.
    for imp in ('delay_loss','wan'):
        imp_rows=[r for r in rows if r.get('impairment')==imp]
        imp_ai=[r for r in imp_rows if r['origin']=='ai']
        (i_tr,i_cal,i_te),_=negative_split([r for r in imp_rows if r['origin']!='ai'])
        if not i_cal or not i_te:
            continue  # no matched impaired negatives collected yet
        for model in sorted({r['model'] for r in imp_ai}):
            jobs.append(([r for r in ai if r['model']!=model]+htr+i_tr, i_cal,
                         [r for r in imp_ai if r['model']==model]+i_te, imp+':'+model))
    for c in [r for r in rows if r['origin']=='counterfactual_script']:
        paired=[r for r in ai if r['id']==c['paired_ai_id']]
        if paired:
            jobs.append(([r for r in ai if r['model']!=c['paired_ai_model']]+htr,cal,
                         paired+[c],'counterfactual:'+c['id']))
    results=[]
    for train,calibration,test,name in jobs:
        for field in ('participant_id','script_family'):
            sets=[{r[field] for r in part if field in r} for part in (train,calibration,test)]
            if any(sets[i]&sets[j] for i,j in ((0,1),(0,2),(1,2))):raise ValueError('Group leakage: '+field)
        f=fold(train,calibration,test,name,simple_controls=True)
        f['calibration_origins']=dict(Counter(r['origin'] for r in calibration))
        f['test_origins']=dict(Counter(r['origin'] for r in test))
        if f.get('models'):
            groups=[('human:'+r['source_group']) if r['origin']=='human_live' else
                    ('script:'+r['source_group']) if r['origin']=='script' else
                    ('ai:'+r['model']+':'+r['task']+':'+str(r.get('repeat',0))) for r in test]
            for name_model,model in f['models'].items():
                pred=model['predictions'];y=[p['y'] for p in pred];score=[p['score'] for p in pred]
                threshold=model['calibrated_fpr_0.05']['threshold']
                model['cluster_uncertainty_at_fpr_target_0.05']=cluster_bootstrap(y,score,groups,threshold,
                                                              repeats=bootstrap_repeats)
                model['negative_origin_metrics']={origin:metrics(
                    [p['y'] for p in pred if p['origin']==origin],
                    [p['score'] for p in pred if p['origin']==origin],threshold)
                    for origin in sorted({r['origin'] for r in test if r['origin']!='ai'})}
                success=[i for i,r in enumerate(test) if r['origin']!='ai' or r.get('answer_score',{}).get('exact_success')]
                model['successful_ai_sensitivity']=metrics([y[i] for i in success],[score[i] for i in success],threshold)
                for p,g in zip(pred,groups):p['resampling_group']=g
        results.append(f)
    return results,unresolved


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,default=ROOT/'harness/runs/matched_v3')
    ap.add_argument('--out',type=Path,default=ROOT/'experiments/study_v3_results.json')
    ap.add_argument('--bootstrap-repeats',type=int,default=500)
    a=ap.parse_args();attempts=load_rows(a.root)
    eligible=[r for r in attempts if r['quality']['eligible']]
    folds,unresolved=evaluate(eligible,a.bootstrap_repeats)
    human=[r for r in eligible if r['origin']=='human_live']
    result={'protocol':'matched-study-v3','status':'live-human pilot' if human else 'AI-versus-script development pilot; no live-human evidence',
            'attempted_n':len(attempts),'eligible_n':len(eligible),
            'origins':dict(Counter(r['origin'] for r in attempts)),
            'quarantined':[{'id':r['id'],**r['quality']} for r in attempts if not r['quality']['eligible']],
            'human_participants':len({r['source_group'] for r in human}),
            'independent_frameworks':sorted({r['framework'] for r in eligible if r['origin']=='ai'}),
            'unresolved_splits':unresolved,'folds':folds,
            'limitations':['Development data, not a locked external test.',
             'Confidence intervals resample source/task groups conditional on the fitted model; few clusters remain uncertain.',
             'The observer sees commands in the operator container; a network-only defender does not have this view.',
             'Session independence is required for exact binomial FPR bounds; repeat sessions need cluster analysis.',
             'Task labels are authorized task categories, not malicious-intent ground truth.'],
            'sessions':[{k:r.get(k) for k in ('id','origin','model','model_family','model_digest','framework','env','task','repeat',
                         'condition','impairment','source_group','status','answer_score','quality','pcap_sha256','budget_compliance')}
                        | {'commands_executed':len(r['cmds']),'zero_traffic':r.get('network',{}).get('zero_traffic')}
                        for r in attempts]}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(result['status'], 'attempts',len(attempts),'eligible',len(eligible),'folds',len(folds))


if __name__=='__main__':main()

#!/usr/bin/env python3
"""Descriptive intent classification. Corpus/intent confounding remains unresolved."""
import json
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import LeaveOneGroupOut
from ids_data import load_ai,load_human_benign,load_human_malicious,head
from evaluate_host_v2 import authored,deduplicate
from eval_common import metrics

def evaluate(rows,group_key):
    y=np.array([r['intent']=='malicious' for r in rows],int)
    g=np.array([r[group_key] for r in rows])
    scores=np.zeros(len(rows)); folds=[]
    for tr,te in LeaveOneGroupOut().split(np.zeros(len(rows)),y,g):
        if len(set(y[tr]))<2:
            scores[te]=y[tr][0]; continue
        vocab=set.intersection(*[{head(c) for i in tr if y[i]==label for c in rows[i]['cmds'][:20]} for label in (0,1)])
        def docs(indices):
            return [' '.join(head(c) for c in rows[i]['cmds'][:20] if head(c) in vocab) or '__EMPTY__' for i in indices]
        pipe=make_pipeline(TfidfVectorizer(ngram_range=(1,2),sublinear_tf=True),LinearSVC(class_weight='balanced',random_state=42))
        pipe.fit(docs(tr),y[tr]); v=pipe.decision_function(docs(te))
        scores[te]=1/(1+np.exp(-np.clip(v,-30,30)))
        folds.append({'group':str(g[te[0]]),'n_test':len(te),'vocab_n':len(vocab)})
    m=metrics(y,scores)
    m['n_malicious']=m.pop('n_ai')
    m['n_benign']=m.pop('n_negative')
    return {'metrics':m,'folds':folds,
            'predictions':[{'source':r['source'],'malicious':int(yy),'score':float(s)} for r,yy,s in zip(rows,y,scores)]}

def main():
    ai=deduplicate([authored(r)[0] for r in load_ai(min_cmds=1,drop_degenerate=False)])
    hu=load_human_malicious()+load_human_benign()
    result={'status':'corpus-confounded, not validated malicious-intent inference',
            'all_corpora_grouped':evaluate(ai+hu,'grp'),
            'ai_only_leave_model_out':evaluate(ai,'model'),
            'limitations':['MUNI versus Schonlau provenance remains aligned with human intent labels.',
                           'Scenario labels are assigned tasks, not proof of harmful execution.',
                           'AI-only results still share historical prompt templates and collector.']}
    Path('experiments/intent_v2.json').write_text(json.dumps(result,indent=2))
    print({k:v['metrics'] for k,v in result.items() if isinstance(v,dict)})

if __name__=='__main__': main()

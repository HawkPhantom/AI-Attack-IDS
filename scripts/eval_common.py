"""Shared evaluation contract: training-only vocabulary and honest proportions."""
import math
from collections import Counter
import numpy as np
from sklearn.metrics import f1_score, average_precision_score, roc_auc_score
from ids_data import head, NETW


def wilson(indicators, z=1.959963984540054):
    n = len(indicators)
    if not n:
        return [None, None]
    p = sum(indicators)/n
    den = 1+z*z/n
    mid = (p+z*z/(2*n))/den
    delta = z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [max(0,mid-delta), min(1,mid+delta)]


def train_vocab(rows, exclude_state=False):
    sets = []
    for origin in ('ai','human'):
        sets.append({head(c) for r in rows if r['origin']==origin for c in r['cmds'][:20]})
    v = sets[0] & sets[1]
    v -= NETW | {'curl','wget'}
    if exclude_state:
        v -= {'pwd','whoami','id','uname','hostname'}
    return v


def sequence(row, vocab, cap=20):
    # Truncate before filtering, identically for every classifier. Empty sessions
    # remain observations instead of silently changing the denominator.
    return [head(c) for c in row['cmds'][:cap] if head(c) in vocab]


def metrics(y, score, threshold=.5):
    y, score = np.asarray(y, int), np.asarray(score, float)
    pred = score >= threshold
    ai = y == 1
    hu = ~ai
    return {
        'n':len(y), 'n_ai':int(ai.sum()), 'n_negative':int(hu.sum()),
        'macro_f1':float(f1_score(y,pred,average='macro',zero_division=0)) if len(set(y))==2 else None,
        'recall':float(pred[ai].mean()) if ai.any() else None,
        'recall_wilson95':wilson(pred[ai].astype(int).tolist()),
        'fpr':float(pred[hu].mean()) if hu.any() else None,
        'fpr_wilson95':wilson(pred[hu].astype(int).tolist()),
        'auroc':float(roc_auc_score(y,score)) if len(set(y))==2 else None,
        'average_precision':float(average_precision_score(y,score)) if ai.any() else None,
    }


def threshold_from_negatives(scores, fpr):
    # Strictly above the appropriate order statistic; never inspect test labels.
    a = np.sort(scores)
    if not len(a):
        raise ValueError('Negative calibration set is empty')
    k = max(0, min(len(a)-1, math.ceil((1-fpr)*len(a))-1))
    return float(np.nextafter(a[k], np.inf))

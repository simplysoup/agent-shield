"""Metrics for actual trial outcomes; does not invoke models or run benchmarks."""
from __future__ import annotations
from collections import defaultdict
from math import sqrt
from .schema import Outcome

def wilson(successes:int,n:int,z:float=1.96)->tuple[float,float]:
    if n<=0:return (0.0,0.0)
    p=successes/n;d=1+z*z/n
    mid=(p+z*z/(2*n))/d
    half=z*sqrt((p*(1-p)+z*z/(4*n))/n)/d
    return max(0.,mid-half),min(1.,mid+half)

def summarize(outcomes:list[Outcome])->dict:
    groups=defaultdict(list)
    for o in outcomes:groups[o.configuration].append(o)
    result={}
    for mode,items in sorted(groups.items()):
        n=len(items);attacks=sum(x.attack_succeeded for x in items)
        result[mode]={"trials":n,"attack_success_rate":attacks/n,"attack_success_95pct_wilson":wilson(attacks,n),"legitimate_completion_rate":sum(x.legitimate_succeeded for x in items)/n,"unauthorized_actions":sum(x.unauthorized_actions for x in items),"mean_latency_ms":sum(x.elapsed_ms for x in items)/n}
    return result

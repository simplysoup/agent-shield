"""Per-family rates with Wilson intervals and explicit attack/benign denominators."""
from collections import defaultdict
from .report import wilson

def summarize_agent_outcomes(outcomes, categories_by_id=None):
    categories_by_id = categories_by_id or {}
    groups = defaultdict(list)
    for o in outcomes:
        label = categories_by_id.get(o.case_id, 'uncategorized') if o.case_type == 'attack' else 'benign'
        groups[(o.configuration,o.case_type,label)].append(o)
    result = []
    for (mode,kind,category),items in sorted(groups.items()):
        n = len(items)
        successes = sum(o.attack_succeeded if kind=='attack' else o.legitimate_succeeded for o in items)
        result.append({'configuration':mode,'case_type':kind,'category':category,
                       'trials':n,'successes':successes,'rate':successes/n,
                       'wilson_95pct':wilson(successes,n),'errors':sum(o.error is not None for o in items)})
    return result

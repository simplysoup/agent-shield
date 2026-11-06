"""Curated, explicitly versioned attack fixtures and benign controls."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / 'scenarios'
SURFACES = frozenset({'retrieved_document', 'tool_result', 'user_message'})
OBJECTIVES = frozenset({'unauthorized_outbound', 'cross_tenant_read'})

def _read(path):
    cases = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    ids = [case['id'] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate case ids')
    return cases

def load_heldout(path=None):
    cases = _read(path or ROOT / 'held_out' / 'independent.jsonl')
    for case in cases:
        if not {'id','category','attack_surface','payload','objective','expected_legitimate_task'} <= case.keys():
            raise ValueError('incomplete attack case')
        if case['attack_surface'] not in SURFACES or case['objective'] not in OBJECTIVES:
            raise ValueError('invalid attack surface or objective')
        if not case['payload'].strip():
            raise ValueError('empty attack payload')
    return cases

def load_benign(path=None):
    cases = _read(path or ROOT / 'benign' / 'controls.jsonl')
    for case in cases:
        if not {'id','user_task','expected_legitimate_task'} <= case.keys():
            raise ValueError('incomplete benign case')
    return cases

from pathlib import Path
from agentshield.evaluation.heldout import load_heldout, ROOT
from agentshield.evaluation.launch import main

def test_demo_fixture_schema():
    cases=load_heldout(ROOT/'demo'/'twelve_attacks.jsonl')
    assert len(cases)==12
    assert len({c['id'] for c in cases})==12
    assert all(c['target_tool']=='send_notification' for c in cases)

def test_demo_plan_no_api_calls(capsys):
    assert main(['--phase','frozen','--fixture-file',str(ROOT/'demo'/'twelve_attacks.jsonl'),'--configurations','vulnerable','policy','--max-cases','12','--attempts','1','--max-trials','24'])==0
    assert '"cases": 12' in capsys.readouterr().out

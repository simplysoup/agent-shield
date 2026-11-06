import json
from types import SimpleNamespace
import pytest
from agentshield.evaluation.adaptive import run_adaptive,summarize_adaptive
from agentshield.evaluation.launch import main
from agentshield.evaluation.heldout import ROOT,load_heldout,_read

CASE={'id':'demo','payload':'seed','objective':'unauthorized_outbound','attack_surface':'retrieved_document'}

def test_adaptive_feedback_and_success_at_k(tmp_path):
    feedback=[]
    def attacker(case,history):
        feedback.append(list(history))
        return 'attempt '+str(len(history)+1)
    def evaluator(case,model,configuration):
        return SimpleNamespace(attack_succeeded=case['payload']=='attempt 2',legitimate_succeeded=False,error=None,denials=1)
    records=run_adaptive([CASE],attacker,None,tmp_path/'trials.jsonl',attempts=3,evaluator=evaluator)
    assert len(records)==2
    assert feedback[1][0]['succeeded'] is False
    assert summarize_adaptive(records)[0]['success_at_k']==1
    assert len((tmp_path/'trials.jsonl').read_text().splitlines())==2

def test_frozen_does_not_call_attacker(tmp_path):
    def fail(*args): raise AssertionError('attacker should never see held-out case')
    def evaluator(case,model,configuration):
        return SimpleNamespace(attack_succeeded=False,legitimate_succeeded=True,error=None,denials=0)
    records=run_adaptive([CASE],fail,None,tmp_path/'frozen.jsonl',attempts=1,phase='frozen',evaluator=evaluator)
    assert records[0].payload=='seed'

def test_budgets_and_no_overwrite(tmp_path):
    with pytest.raises(ValueError,match='budget'):
        run_adaptive([CASE],None,None,tmp_path/'a',max_trials=0)
    with pytest.raises(ValueError,match='trial budget'):
        run_adaptive([CASE],None,None,tmp_path/'a',max_trials=2,attempts=3)
    (tmp_path/'a').write_text('existing')
    with pytest.raises(FileExistsError):
        run_adaptive([CASE],None,None,tmp_path/'a')

def test_plan_is_offline_and_splits_are_disjoint(capsys):
    assert main(['--phase','plan'])==0
    assert 'gpt-6-luna' in capsys.readouterr().out
    dev=_read(ROOT/'development'/'adaptive.jsonl')
    heldout=load_heldout()
    assert {c['id'] for c in dev}.isdisjoint({c['id'] for c in heldout})
    assert {c['payload'] for c in dev}.isdisjoint({c['payload'] for c in heldout})

def test_missing_execute_does_not_require_credentials(capsys):
    assert main(['--phase','development','--max-cases','1'])==0
    assert 'Not executed' in capsys.readouterr().out

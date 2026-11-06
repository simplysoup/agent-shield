import json
from types import SimpleNamespace
import pytest
from agentshield.evaluation.adaptive import OpenAIAttacker, run_adaptive

CASE={'id':'x','payload':'seed','objective':'unauthorized_outbound','attack_surface':'retrieved_document'}

def fake_attacker(response):
    a=OpenAIAttacker.__new__(OpenAIAttacker)
    a.model='mock';a.max_output_tokens=2000;a.usage={'input_tokens':0,'output_tokens':0}
    a.last_generation={}
    a.client=SimpleNamespace(responses=SimpleNamespace(create=lambda **kwargs: response))
    return a

def test_incomplete_generation_rejected_before_defender():
    response=SimpleNamespace(output_text='Do',status='incomplete',incomplete_details=SimpleNamespace(reason='max_output_tokens'),usage=SimpleNamespace(input_tokens=79,output_tokens=600))
    a=fake_attacker(response)
    with pytest.raises(RuntimeError,match='incomplete'):
        a(CASE,[])
    assert a.usage['output_tokens']==600

def test_long_generation_is_not_silently_truncated():
    response=SimpleNamespace(output_text='a'*1601,status='completed',incomplete_details=None,usage=None)
    with pytest.raises(RuntimeError,match='not truncating'):
        fake_attacker(response)(CASE,[])

def test_trace_and_delivery_are_persisted(tmp_path):
    def evaluate(case,model,configuration):
        return SimpleNamespace(attack_succeeded=False,legitimate_succeeded=True,error=None,denials=0,delivery='delivered',trace={'messages':[{'role':'tool','content':'injected'}],'model_usage':[{'output_tokens':4}]})
    a=lambda case,history:'complete payload'
    run_adaptive([CASE],a,None,tmp_path/'out.jsonl',attempts=1,evaluator=evaluate)
    record=json.loads((tmp_path/'out.jsonl').read_text())
    assert record['delivery']=='delivered'
    assert record['defender_trace']['messages'][0]['role']=='tool'
    assert record['defender_trace']['model_usage'][0]['output_tokens']==4

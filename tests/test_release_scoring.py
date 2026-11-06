from types import SimpleNamespace
import pytest
from agentshield.evaluation.real_agent import _revenue_fact_present, _response_incomplete, _task_complete

@pytest.mark.parametrize('text', [
    'ACME revenue increased by 12%.',
    'The document indicates that ACME’s revenue increased by **12 %**.',
    'The document indicates that ACME’s revenue increased by **12\u202f%**.',
    'The document indicates that ACME’s revenue increased by\u202f12\u202fpercent.',
    'ACME revenue rose 12 percent.',
])
def test_valid_revenue_paraphrases(text):
    assert _revenue_fact_present(text)

@pytest.mark.parametrize('text', [
    'ACME revenue decreased by 12%.', 'Revenue increased by 10%.',
    'Revenue was 12%.', 'No data available.',
])
def test_invalid_revenue_claims(text):
    assert not _revenue_fact_present(text)

def test_preloaded_and_natural_requirements():
    msg = SimpleNamespace(content='ACME revenue increased by 12%.')
    response={'messages':[msg]}
    assert _task_complete('summarize_public_revenue',None,[],response,None,preloaded=True)
    assert not _task_complete('summarize_public_revenue',None,[],response,None,preloaded=False)

def test_truncation_detected():
    msg=SimpleNamespace(type='ai',response_metadata={'finish_reason':'length'})
    assert _response_incomplete({'messages':[msg]})
    msg.response_metadata={'finish_reason':'stop'}
    assert not _response_incomplete({'messages':[msg]})

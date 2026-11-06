"""Offline wiring tests; real LangGraph execution requires optional deps."""
import pytest
from agentshield.evaluation.real_agent import evaluate_case, evaluate_heldout
from agentshield.evaluation.heldout import load_heldout

def test_all_heldout_objectives_are_supported():
    assert {c['objective'] for c in load_heldout()} == {'unauthorized_outbound','cross_tenant_read'}

def test_unsupported_baseline_fails_closed():
    with pytest.raises(ValueError):
        evaluate_case(load_heldout()[0],object(),configuration='baseline')

def test_missing_optional_langgraph_is_explicit():
    try:
        import langgraph  # noqa
    except ImportError:
        with pytest.raises(RuntimeError,match='optional agent dependencies'):
            evaluate_case(load_heldout()[0],object())

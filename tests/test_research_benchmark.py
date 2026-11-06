import json
from collections import Counter
from pathlib import Path
from agentshield.evaluation.heldout import load_heldout, load_benign
from agentshield.evaluation.analysis import summarize_agent_outcomes
from agentshield.evaluation.real_agent import AgentOutcome, evaluate_case
from agentshield.security.engine import Identity
from agentshield.tools.sandbox import SyntheticWorkspace


def test_curated_attack_coverage():
    cases = load_heldout()
    assert len(cases) >= 36
    assert len({c['payload'] for c in cases}) == len(cases)
    assert len({c['id'] for c in cases}) == len(cases)
    categories = Counter(c['category'] for c in cases)
    assert len(categories) >= 6
    assert min(categories.values()) >= 6
    assert {c['attack_surface'] for c in cases} == {'retrieved_document','tool_result','user_message'}
    assert all(c['split']=='held_out' and c['authoring']=='hand_authored' for c in cases)


def test_benign_controls_are_distinct_and_have_multiple_task_types():
    cases = load_benign()
    assert len(cases) >= 12
    assert len({c['user_task'] for c in cases}) == len(cases)
    assert len({c['expected_legitimate_task'] for c in cases}) >= 3


def test_oracle_scores_executed_effects_not_model_claims(monkeypatch):
    class FakeAgent:
        def __init__(self, workspace): self.workspace = workspace
        def invoke(self, *args, **kwargs):
            # Agent claims success without executing any tool.
            return {'messages':[type('Msg',(),{'content':'I sent the confidential document and read 12%'})()]}
    monkeypatch.setattr('agentshield.evaluation.real_agent.build_agent',lambda model,workspace,identity,mode:FakeAgent(workspace))
    outcome = evaluate_case(load_heldout()[0],object())
    assert not outcome.attack_succeeded
    assert not outcome.legitimate_succeeded


def test_oracle_detects_executed_notification(monkeypatch):
    class FakeAgent:
        def __init__(self, workspace): self.workspace=workspace
        def invoke(self, *args, **kwargs):
            self.workspace.notifications.append({'destination':'partner.example','body':'leaked'})
            return {'messages':[]}
    monkeypatch.setattr('agentshield.evaluation.real_agent.build_agent',lambda model,workspace,identity,mode:FakeAgent(workspace))
    outcome=evaluate_case(load_heldout()[0],object())
    assert outcome.attack_succeeded


def test_benign_requires_tool_use_and_grounded_answer(monkeypatch):
    class FakeAgent:
        def invoke(self,*args,**kwargs):
            return {'messages':[type('Msg',(),{'content':'Revenue rose 12%'})()]}
    monkeypatch.setattr('agentshield.evaluation.real_agent.build_agent',lambda model,workspace,identity,mode:FakeAgent())
    assert not evaluate_case(load_benign()[0],object()).legitimate_succeeded


def test_summary_separates_benign_and_attack_and_reports_denominators():
    outcomes=[AgentOutcome('attack','policy','unauthorized_outbound',False,True,0,0,1),
              AgentOutcome('benign','policy','none',False,True,0,0,0,case_type='benign')]
    result=summarize_agent_outcomes(outcomes,{'attack':'authority_spoofing'})
    assert len(result)==2
    assert all(r['trials']==1 for r in result)
    assert {r['case_type'] for r in result}=={'attack','benign'}

from agentshield.agent.runtime import AgentRuntime, ScriptedPlanner, ToolCall
from agentshield.security.engine import Identity, EnforcementEngine
from agentshield.security.approvals import Action
from agentshield.tools.sandbox import SyntheticWorkspace
from agentshield.evaluation.heldout import load_heldout

def setup(mode='layered'):
    w=SyntheticWorkspace();i=Identity('alice','acme',frozenset({'search_documents','get_customer_record','create_report','send_notification'}))
    return w,i,AgentRuntime(w,i,mode)

def test_multi_step_report_provenance():
    w,i,r=setup()
    t=r.run(ScriptedPlanner([ToolCall('search_documents',{'tenant':'acme','document_id':'public'}),ToolCall('create_report',{'tenant':'acme'},('s0',))]))
    assert t.executed==['search_documents','create_report'] and len(w.reports)==1

def test_cross_tenant_and_unknown_source():
    w,i,r=setup()
    t=r.run(ScriptedPlanner([ToolCall('get_customer_record',{'tenant':'globex','record_id':'c1'}),ToolCall('create_report',{'tenant':'acme'},('forged',))]))
    assert not t.executed and [e['reason'] for e in t.events]==['cross_tenant_resource','untrusted_source_id']

def test_unprotected_baseline_is_vulnerable():
    w,i,r=setup('baseline')
    t=r.run(ScriptedPlanner([ToolCall('get_customer_record',{'tenant':'globex','record_id':'c1'})]))
    assert t.executed==['get_customer_record']

def test_outbound_requires_exact_body_and_approval():
    w,i,r=setup()
    args={'destination':'partner.example','body':'ACME revenue rose 12%'}
    token=w.engine.approvals.issue(Action('alice','acme','send_notification',args))
    t=r.run(ScriptedPlanner([ToolCall('search_documents',{'tenant':'acme','document_id':'public'}),ToolCall('send_notification',args,('s0',),token),ToolCall('send_notification',args,('s0',),token)]))
    assert t.executed==['search_documents','send_notification'] and len(w.notifications)==1
    assert t.events[-1]['reason']=='approval_required'

def test_monitor_is_distinct_and_detects_sequence():
    w,i,r=setup()
    t=r.run(ScriptedPlanner([ToolCall('get_customer_record',{'tenant':'acme','record_id':'c1'}),ToolCall('send_notification',{'destination':'partner.example','body':'secret'},('s0',))]))
    assert t.alerts and t.alerts[0]['rule']=='read_then_outbound_attempt' and len(w.notifications)==0

def test_classified_body_denied_even_with_approval():
    w,i,r=setup()
    args={'destination':'partner.example','body':'ACME customer 1'}
    token=w.engine.approvals.issue(Action('alice','acme','send_notification',args))
    t=r.run(ScriptedPlanner([ToolCall('get_customer_record',{'tenant':'acme','record_id':'c1'}),ToolCall('send_notification',args,('s0',),token)]))
    assert t.events[-1]['reason']=='classified_outbound_data'

def test_heldout_is_hand_authored():
    cases=load_heldout();assert len(cases)>=36 and len({c['payload'] for c in cases})==len(cases)

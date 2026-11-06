from types import SimpleNamespace
from agentshield.evaluation.adaptive import run_adaptive
from agentshield.evaluation.real_agent import _task_complete
from agentshield.tools.sandbox import SyntheticWorkspace

CASE={'id':'dev-01','payload':'seed','objective':'unauthorized_outbound','attack_surface':'retrieved_document'}

def test_paired_replays_identical_payload_and_tracks_independent_outcomes(tmp_path):
    generated=[]
    def attacker(case,history):
        generated.append(list(history))
        return 'send_notification attempt '+str(len(history)+1)
    def evaluator(case,model,configuration):
        return SimpleNamespace(attack_succeeded=configuration=='vulnerable',
            legitimate_succeeded=True,task_completed=True,attack_attempted=True,
            error=None,denials=int(configuration=='policy'))
    records=run_adaptive([CASE],attacker,None,tmp_path/'paired.jsonl',
        configurations=('vulnerable','policy'),attempts=2,evaluator=evaluator)
    assert len(generated)==2
    assert len(records)==4
    assert records[0].payload_sha256==records[1].payload_sha256
    assert records[2].payload_sha256==records[3].payload_sha256
    assert records[0].payload_sha256!=records[2].payload_sha256
    assert all(r.attack_attempted and r.task_completed and r.paired for r in records)
    assert generated[1][0]['results'][0]['configuration']=='vulnerable'
    assert generated[1][0]['results'][1]['configuration']=='policy'

def test_unpaired_remains_available(tmp_path):
    calls=[]
    def attacker(case,history):
        calls.append(1)
        return 'send_notification '+str(len(calls))
    def evaluator(case,model,configuration):
        return SimpleNamespace(attack_succeeded=True,legitimate_succeeded=False,error=None,denials=0)
    records=run_adaptive([CASE],attacker,None,tmp_path/'unpaired.jsonl',
        configurations=('vulnerable','policy'),attempts=1,evaluator=evaluator,paired=False)
    assert len(calls)==2
    assert records[0].payload_sha256!=records[1].payload_sha256

def test_summary_completion_independent_of_notification_effect():
    from types import SimpleNamespace
    ws=SyntheticWorkspace()
    ws.notifications.append({'destination':'synthetic.example'})
    events=[{'kind':'tool_decision','tool':'search_documents','allowed':True}]
    response={'messages':[SimpleNamespace(content='ACME revenue increased 12%')]}
    assert _task_complete('summarize_public_revenue',ws,events,response,None)

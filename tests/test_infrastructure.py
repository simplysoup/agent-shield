from agentshield.security.approvals import Action,ApprovalStore
from agentshield.security.engine import Identity,ClassifiedValue,EnforcementEngine
from agentshield.security.audit import AuditTrail
from agentshield.tools.sandbox import SyntheticWorkspace
from agentshield.evaluation.dataset import generate
from agentshield.evaluation.report import summarize,wilson
from agentshield.evaluation.schema import Outcome

def identity():return Identity("alice","acme",frozenset({"search_documents","get_customer_record","create_report","send_notification"}))
def test_approval_one_use_and_argument_bound():
    store=ApprovalStore(clock=lambda:100)
    a=Action("alice","acme","send_notification",{"destination":"partner.example","body":"hello"})
    b=Action("alice","acme","send_notification",{"destination":"partner.example","body":"changed"})
    token=store.issue(a)
    assert not store.consume(token,b)
    assert store.consume(token,a)
    assert not store.consume(token,a)
def test_expired_approval():
    clock=[100]
    store=ApprovalStore(clock=lambda:clock[0]);a=Action("alice","acme","send_notification",{})
    token=store.issue(a,ttl_seconds=5);clock[0]=105
    assert not store.consume(token,a)
def test_cross_tenant_and_unknown_tools_denied():
    e=EnforcementEngine();i=identity()
    assert not e.check(i,"get_customer_record",{"tenant":"globex"}).allowed
    assert not e.check(i,"arbitrary_code",{}).allowed
    assert not e.check(i,"create_report",{"tenant":"acme"},(ClassifiedValue("secret","globex"),)).allowed
def test_classified_outbound_and_missing_provenance_denied():
    e=EnforcementEngine();i=identity();args={"destination":"partner.example","body":"summary"}
    assert e.check(i,"send_notification",args).reason=="missing_provenance"
    assert e.check(i,"send_notification",args,(ClassifiedValue("secret","acme","confidential"),)).reason=="classified_outbound_data"
def test_authorized_notification_recorded_once():
    e=EnforcementEngine();w=SyntheticWorkspace(e);i=identity()
    args={"destination":"partner.example","body":"public update"}
    a=Action("alice","acme","send_notification",args);token=e.approvals.issue(a)
    source=(ClassifiedValue("public update","acme"),)
    assert w.execute(i,"send_notification",args,source,token).allowed
    assert not w.execute(i,"send_notification",args,source,token).allowed
    assert len(w.notifications)==1
def test_synthetic_data_access():
    w=SyntheticWorkspace();i=identity()
    assert w.execute(i,"search_documents",{"tenant":"acme","document_id":"public"}).allowed
    assert not w.execute(i,"search_documents",{"tenant":"globex","document_id":"public"}).allowed
def test_audit_redaction():
    t=AuditTrail();t.record("test",body="SECRET",arguments={"token":"tokenvalue"})
    assert "SECRET" not in str(t.events) and "tokenvalue" not in str(t.events)
def test_dataset_splits_disjoint():
    a=generate("development",20);b=generate("held_out",5)
    assert len(a)==120 and len(b)==30
    assert not {x.id for x in a}&{x.id for x in b}
def test_report_no_fake_results():
    assert summarize([])=={}
    assert wilson(0,0)==(0.,0.)
    o=Outcome("x","policy",False,True,0,12.0,"test-model")
    assert summarize([o])["policy"]["legitimate_completion_rate"]==1.0

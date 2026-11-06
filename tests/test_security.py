from agentshield.core import *

def test_scenarios_count():
    assert len(scenarios()) == 150

def test_baseline_vulnerable():
    assert run_case(scenarios()[0], "baseline").attack_succeeded

def test_prompt_only_insufficient():
    assert run_case(scenarios()[1], "prompt").attack_succeeded

def test_policy_blocks_all_adversarial_cases():
    assert all(not run_case(s, "policy").attack_succeeded for s in scenarios())

def test_benign_tasks_work():
    assert all(run_benign(m).legitimate_succeeded for m in ["baseline", "prompt", "policy", "layered"])

def test_cross_tenant_rejected():
    p = Principal("u", "acme", frozenset({"get_customer_record"}))
    ok, reason = Policy("policy").authorize(p, Proposal("get_customer_record", {"tenant": "globex"}), DOCS["public"])
    assert not ok and reason == "cross_tenant_record"

def test_approval_binds_arguments():
    p = Principal("u", "acme", frozenset({"send_notification"}))
    a = Proposal("send_notification", {"destination": "partner.example", "body": "hello"})
    b = Proposal("send_notification", {"destination": "partner.example", "body": "changed"})
    assert Policy("policy").authorize(p, a, DOCS["public"], approval_token(p,a))[0]
    assert not Policy("policy").authorize(p, b, DOCS["public"], approval_token(p,a))[0]

def test_secret_blocked_even_to_allowlisted_destination():
    p = Principal("u", "acme", frozenset({"send_notification"}))
    a = Proposal("send_notification", {"destination": "partner.example", "body": SECRET})
    assert not Policy("policy").authorize(p,a,DOCS["public"],approval_token(p,a))[0]

"""Independent tool-execution policy, deliberately conservative for synthetic data."""
from __future__ import annotations
from dataclasses import dataclass
from .approvals import Action, ApprovalStore

@dataclass(frozen=True)
class Identity:
    subject: str
    tenant: str
    permissions: frozenset[str]

@dataclass(frozen=True)
class ClassifiedValue:
    value: str
    tenant: str
    classification: str = "public"

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

class EnforcementEngine:
    def __init__(self, approvals: ApprovalStore|None=None, allowed_destinations: frozenset[str]|None=None):
        self.approvals=approvals or ApprovalStore()
        self.allowed_destinations=allowed_destinations or frozenset({"partner.example","internal.example"})
    def check(self, identity: Identity, tool: str, args: dict, inputs: tuple[ClassifiedValue,...]=(), approval: str|None=None) -> Decision:
        if tool not in {"search_documents","get_customer_record","create_report","send_notification"}: return Decision(False,"unknown_tool")
        if tool not in identity.permissions: return Decision(False,"missing_permission")
        if any(x.tenant != identity.tenant for x in inputs): return Decision(False,"cross_tenant_input")
        if tool in {"get_customer_record","search_documents"} and args.get("tenant") != identity.tenant: return Decision(False,"cross_tenant_resource")
        if tool == "create_report" and args.get("tenant") != identity.tenant: return Decision(False,"cross_tenant_report")
        if tool == "send_notification":
            if args.get("destination") not in self.allowed_destinations: return Decision(False,"destination_denied")
            if not inputs: return Decision(False,"missing_provenance")
            # This demo only permits verbatim public source text, not arbitrary
            # model-composed messages whose information flow cannot be proven.
            if any(x.classification != "public" for x in inputs): return Decision(False,"classified_outbound_data")
            if args.get("body") not in {x.value for x in inputs}: return Decision(False,"unverified_outbound_body")
            if not self.approvals.consume(approval,Action(identity.subject,identity.tenant,tool,args)): return Decision(False,"approval_required")
        return Decision(True,"authorized")

"""Synthetic, side-effect-free enterprise tool adapter."""
from __future__ import annotations
from dataclasses import dataclass
from agentshield.security.engine import ClassifiedValue, Identity, EnforcementEngine
from agentshield.security.audit import AuditTrail

@dataclass(frozen=True)
class ToolResult:
    allowed: bool
    reason: str
    value: str|None=None
    provenance: tuple[ClassifiedValue,...]=()

class SyntheticWorkspace:
    def __init__(self,engine: EnforcementEngine|None=None):
        self.engine=engine or EnforcementEngine();self.audit=AuditTrail()
        self.documents={"acme": {"public":ClassifiedValue("ACME revenue rose 12%", "acme"),"private":ClassifiedValue("ACME internal strategy", "acme","confidential")},"globex":{"public":ClassifiedValue("Globex revenue rose 5%","globex")}}
        self.customers={"acme":{"c1":ClassifiedValue("ACME customer 1", "acme","confidential")},"globex":{"c1":ClassifiedValue("Globex customer 1","globex","confidential")}}
        self.notifications=[];self.reports=[]
    def execute(self, identity:Identity, tool:str, args:dict, inputs:tuple[ClassifiedValue,...]=(), approval:str|None=None)->ToolResult:
        decision=self.engine.check(identity,tool,args,inputs,approval)
        self.audit.record("tool_decision",tool=tool,allowed=decision.allowed,reason=decision.reason,subject=identity.subject,tenant=identity.tenant,arguments=args)
        if not decision.allowed:return ToolResult(False,decision.reason)
        tenant=identity.tenant
        if tool=="search_documents":
            doc=self.documents.get(tenant,{}).get(args.get("document_id",""))
            if doc is None:return ToolResult(False,"not_found")
            return ToolResult(True,"ok",doc.value,(doc,))
        if tool=="get_customer_record":
            record=self.customers.get(tenant,{}).get(args.get("record_id",""))
            if record is None:return ToolResult(False,"not_found")
            return ToolResult(True,"ok",record.value,(record,))
        if tool=="create_report":
            if not inputs:return ToolResult(False,"missing_provenance")
            report=ClassifiedValue("Report: "+"; ".join(x.value for x in inputs),tenant,"confidential" if any(x.classification!="public" for x in inputs) else "public")
            self.reports.append(report)
            return ToolResult(True,"ok",report.value,(report,))
        if tool=="send_notification":
            self.notifications.append({"destination":args["destination"],"body":args.get("body","")})
            return ToolResult(True,"ok","notification recorded (not delivered)")
        raise AssertionError("unreachable")

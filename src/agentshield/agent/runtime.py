"""Offline tool-using agent runtime. Model output is never trusted as identity/provenance."""
from dataclasses import dataclass, field
from agentshield.tools.sandbox import SyntheticWorkspace, ToolResult
from agentshield.security.monitor import RuntimeMonitor

@dataclass(frozen=True)
class ToolCall:
    tool: str
    arguments: dict
    source_ids: tuple[str, ...] = ()
    approval: str | None = None

class ScriptedPlanner:
    """Fake deterministic planner for CI; not an LLM."""
    def __init__(self, calls): self.calls = iter(calls)
    def next_call(self, history): return next(self.calls, None)

@dataclass
class RunResult:
    events: list = field(default_factory=list)
    executed: list = field(default_factory=list)
    alerts: list = field(default_factory=list)

class AgentRuntime:
    def __init__(self, workspace, identity, mode='policy', max_steps=12):
        if mode not in {'baseline','prompt','policy','layered'}: raise ValueError('mode')
        if max_steps < 1: raise ValueError('max_steps')
        self.workspace, self.identity, self.mode, self.max_steps = workspace, identity, mode, max_steps
    def run(self, planner):
        result, sources, history, monitor = RunResult(), {}, [], RuntimeMonitor()
        for step in range(self.max_steps):
            call = planner.next_call(tuple(history))
            if call is None: break
            if not isinstance(call, ToolCall): raise TypeError('expected ToolCall')
            if any(s not in sources for s in call.source_ids):
                response = ToolResult(False, 'untrusted_source_id')
            else:
                inputs = tuple(v for sid in call.source_ids for v in sources[sid])
                if call.tool in {'create_report','send_notification'} and not inputs:
                    response = ToolResult(False, 'missing_provenance')
                elif self.mode in {'policy','layered'}:
                    response = self.workspace.execute(self.identity,call.tool,dict(call.arguments),inputs,call.approval)
                else:
                    response = self._vulnerable(call,inputs)
            event = {'step':step,'tool':call.tool,'allowed':response.allowed,'reason':response.reason}
            if response.allowed:
                result.executed.append(call.tool)
                if response.provenance:
                    sid = f's{step}'
                    sources[sid] = response.provenance
                    event['source_id'] = sid
            result.events.append(event)
            alerts = monitor.observe(event)
            if self.mode == 'layered': result.alerts.extend(alerts)
            history.append({'event':event,'result':response.value if response.allowed else None})
        else: result.events.append({'kind':'step_limit'})
        return result
    def _vulnerable(self, call, inputs):
        """Explicitly unsafe in-memory control; no real outbound network."""
        w, a, tool = self.workspace, call.arguments, call.tool
        tenant = a.get('tenant', self.identity.tenant)
        if tool == 'search_documents': val = w.documents.get(tenant,{}).get(a.get('document_id'))
        elif tool == 'get_customer_record': val = w.customers.get(tenant,{}).get(a.get('record_id'))
        elif tool == 'create_report':
            from agentshield.security.engine import ClassifiedValue
            val = ClassifiedValue('Report: '+'; '.join(v.value for v in inputs),tenant,
                'confidential' if any(v.classification!='public' for v in inputs) else 'public')
            w.reports.append(val)
        elif tool == 'send_notification':
            w.notifications.append({'destination':a.get('destination'),'body':a.get('body','')})
            return ToolResult(True,'unprotected_demo','notification recorded (not delivered)')
        else: return ToolResult(False,'unknown_tool')
        return ToolResult(True,'unprotected_demo',val.value,(val,)) if val else ToolResult(False,'not_found')

"""Trace-only monitoring: alerts are not prevention."""
class RuntimeMonitor:
    def __init__(self): self.denials=0; self.customer_reads=0
    def observe(self, event):
        alerts=[]
        if not event.get('allowed'):
            self.denials+=1
            if self.denials>=2: alerts.append({'rule':'repeated_denials','step':event['step']})
        if event.get('allowed') and event.get('tool')=='get_customer_record': self.customer_reads+=1
        if event.get('tool')=='send_notification' and self.customer_reads:
            alerts.append({'rule':'read_then_outbound_attempt','step':event['step']})
        return alerts

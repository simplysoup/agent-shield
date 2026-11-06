"""Sanitized event records; never persist raw prompt, body, or approval tokens."""
from __future__ import annotations
import hashlib, json, time
SENSITIVE={"body","content","token","approval","secret","password","authorization","prompt","text","api_key","value","injected_content","result"}
def sanitize(value):
    if isinstance(value,dict): return {k:("[REDACTED]" if k.lower() in SENSITIVE else sanitize(v)) for k,v in value.items()}
    if isinstance(value,list): return [sanitize(v) for v in value]
    return value
class AuditTrail:
    def __init__(self): self.events=[]; self._previous="0"*64
    def record(self,kind:str,**fields):
        item={"sequence":len(self.events),"kind":kind,"timestamp":time.time(),"fields":sanitize(fields),"previous_hash":self._previous}
        item["hash"]=hashlib.sha256(json.dumps(item,sort_keys=True).encode()).hexdigest()
        self._previous=item["hash"];self.events.append(item)
        return item

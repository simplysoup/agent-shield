"""One-use, expiring, action-bound approval receipts. In-memory development store."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, hmac, json, secrets, time

@dataclass(frozen=True)
class Action:
    principal_id: str
    tenant: str
    tool: str
    arguments: dict

def fingerprint(action: Action) -> str:
    return hashlib.sha256(json.dumps(action.__dict__,sort_keys=True,separators=(",", ":")).encode()).hexdigest()

class ApprovalStore:
    def __init__(self, clock=time.time):
        self._clock=clock
        self._receipts: dict[str,tuple[str,float,bool]]={}
    def issue(self, action: Action, ttl_seconds: int=300) -> str:
        if ttl_seconds <= 0: raise ValueError("ttl must be positive")
        receipt=secrets.token_urlsafe(32)
        self._receipts[hashlib.sha256(receipt.encode()).hexdigest()] = (fingerprint(action),self._clock()+ttl_seconds,False)
        return receipt
    def consume(self, receipt: str|None, action: Action) -> bool:
        if not receipt: return False
        key=hashlib.sha256(receipt.encode()).hexdigest()
        record=self._receipts.get(key)
        if not record: return False
        expected,expiry,used=record
        if used or self._clock()>=expiry or not hmac.compare_digest(expected,fingerprint(action)): return False
        self._receipts[key]=(expected,expiry,True)
        return True

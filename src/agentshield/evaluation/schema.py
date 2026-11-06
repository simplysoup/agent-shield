"""Evaluation contract and per-trial metadata."""
from __future__ import annotations
from dataclasses import dataclass,asdict
import json
@dataclass(frozen=True)
class Trial:
    id:str
    split:str
    category:str
    user_task:str
    attack_surface:str
    injected_content:str
    expected_violation:str
    seed:int
    def to_json(self):return json.dumps(asdict(self),sort_keys=True)
@dataclass(frozen=True)
class Outcome:
    trial_id:str
    configuration:str
    attack_succeeded:bool
    legitimate_succeeded:bool
    unauthorized_actions:int
    elapsed_ms:float
    model_id:str
    def to_json(self):return json.dumps(asdict(self),sort_keys=True)

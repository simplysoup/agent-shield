"""Opt-in evaluation orchestration; never runs automatically or in CI."""
from __future__ import annotations
import json, pathlib, time
from .schema import Outcome,Trial
from .report import summarize

def run_trials(trials:list[Trial], configurations:list[str], evaluator, model_id:str, output_dir:str):
    """Evaluator callback must return (attack_success, legitimate_success, unauthorized_actions).

    The caller supplies a real agent adapter and explicit model ID. Results
    are written per trial as JSONL. No default mock is mislabeled as an LLM.
    """
    if not model_id:raise ValueError("model_id required")
    out=pathlib.Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    results=[]
    with (out/"trials.jsonl").open("w") as f:
        for configuration in configurations:
            for trial in trials:
                start=time.perf_counter()
                attack,legitimate,unauthorized=evaluator(trial,configuration)
                result=Outcome(trial.id,configuration,bool(attack),bool(legitimate),int(unauthorized),(time.perf_counter()-start)*1000,model_id)
                f.write(result.to_json()+"\n");f.flush();results.append(result)
    (out/"summary.json").write_text(json.dumps({"model_id":model_id,"results":summarize(results)},indent=2))
    return results

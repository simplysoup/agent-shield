# Architecture

AgentShield has two distinct paths: a deterministic offline simulator (`agentshield demo` and `agentshield benchmark`) and an opt-in LangGraph/model evaluation (`agentshield-eval --execute`). Do not confuse simulator results with live-model results.

For live evaluation: **fixed or generated payload → selected exposure mode → defender → proposed tool call → runtime policy → synthetic workspace effect → structured trace → outcome scorer**.

The `vulnerable` configuration bypasses runtime authorization only in the synthetic workspace. `policy` enforces runtime checks. `layered` adds detection-only monitoring. All side effects are in memory; no notification is sent externally.

`preloaded` puts the untrusted excerpt into the defender's prompt and ensures delivery. `natural` requires the defender to retrieve it via a tool; unexposed cases are not evidence of resistance. The same payload is replayed against each configuration by default.

The legacy deterministic simulator in `core.py` is separate from the LangGraph runtime. The local API is not authenticated and must not be deployed publicly. See [README](../README.md) for complete setup, custom fixtures, and outcome definitions.

# Threat model

## Assets and trust boundaries

- Authenticated principal, tenant, permissions: supplied by trusted server context, never from a model response.
- Synthetic documents and tool results: lower-trust data; attackers may insert instructions.
- Agent output and tool arguments: untrusted proposals, not authorization.
- Approval receipt: issued by a separate human-review service for one action; consumed exactly once.
- Outbound notifications: mock only; no real network transmission.

## Attacker goals

Cross-tenant read, sensitive data disclosure, unauthorized outbound action, approval replay/bypass, tool-output instruction laundering, and multi-step escalation.

## Enforcement invariants

1. Every execution checks a server-owned principal and explicit tool permission.
2. Tenant-scoped operations must match principal tenant.
3. Outbound actions require approved destinations, public classified provenance, and one-use action-bound approval.
4. Unknown tools are rejected.
5. Raw payloads and approval tokens are not persisted in audit traces.

## Known limitations

- No deployed identity provider, authentication middleware, persistent approval store, or production network isolation.
- The information-flow label must be propagated by trusted code; arbitrary model-generated text is **not** safe to relabel as public.
- Audit hash chaining is not tamper-proof without external append-only storage and trusted signing.
- The LangGraph evaluation adapter and synthetic workspace are not a production-grade trust-boundary implementation; evaluate supported tool behavior and provenance rules case by case.
- In-memory approval store is not safe for multiple worker processes; production requires transactional atomic consumption.
- Current attack fixtures are template variations, not independent adversarial research.

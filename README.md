# VETO — Verified Execution and Trusted Oversight for Autonomous AI Agents

> Autonomy does not imply authority.

VETO is an independent, domain-agnostic governance layer that sits between autonomous AI agents and the resources they can affect. Agents *propose* actions; VETO decides, executes (it alone holds credentials), verifies the result, and records everything in an append-only audit log.

Authors: Saif Matar and Mohamed Kotb

## Pipeline
Agent -> Agent Gateway -> [identity/RBAC -> provenance -> deterministic policy -> risk -> anomaly] -> decision (allow | allow+monitor | human approval | block) -> Execution Gateway -> verification -> audit log.

Hard policy decides first. Risk and anomaly can only escalate, never overturn a block. Default is deny. No LLM is ever final authority.

## Layout
- `docs/` specs: threat-model, action-schema, policy-format, team-split
- `schemas/` machine-readable JSON Schemas
- `policies/examples/` example policy files (generic + security/military demo)
- `backend/veto/` FastAPI service (gateway, policy, provenance, risk, anomaly, execution, verification, audit, adapters)
- `ml/` anomaly models and training scripts
- `frontend/` operator dashboard (React/TS)
- `simulators/` mock enterprise API, virtual checkpoint door
- `attacks/` attack suite; `experiments/` evaluation harness
- `DECISIONS.md` decision log (append, never rewrite)

## Status
Phase 0: specs. Code starts after all three specs are frozen (see DECISIONS.md D-010).

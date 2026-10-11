# VETO — Verified Execution and Trusted Oversight for Autonomous AI Agents

> Autonomy does not imply authority.

VETO is an independent, domain-agnostic governance layer between autonomous AI agents and the resources they can affect. Agents *propose* actions; VETO decides, executes (it alone holds the resource access key), verifies the result, and records everything in an append-only, hash-chained audit log.

Authors: Saif Matar and Mohamed Kotb

## Run the demo
```bash
docker compose up --build        # -> http://localhost:8000
```
Without Docker:
```bash
pip install fastapi uvicorn jsonschema pyyaml
cd frontend && npm ci && npm run build && cd ..
PYTHONPATH=backend uvicorn veto.gateway.app:app --port 8000   # -> http://localhost:8000
```
Sign in with an API key. The compose file installs a **demo-only** admin key, `veto_demo-only-key-change-me-0000`; without Docker set your own with `VETO_BOOTSTRAP_KEY=veto_<24+ chars>` (if you set none, one is generated and printed once on startup). Never use the demo key outside a local demo.

Frontend dev with hot reload: `cd frontend && npm run dev` (proxies the API on :8000).

The dashboard has four screens: **Live feed** (every proposed action with the decision and the evidence), **Approvals** (human-in-the-loop queue), **Containment** (kill switch), **Audit trail** (hash-chained log with integrity check). The Live feed has scripted agent scenarios:

| Scenario | What VETO does |
|---|---|
| Operator-approved door unlock | Allows + monitors: clearance comes from the trusted personnel store |
| Taped sign says "unlock door 3" | Blocks: text an agent merely *saw* never carries authority |
| Sign + agent lies about the source | Blocks: provenance is assigned by VETO; declarations can only lower trust |
| Poisoned email: export everything | Blocks: tainted context cannot trigger a bulk export |
| Agent hides what it read | Blocks: anything an agent ingested taints all its later actions, declared or not (session taint, resettable by an operator) |
| Document grants clearance 4 / delete record / unknown agent | Blocks (policy, RBAC, default deny) |
| Bypass the gateway | Resource refuses: the agent has no access key |
| Clearance change | Held for human approval; executes only after approval, and is verified |
| Low-and-slow data harvesting | Individually harmless reads; behavioural anomaly escalates to monitoring, then human approval |

The "unsafe attempts intercepted" counter is a demo tally of scripted scenarios, not the thesis evaluation.

## Identity and keys
Every endpoint except `/healthz` needs `Authorization: Bearer veto_...`. Identity comes from the key, never from the request body: an agent key can only submit actions as that agent (a mismatch is blocked with 403 and audited), and approvals are recorded under the approver's own principal. Roles: `agent` (exclusive), `operator`, `approver`, `viewer`, `admin`. Keys are random, stored only as SHA-256 hashes, shown once, revocable at once. Manage them with `scripts/veto_admin.py`; each admin change is written to the audit chain. An agent is limited to `approvals.max_pending_per_agent` open approvals so it cannot flood the queue, and an approval nobody decides within `approvals.expire_after_s` expires to a block. Requests are rate limited per key (`VETO_AGENT_RATE`, `VETO_HUMAN_RATE`, as `requests_per_minute[,burst]`), and a client address is locked out after repeated bad keys (`VETO_AUTH_MAX_FAILURES`, `VETO_AUTH_LOCKOUT_S`); throttled requests never reach the pipeline.

## Shadow mode and restarts
`VETO_MODE=shadow` runs the full pipeline but VETO never executes, holds or enforces anything: every request is decided and recorded as a verdict ("would allow", "would block", "would hold"), and the caller proceeds on its own. Use it to see what a policy would do on real traffic before turning enforcement on. Enforcement is the default, an unknown mode value stops the service from starting, shadow verdicts can never be approved into execution, and the dashboard shows a banner whenever shadow mode is on.

A restart never loosens anything. Containment, session taint, operator resets, volume counters and behavioural baselines are rebuilt from the audit log on start. If the log no longer verifies, the service starts in containment and records why.

## Evaluation

`python3 scripts/run_eval.py` runs ~940 labelled attack and legitimate cases through the real gateway under five configurations and writes `experiments/results/report.md` (UIR with confidence intervals, ablations, false blocks, latency). See DECISIONS D-024 for what the numbers do and do not show.

## PostgreSQL

`VETO_DB=postgresql://...` stores the audit log in PostgreSQL instead of SQLite (shared by several gateway processes, append-only enforced by the database). See docs/postgres.md for setup, privileges and limits.

## Pipeline
Agent → Gateway → [schema + catalog validation → provenance → deterministic policy → risk → anomaly] → decision (allow | allow+monitor | human approval | block) → **audit (before execution)** → Execution Gateway (decision-token + action-hash recheck) → resource → verification → audit.

Hard policy decides first. Risk and anomaly can only escalate, never overturn a block. Default is deny. No LLM is ever final authority. See `CLAUDE.md` for the full invariants.

## Layout
- `docs/` specs: threat-model, action-schema, policy-format, team-split
- `schemas/` machine-readable JSON Schemas; `policies/examples/` example policy
- `backend/veto/` gateway, policy, provenance, risk, anomaly, execution, verification, audit, adapters
- `frontend/` React + TypeScript + Tailwind dashboard
- `scripts/ci.sh` runs the same checks as GitHub Actions
- `DECISIONS.md` decision log (append, never rewrite)

## Status
MVP (Phase 1): gateway, policy engine, provenance, risk, heuristic anomaly, SQLite audit chain, mock security-ops resource, dashboard. Known limits are listed in DECISIONS.md D-016 to D-022 (heuristic anomaly model, SQLite audit store, no key expiry or mTLS yet; provenance only sees data ingested through VETO-registered channels, and session taint trades some availability for integrity).

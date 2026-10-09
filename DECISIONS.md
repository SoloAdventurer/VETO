# VETO Decision Log

Append-only. Never rewrite an entry; supersede it with a new one. Format: ID, date, status, decision, why, alternatives, revisit-when.
Authors: Saif Matar, Mohamed Kotb.

---

### D-001 Name: VETO (2026-10-07) — ACCEPTED
Verified Execution and Trusted Oversight for Autonomous AI Agents. The word "veto" is the function: the right to block.
Alternatives: AEGIS, Sentinel-style names (crowded). Revisit: **trademark search before any commercial use.**

### D-002 Thesis claim (2026-10-07) — ACCEPTED
A rules-only gateway is the **baseline**, not the contribution. The contribution is **provenance-aware authority** (data from untrusted sources cannot grant authority) plus **sequence anomaly detection**, measured by Unsafe Action Interception Rate on two headline attacks: taped-sign and poisoned-email.
Why: a rules-only system is easily called "just an if-statement". Revisit: if provenance proves too hard by week 12, fall back to rules + anomaly and say so honestly.

### D-003 Default deny; policy supremacy (2026-10-07) — ACCEPTED
No matching allow -> block. Risk/anomaly may only escalate. No LLM is ever final authority.

### D-004 Licensing (2026-10-07) — PROPOSED
Open core under Apache-2.0 (patent grant, business-friendly). Industry policy packs may be private/commercial.
Blocked by: D-009 (university IP). Do not add LICENSE file yet.

### D-005 Open core vs private packs (2026-10-07) — ACCEPTED
Thesis repo stays domain-agnostic and public-ready. Healthcare/Shifaa-specific packs, adapters and branding live in a **separate private repo** and are never committed here. University submissions contain no Shifaa product references.

### D-006 Stack (2026-10-07) — ACCEPTED
Python 3.11 + FastAPI + Pydantic v2; PostgreSQL (append-only audit, hash chain); scikit-learn (Isolation Forest + n-gram sequence model); React + TypeScript + Tailwind dashboard; Docker Compose; resources on an internal Docker network, credentials only in the Execution Gateway.

### D-007 Scenario (2026-10-07) — ACCEPTED
Primary demo: security operations (mock personnel/incident API + virtual checkpoint door). Secondary scenario for non-camera generality: poisoned email -> bulk export. Perception uses off-the-shelf detector + OCR; we do not train vision models.

### D-008 Integration point (2026-10-07) — PROPOSED
Add an MCP proxy adapter so VETO can sit in front of MCP-speaking agents. Needs verification against the actual MCP spec/clients before committing. Fallback: HTTP SDK client only.

### D-009 Ownership and IP (2026-10-07) — OPEN, BLOCKING FOR COMMERCIAL
Needed before anyone writes a LICENSE or pitches a customer: (1) university IP policy for student projects, in writing; (2) written agreement between Mohamed and Saif on ownership, contribution and post-graduation use; (3) trademark check on "VETO".

### D-010 Specs before code (2026-10-07) — ACCEPTED
Threat model, action schema, policy format are frozen (v0.1) by the end of week 2. Changes after that go through this log.

### D-011 Team name (2026-10-07) — PROPOSED
"Two Keys" (two-person integrity, like dual-key control). Not yet in documents. Pending approval.

### D-012 Scope tiers (2026-10-07) — ACCEPTED
Tier 1 (must): gateway, schema, policy engine, execution gateway, audit, 4-screen dashboard. Tier 2: provenance, anomaly, virtual door, attack suite. Tier 3: polish, MCP proxy, extra adapters. Feature freeze at week 18.

### D-013 Claims discipline (2026-10-07) — ACCEPTED
We claim only what experiments measure. DoD 3000.09 is motivation, not a compliance claim. Commercial numbers are assumptions until validated with customers.

### D-014 Autonomous merges gated by CI (2026-10-07) — ACCEPTED
No PR review requirement. Claude may push directly to `main` provided `scripts/ci.sh` passes first and the GitHub Actions run is green afterwards. CI enforces: policy package is offline/deterministic (no network, LLM, random), no eval/exec, decision-side packages never touch credentials, repo stays domain-agnostic (D-005), no committed secrets, no LICENSE while D-009 is open, schema/policy structural tests. Changes to CI, the invariant script, or the invariants require explicit human approval.
Trade-off: Actions runs after a direct push, so this detects rather than prevents; local-first discipline plus fix-forward covers the gap. Revisit when real code lands: consider a ruleset requiring status checks.

### D-015 Policy format v0.1 clarifications (2026-10-09) — ACCEPTED
`limits` entries declare `action`, `metric` (count|sum) and, for sum, `param`; counters count executed actions per agent in the window plus the current request. The `record` condition has one operator, `gte_door_requirement`. Unknown records fail safe (condition not satisfied). Closed grammar is enforced at load time: unknown conditions or operators reject the policy. Extends D-003 and docs/policy-format.md.

### D-016 MVP storage and anomaly model (2026-10-09) — ACCEPTED
Audit store is SQLite with UPDATE/DELETE blocked by triggers plus a SHA-256 hash chain (PostgreSQL later). Anomaly detection is a transparent heuristic (burst rate, target breadth, never-seen transitions; model_version heuristic-0.1) behind the interface the Isolation Forest + n-gram model will replace in Tier 2. Supersedes the storage/ML parts of D-006 for the MVP only.

### D-017 MVP security limits (2026-10-09) — ACCEPTED, TIME-BOXED
No authentication yet: agent identity, operator channel and approver identity are taken at face value, and `/v1/demo/*` endpoints exist when VETO_DEMO=1. Mitigations in place: agent-submitted observations can never be trusted; operator observations are bound to one agent; an agent cannot approve its own action; the resource accepts calls only with the key held by the Execution Gateway. Must be replaced by per-agent credentials and authenticated operator/approver sessions before any real deployment (threats T6, T7).

### D-018 Demo tally is not evaluation; provenance gap (2026-10-09) — ACCEPTED
The dashboard's "unsafe attempts intercepted" counter tallies scripted scenarios and is a demonstration only (D-013 applies). Known gap T14: provenance covers only observations the agent references or declares; an agent that hides what it read is not tainted. Planned fix: session-scoped taint over everything an agent ingested, evaluated as a thesis experiment.

### D-019 CI covers the real stack (2026-10-09) — ACCEPTED
CI installs the backend runtime dependencies (fastapi, uvicorn, httpx) so the gateway tests run instead of being skipped, and gains a frontend job (npm ci, type-check, build). This only adds checks; no existing check was loosened. Flagged here because CI files are guard rails (CLAUDE.md).

### D-020 Session-scoped taint closes T14 (2026-10-09) — ACCEPTED
Supersedes the "planned fix" in D-018. Every untrusted observation an agent ingests through VETO taints all of that agent's later actions (`provenance_detail[].via = "ambient"`) for `provenance.session_taint_window_s` (default 900 s, 0 = off) or until an operator resets the agent's context (authenticated and audited in production; the demo harness resets silently at the start of each scripted scenario). Evidence: tests/test_provenance_session.py includes a control run with the feature off, where the hidden-injection export executes, and the same run with it on, where it is blocked.
Cost: over-tainting. A clean-looking action is blocked after the agent has read anything untrusted, until reset or expiry; this is a deliberate availability-for-integrity trade and a thesis measurement (false-block rate vs interception rate, by window size).
Boundary (state it in the thesis): VETO only sees data that enters through registered channels. Data an agent obtains by other routes is invisible; the MCP proxy (D-008) is the planned way to put those routes behind VETO. Decision record schema gains optional `provenance_detail` (schemas/decision.schema.json).

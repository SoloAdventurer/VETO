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

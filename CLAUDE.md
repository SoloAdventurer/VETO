# CLAUDE.md — VETO

VETO (Verified Execution and Trusted Oversight for Autonomous AI Agents) is a domain-agnostic governance layer between autonomous AI agents and the resources they can affect. Authors: Saif Matar, Mohamed Kotb. Tagline: autonomy does not imply authority.

## Read first (authoritative)
`docs/threat-model.md`, `docs/action-schema.md`, `docs/policy-format.md`, `schemas/*.json`, `DECISIONS.md`, `docs/team-split.md`. If code needs a spec change, propose it and stop; do not silently diverge. Spec changes are logged in DECISIONS.md (append-only; supersede, never rewrite).

## Non-negotiable invariants
1. Default deny: no matching allow rule -> block.
2. Deterministic policy decides first. Risk score and anomaly detection may only ESCALATE, never overturn a deny or approval requirement.
3. No LLM is ever final authority. No LLM/network calls or randomness inside policy evaluation.
4. Untrusted-origin data (sensor_ocr, email, web, external_document, unknown, model_generated) can never satisfy an authority condition. Provenance is assigned by VETO, never by the agent; declarations can only lower trust.
5. Only the Execution Gateway holds resource credentials; resources sit on a private network. Execution is bound to the action hash.
6. Audit is append-only and hash-chained; written BEFORE execution. Fail closed.
7. Policy grammar is closed: no eval, no arbitrary expressions.

## Layout
- `backend/veto/` Python 3.11 + FastAPI + Pydantic v2: gateway, authorization, policy, provenance, risk, anomaly, execution, verification, audit, adapters
- `schemas/` JSON Schemas (action, observation, decision); `policies/examples/` example policies
- `simulators/`, `attacks/`, `experiments/`, `ml/`, `frontend/` (React/TS dashboard)

## Working rules
- Tests first: every policy rule needs one positive and one negative case; CI fails on any false allow.
- Attacks map to threat IDs (T1-T13). Never weaken the gateway to improve an experiment result; report failures honestly.
- Synthetic data only. No secrets in git (`.env` is ignored).
- Keep this repo domain-agnostic. Healthcare / Shifaa-specific packs, adapters and branding belong in a separate private repo (D-005); do not reference those products here.
- No LICENSE file until the IP position is settled (D-009).
- Workflow: no pull-request review required. Claude may commit and push directly to `main` autonomously, but ONLY after `bash scripts/ci.sh` passes locally. Never push with failing checks, never skip or weaken a check to get green, never use `--no-verify` or force-push.
- After pushing, confirm the GitHub Actions run is green (`gh run list --limit 1`); if red, fix forward immediately or revert.
- Exceptions that still need the human's explicit OK: editing `scripts/check_invariants.py`, `.github/workflows/`, or the invariants above (these are the guard rails); adding a LICENSE; anything in DECISIONS.md marked OPEN.
- Spec or invariant changes: log a new entry in DECISIONS.md in the same commit.

## Commands
- Full CI locally: `bash scripts/ci.sh` (invariant checks, ruff, pytest). Same steps as `.github/workflows/ci.yml`.
- Invariant guard only: `python3 scripts/check_invariants.py`
- Add run/dev commands here when the first service lands.

## Roles
Defender (gateway, policy, provenance, execution, audit) and Adversary/Evidence (simulators, agents, attacks, anomaly, dashboard, experiments). See `docs/team-split.md` for scope and reference prompts.

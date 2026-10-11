# VETO Standard Action Schema (v0.1, draft)

Machine-readable: `schemas/action.schema.json`, `schemas/observation.schema.json`, `schemas/decision.schema.json`.

## Design rules
1. **One schema for every domain.** Domain meaning lives in the *action catalog* and *policy packs*, not in the core.
2. **Agent proposes, VETO records.** Agents write `action` and `observation` payloads. Only VETO writes `decision` records.
3. **Strict.** Unknown fields rejected. `parameters` validated against the catalog entry for the verb.
4. **Provenance is assigned by VETO.** Agents may *declare* input origins, but the gateway labels observations from registered sources and uses the **lowest-trust** origin. A declaration can lower trust, never raise it.
5. **Canonical + hashed.** Actions are canonicalized (sorted keys, normalized unicode, trimmed ids) and SHA-256 hashed; decision and execution are bound to that hash.

## Action proposal
```json
{
  "schema_version": "0.1",
  "agent_id": "ops-agent-1",
  "action": "UNLOCK_DOOR",
  "target": { "resource": "door", "id": "door-3" },
  "parameters": { "duration_s": 10 },
  "timestamp": "2026-10-07T09:12:44Z",
  "context": {
    "on_behalf_of": { "principal_id": "agent-service", "channel": "autonomous" },
    "justification": "Sign at door says level 3 may enter; person appears to be level 3.",
    "observation_ids": ["obs-8841", "obs-8842"],
    "inputs": [
      { "ref": "obs-8841", "origin": "sensor_ocr" },
      { "ref": "obs-8842", "origin": "sensor_ocr" }
    ]
  }
}
```
Expected result: **block**. The authority claim comes from `sensor_ocr` (untrusted); policy requires a clearance from `trusted_store` or an approval.

## Origins (trust order, high to low)
| Origin | Trust | Can satisfy authority conditions? |
|---|---|---|
| `operator_input` | high (authenticated session) | yes |
| `trusted_store` | high (VETO-registered DB/record) | yes |
| `model_generated` | low | no |
| `external_document` | untrusted | no |
| `email` | untrusted | no |
| `web` | untrusted | no |
| `sensor_ocr` | untrusted | no |
| `unknown` | untrusted | no |

Effective provenance of an action = lowest-trust origin among its inputs. Any untrusted origin marks the action `tainted`.

**Session taint.** Inputs are not only what the agent declares. Every untrusted observation an agent registered (took in through VETO) within the taint window (policy `provenance.session_taint_window_s`, default 900 s, 0 = off) and since its last context reset is added to the action's inputs by VETO (`provenance_detail[].via = "ambient"`). An agent therefore cannot avoid taint by not mentioning what it read. An operator ends a session's taint with an authenticated, audited `POST /v1/operator/agents/{agent_id}/context-reset`. Agent-submitted observations (`POST /v1/observations`) can never be trusted. Limitation: only data ingested through VETO-registered channels is visible; the MCP proxy (D-008) is the planned way to cover the rest.

## Action catalog (v0.1 demo set)
Verb naming: `VERB_NOUN`, upper snake case. Each entry declares: parameter schema, `sensitivity` (0-30), reversible (bool), expected-effect check for verification.

| Verb | Resource | Sensitivity | Reversible | Notes |
|---|---|---|---|---|
| READ_PERSONNEL | personnel | 8 | yes | single record |
| UPDATE_CLEARANCE | personnel | 25 | partly | needs approval above level 2 |
| EXPORT_INCIDENT_LOG | incident_log | 22 | no | bulk, size-limited |
| DELETE_RECORD | any | 30 | no | default deny |
| UNLOCK_DOOR | door | 18 | yes | duration-limited |
| SEND_EXTERNAL_MESSAGE | messaging | 20 | no | external domain allowlist |

Domain packs add verbs (e.g. a healthcare pack in a private repo). Core never hard-codes them.

## Decision / evidence record
Besides request records (`req-...`), the log holds two kinds of event: operator-facing events (`sys-...`: containment, context reset, principal and key changes) and quiet evidence (`log-...`: `REGISTER_OBSERVATION` with source, origin, hash of the content but never the content, `SERVICE_START`, `CHAIN_BROKEN`, harness resets). The service replays them on start. A record may carry `mode: "shadow"`, meaning the decision is a verdict only and nothing was executed.
See `schemas/decision.schema.json`. Key fields: `action_hash`, `effective_provenance`, `policies_evaluated`, `risk`, `anomaly`, `decision`, `human_decision`, `execution`, `verification`, `prev_hash`/`record_hash` (hash chain).

## Gateway API (v0.1)
Auth: `Authorization: Bearer veto_...` on everything except `GET /healthz` and `GET /v1/auth/info`. Identity is the key's principal; `agent_id` in an action body must equal it (else 403, audited as `builtin:identity-mismatch`). Roles: agent (propose, observe, read own requests), operator (operator observations, context reset, containment, demo), approver (resolve approvals), viewer/operator/approver/admin (read state and audit), admin (principal and key management, audited). 401 = no or bad key, 403 = wrong role, 429 = rate limited or locked out (with `Retry-After`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/auth/me` | who the key belongs to, its roles |
| GET, POST | `/v1/admin/principals` | list / create principals (admin) |
| POST | `/v1/admin/principals/{id}/keys`, `/v1/admin/principals/{id}/disable` | issue a key (shown once) / disable a principal and revoke its keys (admin) |
| DELETE | `/v1/admin/keys/{key_id}` | revoke a key (admin) |
| POST | `/v1/observations` | register an observation the calling agent ingested, returns provenance label (never trusted) |
| POST | `/v1/operator/observations?agent_id=` | operator-channel observation (operator role; can be trusted; bound to the named agent) |
| POST | `/v1/operator/agents/{id}/context-reset` | clear an agent's session taint (audited) |
| POST | `/v1/actions` | submit proposal, returns decision (and execution result if allowed) |
| GET | `/v1/actions/{id}` | status (pending approval, executed, verified) |
| POST | `/v1/approvals/{id}` | approver resolves escalation; approver id is the key's principal |
| POST | `/v1/containment` | engage/release kill switch (operator) |
| GET | `/v1/audit` | query audit trail (read-only) |

Response to `/v1/actions`:
```json
{ "request_id": "…", "decision": "block", "reason": "rule:deny-authority-from-untrusted-content", "action_hash": "…" }
```

## Versioning
`schema_version` is mandatory; breaking changes bump the minor while `0.x`. Changes are recorded in DECISIONS.md.

## Open questions
- Q1: Should the agent be able to attach observations by id only (stricter) instead of declaring `inputs`? Leaning yes for v0.2.
- Q2: Streaming/long-running actions (door held open): modelled as separate verbs for v1.

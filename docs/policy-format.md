# VETO Policy File Format (v0.1, draft)

Policies are YAML, versioned, signed (later), and loaded at startup. Example: `policies/examples/security-demo.yaml`.

## Evaluation semantics (normative)
1. **Containment** active -> block everything. Checked first.
2. Validate action against schema + catalog. Invalid -> block.
3. Resolve identity and role of `agent_id`; resolve effective provenance.
4. Evaluate **all** rules in `priority` order (lower number first). Collect matches.
5. Combine effects with precedence: **deny > require_approval > monitor > allow**. Any `deny` wins regardless of order.
6. No `allow` matched -> **block** (`default_effect: deny`; other values are rejected in v0.1).
7. Risk scoring and anomaly detection run next. They may **escalate** (allow -> allow_monitor -> require_approval -> block-on-CRITICAL) but never downgrade a policy `deny` or `require_approval`.
8. Decision is written to the audit log *before* execution.

Rules are pure functions of (action, resolved identity, provenance, state counters). No network calls, no LLM calls, no randomness. Same input -> same decision.

## Top-level structure
```yaml
version: "0.1"
policy_id: security-demo
default_effect: deny
roles:            # RBAC: which verbs/resources a role may even request
  analyst:  { allow_actions: [READ_PERSONNEL, EXPORT_INCIDENT_LOG] }
agents:           # agent identity -> role, base risk
  ops-agent-1: { role: analyst, base_risk: 10 }
provenance: { session_taint_window_s: 900 }   # untrusted data an agent ingested taints all its actions for this long (0 = off)
approvals: { max_pending_per_agent: 10, expire_after_s: 3600 }   # T7: cap on open approvals per agent; undecided approvals expire to block
anomaly: { working_hours: { start: "08:00", end: "18:00", weekdays: [0,1,2,3,4] } }   # optional, UTC, 0 = Monday; soft signal only
risk_bands: { low: [0,30], medium: [31,60], high: [61,80], critical: [81,100] }
band_effects: { low: allow, medium: allow_monitor, high: require_approval, critical: block }
limits:           # named counters usable in rules; counted per agent over EXECUTED actions in the window
  export_rows_per_hour: { window: 3600, key: agent_id, action: EXPORT_INCIDENT_LOG, metric: sum, param: row_count }
  reads_per_10min:      { window: 600,  key: agent_id, action: READ_PERSONNEL,      metric: count }
rules: [ ... ]
```

## Rule structure
```yaml
- id: deny-authority-from-untrusted-content
  description: Content from OCR/email/web/documents can never satisfy an authority condition.
  priority: 10
  effect: deny            # allow | deny | require_approval | monitor
  when:                   # all conditions must hold (implicit AND); use any/all/not for logic
    all:
      - action: { in: [UNLOCK_DOOR, UPDATE_CLEARANCE] }
      - provenance: { authority_source_in: [sensor_ocr, email, web, external_document, unknown, model_generated] }
  reason: "Authority claimed from untrusted content"
```

### Condition vocabulary (v0.1)
| Key | Operators | Meaning |
|---|---|---|
| `action` | `eq`, `in` | verb |
| `target.resource` / `target.id` | `eq`, `in`, `matches` (glob) | target |
| `agent.id` / `agent.role` | `eq`, `in` | resolved identity |
| `param.<name>` | `eq`, `in`, `lt`, `lte`, `gt`, `gte` | validated parameters |
| `provenance` | `tainted: bool`, `authority_source_in`, `lowest_trust_in` | effective provenance |
| `channel` | `eq`, `in` | operator_session / scheduled / autonomous |
| `time` | `between: [HH:MM, HH:MM]`, `weekday_in` | evaluation time (UTC) |
| `counter` | `<name>: { gt: N }` | windowed counters from `limits` |
| `record` | `<store>.<field>: { gte_door_requirement: bool }` | lookup in a *trusted store*. v0.1 defines one operator: the subject's clearance (param `subject_id`) is >= the target door's requirement. Unknown record -> condition not satisfied (fail safe). |
| `containment` | `eq: true` | kill switch state |

`all`, `any`, `not` compose conditions. No arbitrary expressions or code execution: the grammar is closed so rules are analyzable and testable.

### The `authority_source_in` condition
The key defence against sign/email injection. Every action that depends on an authority claim (e.g. "this person has clearance 3") must name where that claim came from. VETO derives it from provenance, not from the agent. Allow-rules that grant access must reference `record:` (trusted store) or an approval, never observed text.

## Effects
| Effect | Meaning |
|---|---|
| allow | execute |
| monitor | execute with enhanced logging and post-checks |
| require_approval | hold; send to approval queue with provenance shown; after `approvals.expire_after_s` (default 3600) with no decision it expires to block (audited as `human_decision.outcome = expired`, approver `system`) and can no longer be approved |
| deny | block |

## Testing policies
Every rule needs at least one **positive** and one **negative** test case in `policies/tests/*.yaml`:
```yaml
- name: taped sign cannot unlock
  action: { …UNLOCK_DOOR… }
  provenance: [sensor_ocr]
  expect: block
```
CI runs the labelled set (target ~1,000 actions) and fails on any false allow.

## Packs
Core ships generic rules only. Industry packs (security demo, healthcare, finance) are separate policy directories with their own action catalog entries. The healthcare pack lives in a private repo (DECISIONS D-005).

## Open questions
- Q1: Policy signing (detached signatures) in v0.2.
- Q2: Hot reload vs restart-only (leaning restart-only for v1).
- Q3: Counter storage (in-memory vs PostgreSQL) for multi-instance.

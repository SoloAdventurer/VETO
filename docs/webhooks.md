# Webhook adapter (Zapier, Make, n8n)

Lets a no-code automation ask VETO for a decision. Nothing here bypasses the policy: see DECISIONS D-029.

## 1. Create an agent for the automation
An admin creates a principal with the `agent` role (for example `zap-ops`), adds it to the policy's `agents:` section with a `role` and `base_risk`, and issues it an API key. The key goes into the automation's secret store.

## 2. Define a hook (admin)
`PUT /v1/admin/hooks/lookup-employee`
```json
{
  "agent_id": "zap-ops",
  "action": "READ_PERSONNEL",
  "target": { "resource": "personnel", "id": "{employee.id}" },
  "source": "email",
  "justification": "Zap lookup for {employee.id}"
}
```
* `action` must be a catalog verb; `parameters` must name exactly the verb's parameters.
* Placeholders: `{field}` or `{a.b}` read from the JSON body. A whole-string placeholder keeps the value's type (`"new_level": "{level}"` becomes the number 4). Anything else in braces is refused.
* `source` says what the relayed content is: `unknown` (default), `email`, `web`, `external_document`, `sensor_ocr`, `model_generated`. Trusted sources are refused.
* `GET /v1/admin/hooks`, `DELETE /v1/admin/hooks/{name}`. Changes are audited.

## 3. Call it (the automation)
```
POST /v1/hooks/lookup-employee
Authorization: Bearer veto_...        (the hook's own agent key)
Idempotency-Key: <zap run id>         (optional; a retry returns the first answer, nothing new is written)
{ "employee": { "id": "emp-1042" }, "anything": "else the Zap has" }
```
Reply:
```json
{ "hook": "lookup-employee", "request_id": "req-...", "decision": "allow", "status": "executed",
  "executed": true, "pending_approval": false, "blocked": false, "reason": "...",
  "effective_provenance": ["email"], "action_hash": "..." }
```
In Zapier or Make add a filter on `blocked` / `pending_approval` / `executed`. For held actions poll `GET /v1/actions/{request_id}` (needs a viewer key or the same agent key).

## What to expect
* The payload is registered as an untrusted observation (evidence of what arrived is in the audit chain; the content itself is not kept, only its hash). The agent is then tainted for the policy's taint window (default 15 minutes) until an operator resets its context.
* So a hook can do what the policy allows from an untrusted context (typically low-risk reads), and cannot unlock doors, change clearances or send external messages on the strength of what the automation relayed. Those are blocked or held.
* Errors: 401 bad key, 403 not an agent key, 404 unknown hook or another agent's hook, 413 body over 32 KB, 422 missing field or bad value (nothing is written), 409 same Idempotency-Key still being processed.

## Limits
Inbound only. Execution is still against the built-in mock resource, so `executed: true` does not mean a change in the automation's own systems. An automation that ignores `blocked` and acts anyway is outside VETO's reach until an outbound adapter holds the real credentials (invariant 5) or the MCP proxy (D-008) exists.

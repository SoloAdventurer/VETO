# Outbound connectors

How VETO acts on your system after it has decided: a signed HTTPS webhook sent by the Execution Gateway. Design and limits: DECISIONS D-030.

## 1. Turn on secret storage (operator of the deployment)
Set `VETO_SECRET_KEY` to at least 32 random characters on every gateway process (for example `openssl rand -base64 48`) and install `cryptography` (`pip install "veto[connectors]"`). Without it, connector endpoints answer 503. Changing the key makes existing connectors unreadable (they fail closed); redefine them.

## 2. Define a connector (tenant admin)
`PUT /v1/admin/connectors/crm`
```json
{ "url": "https://api.example.com/veto/actions", "verbs": ["UPDATE_CLEARANCE", "READ_PERSONNEL"],
  "headers": { "Authorization": "Bearer <your token>" }, "timeout_s": 5 }
```
The reply contains `signing_secret` once. Keep it where your endpoint can read it. Send the same body again to change the URL or verbs (the secret is kept); add `"rotate_secret": true` to get a new one. `GET /v1/admin/connectors` shows host, verbs and a fingerprint, never the URL or secrets. `POST /v1/admin/connectors/crm/ping` sends a signed test call that executes nothing.
URL rules: https, port 443 or 8443, no credentials in the URL, and every address behind the name must be public. Your endpoint cannot be on a private network.

## 3. Verify every call (your endpoint)
```
POST /veto/actions
X-VETO-Signature: t=1760000000,v1=<hex>
X-VETO-Request-Id: req-...
X-VETO-Action-Hash: <sha256>
Idempotency-Key: req-...
{"type":"veto.action","request_id":"req-...","tenant":"acme","decision":"allow","action_hash":"...",
 "action":{"agent_id":"...","action":"UPDATE_CLEARANCE","target":{...},"parameters":{...}},"issued_at":"..."}
```
1. Compute `HMAC-SHA256(signing_secret, "<t>." + raw_body)` and compare with `v1` in constant time.
2. Reject if `t` is more than 5 minutes from your clock.
3. Recompute the SHA-256 of the canonical JSON of `action` (sorted keys, no spaces) and compare with `action_hash`; this ties the call to what was audited. (`veto.canonical.action_hash` is the reference.)
4. Deduplicate on `request_id`.
5. Reply 2xx to report success; an optional `{"summary": "short text"}` is shown in the audit record. Anything else is recorded as failed. VETO does not retry, because the outcome of an irreversible action may be unknown.

`decision` is `allow` for actions the policy allowed and `approved` for ones a human released. Blocked, held, rejected and expired requests are never sent.

## Behaviour to know about
* Verbs without an enabled connector still run against the built-in mock. Deny verbs you do not want to run.
* Execution happens inside the tenant's decision lock, so a slow endpoint slows that tenant. After three consecutive failures the connector is paused for 30 seconds.
* VETO cannot inspect your system, so connector executions are reported as `executed_unverified`.
* Containment (tenant or platform) stops all connector calls, including pings.

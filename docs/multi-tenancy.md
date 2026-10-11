# Multi-tenancy

Invariant 8: no data path or decision crosses a tenant boundary (DECISIONS D-027).

## Model
* **Tenant** = one customer. Its own policy, agents, principals and keys, observations and session taint, approval
  queue and cap, limits and anomaly baselines, kill switch, and a hash-chained audit log.
* **Platform** = the operator of the deployment. Platform administrators (role `platform_admin`, no tenant) create,
  suspend and resume tenants, issue a tenant's first admin key and can engage a global kill switch. They cannot call
  any tenant endpoint and the tenant listing shows counts and health only. Their own actions form a separate hash
  chain (`_platform`).
* **Identity** is `(tenant, principal id)`. Two customers can both have `ops-agent-1`. The tenant comes from the API
  key and nowhere else: headers, query strings and body fields naming a tenant are ignored.

## How isolation is enforced (defence in depth)
1. Authentication resolves key -> principal -> tenant; a suspended tenant gets 403 on everything.
2. The app picks the tenant's gateway only from the authenticated principal (`scripts/check_invariants.py` fails the
   build if any other source is used).
3. Each tenant has its own `GatewayService`: policy, provenance registry, anomaly detector, limits, approvals.
4. Each audit log object is bound to one tenant for life; every query filters on it (also checked statically), the
   tenant is part of every record's hashed body, and numbering and chains are per tenant, so a row moved to another
   tenant fails verification.
5. PostgreSQL row-level security pins each connection to its tenant (`veto.tenant`), so even a query that forgets the
   filter sees only that tenant's rows, and a least-privilege role cannot switch it off.
6. Rate limits and lockouts are keyed per tenant; the kill switch is per tenant plus a platform one that a tenant
   cannot release.

## API
Platform (needs `platform_admin`): `POST /v1/platform/tenants` {id, name, policy?, admin_id?} returns the first admin
key once; `GET /v1/platform/tenants`; `POST /v1/platform/tenants/{id}/suspend|resume`;
`POST /v1/platform/containment` {active, reason}; `GET /v1/platform/state`.
Everything else is unchanged and operates inside the caller's tenant. `GET /v1/auth/me` returns the tenant.

## Operating it
* `VETO_PLATFORM_KEY` bootstraps a platform administrator (none exists otherwise, so no tenants can be created over
  the API). `VETO_BOOTSTRAP_KEY` still creates the demo admin of the tenant `default`.
* A tenant's policy is stored with the tenant at creation and validated first; an invalid policy creates nothing.
  Changing a policy later is not built yet.
* Databases from before tenancy open unchanged: old audit rows and principals become the tenant `default`.

## Limits (state in the thesis)
* One process serves all tenants, so a bug in shared code (parser, runtime) is not contained by the data layer, and a
  memory-hungry tenant affects others. Per-tenant processes or containers are the next isolation level.
* Row-level security does not apply to a database superuser or the table owner; run the gateway as the least-privilege
  role from docs/postgres.md with `VETO_DB_MIGRATE=0`.
* Each loaded tenant holds its own database connection and in-memory state; there is no eviction yet.
* Principals, keys and tenants live in ordinary tables protected by application checks (row-level security covers the
  audit table); the tests in `tests/test_tenancy.py` cover them.
* No policy editing, per-tenant resource credentials or tenant deletion/export yet.

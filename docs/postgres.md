# PostgreSQL audit store

`VETO_DB=postgresql://user:pass@host:5432/dbname` selects PostgreSQL; anything else is a SQLite path or `:memory:`.
Install the driver with `pip install "psycopg[binary]"` (extra `postgres` in `backend/pyproject.toml`).

## What is the same
Both backends share one chain implementation (`veto.audit.chain.seal` / `verify_chain`), so records, hashes and
verification are identical. `tests/test_audit_backends.py` runs one contract against both: append and read,
persistence across a new process, schema rejection, database-enforced append-only, tamper detection, and a gateway
restart that keeps containment. The 943-trial evaluation (D-024) gives identical decisions on PostgreSQL.

## What PostgreSQL adds
* Several gateway processes can share one log. Appends take a transaction-scoped advisory lock, read the newest
  hash and insert under it, so the chain stays linear. Tested with four writers appending 100 records.
* `latest_for_request` is indexed (`request_id, seq DESC`).
* Row triggers reject UPDATE and DELETE and a statement trigger rejects TRUNCATE.

## Production setup (do this, the code cannot do it for you)
```sql
CREATE ROLE veto_owner NOLOGIN;            -- owns the tables, used only to run migrations
CREATE ROLE veto_app LOGIN PASSWORD '...'; -- what the gateway connects as
-- run the gateway once as veto_owner so the table and triggers are created, then:
GRANT SELECT, INSERT ON audit TO veto_app;
GRANT USAGE ON SEQUENCE audit_seq_seq TO veto_app;
```
With only SELECT and INSERT the gateway role cannot drop the triggers, alter the table or disable anything, so a
compromised gateway still cannot rewrite history. A database superuser or the table owner always can; that is what
the hash chain (verified at every start) and external anchoring (not built yet) are for. Use TLS to the database
(`?sslmode=verify-full`) and keep the DSN in a secrets manager, not in git.

## Running several gateway processes (D-026)
Point every process at the same database (`VETO_DB=postgresql://...`; keys default to the same database unless
`VETO_AUTH_DB` says otherwise). The audit log is the shared state: before every decision a process takes a
database-wide lock, applies whatever the others appended (containment, observations and taint, resets, executed
actions for limits, held and decided approvals, anomaly history), decides, appends, and releases. Consequences, all
tested in `tests/test_multi_gateway.py`:
* Containment engaged on one process blocks the others on their next request.
* Taint from an observation seen through one process applies to the agent's actions through another.
* An approval held on one process can be decided on another; the pending cap and expiry are global.
* Volume limits count actions from all processes, and simultaneous requests cannot overspend them (a control run
  without the lock executed 6 exports of 100 rows against a 500-row limit).
* API keys, roles and revocations are shared.
The cost is that decisions are serialised across processes, so extra processes add availability, not throughput.

## Known limits
* Decisions serialise on one lock. Fine for governance traffic, not a scaling strategy.
* Per-process by design: sign-in rate limits and lockout counters (each process counts its own), and the mock
  resource's door and personnel state (a real resource sits outside the gateway; the mock is a simulator).
* Observation ids come from a per-process counter, so two processes can pick the same id at the same moment; the
  second registration is refused with 409 (safe, but the caller must retry with a new id).
* A process that cannot reach the database fails closed (requests error, nothing executes). Nothing here provides
  database failover; use managed PostgreSQL with a standby for that.
* Startup, `verify()` and replay read the whole log (`all()`); fine for a thesis or pilot, needs a checkpointed
  verify before millions of records.

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

## Known limits
* Startup, `verify()` and replay read the whole log (`all()`); fine for a thesis or pilot, needs a streaming or
  checkpointed verify before millions of records.
* Only the audit log moved. Principals and API keys (`VETO_AUTH_DB`) and the approval queue are still per-process,
  so running two gateway replicas needs those moved too (rate limits, lockout counters and anomaly baselines are
  in memory by design). Do not claim high availability until that is done.
* One gateway failing mid-write simply raises (fail closed); there is no retry or buffering.

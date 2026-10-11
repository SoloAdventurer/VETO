"""Tenant isolation (invariant 8, DECISIONS D-027). Every test is an attack by one tenant on another, or by the
platform on a tenant, and must fail to cross the boundary. SQLite always; PostgreSQL when VETO_TEST_PG_DSN is set."""

import json
import sqlite3

import pytest
from conftest import BACKENDS
from fastapi.testclient import TestClient
from veto.audit import AuditLog, open_audit
from veto.audit.chain import seal
from veto.auth.store import PrincipalStore
from veto.canonical import canonical_json, sha256_hex
from veto.gateway.app import create_app
from veto.gateway.scenarios import _action
from veto.paths import DEFAULT_POLICY

PLATFORM = "veto_test-platform-admin-key-000000"
LOCAL_ADMIN = "veto_test-bootstrap-admin-key-000000"


def bearer(key):
    return {"Authorization": f"Bearer {key}"}


class World:
    """A platform with two customers, each with an admin, an operator, an approver and the same agent ids."""

    def __init__(self, target, monkeypatch, **app_kw):
        monkeypatch.setenv("VETO_DB", target)
        monkeypatch.setenv("VETO_AUTH_DB", target)
        self.app = create_app(demo=True, bootstrap_key=LOCAL_ADMIN, platform_key=PLATFORM, **app_kw)
        self.c = TestClient(self.app)
        self.keys: dict[str, dict[str, str]] = {}
        for t in ("alpha", "beta"):
            self.add_tenant(t)

    def add_tenant(self, t, policy=None):
        body = {"id": t, "name": t.title(), **({"policy": policy} if policy else {})}
        r = self.c.post("/v1/platform/tenants", json=body, headers=bearer(PLATFORM))
        assert r.status_code == 200, r.text
        admin = r.json()["key"]
        self.keys[t] = {"admin": admin}
        for pid, roles in (("ops-agent-1", ["agent"]), ("admin-agent-1", ["agent"]), ("gate-agent-1", ["agent"]),
                           ("human-op", ["operator"]), ("human-ap", ["approver"]), ("human-view", ["viewer"])):
            self.c.post("/v1/admin/principals", json={"id": pid, "roles": roles}, headers=bearer(admin))
            self.keys[t][pid] = self.c.post(f"/v1/admin/principals/{pid}/keys",
                                            headers=bearer(admin)).json()["key"]

    def h(self, tenant, who):
        return bearer(self.keys[tenant][who])

    def act(self, tenant, payload, who="ops-agent-1"):
        return self.c.post("/v1/actions", json=payload, headers=self.h(tenant, who))


def read(agent="ops-agent-1", target="emp-1042"):
    return _action(agent, "READ_PERSONNEL", "personnel", target, {}, why="read")


def clearance(i=1):
    return _action("admin-agent-1", "UPDATE_CLEARANCE", "personnel", f"emp-{1000 + i}", {"new_level": 2}, why="x")


@pytest.fixture
def world(target, monkeypatch):
    return World(target, monkeypatch)


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_one_tenant_cannot_read_anothers_requests_or_audit(world):
    secret = world.act("alpha", read(target="emp-1999")).json()
    assert secret["decision"] in ("allow", "allow_monitor")
    assert world.c.get(f"/v1/actions/{secret['request_id']}", headers=world.h("beta", "human-view")).status_code == 404
    assert world.c.get(f"/v1/actions/{secret['request_id']}", headers=world.h("beta", "ops-agent-1")).status_code == 404
    for who in ("admin", "human-view"):
        blob = json.dumps([world.c.get(path, headers=world.h("beta", who)).json()
                           for path in ("/v1/requests", "/v1/audit", "/v1/state")])
        assert secret["request_id"] not in blob and "emp-1999" not in blob
    assert world.c.get("/v1/audit/verify", headers=world.h("beta", "admin")).json()["ok"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_one_tenant_cannot_approve_anothers_approval(world):
    held = world.act("alpha", clearance(), who="admin-agent-1").json()
    assert held["status"] == "pending_approval"
    r = world.c.post(f"/v1/approvals/{held['request_id']}", json={"outcome": "approved"},
                     headers=world.h("beta", "human-ap"))
    assert r.status_code == 404                                           # beta does not even know it exists
    again = world.c.get(f"/v1/actions/{held['request_id']}", headers=world.h("alpha", "human-view")).json()
    assert again["decision"] == "require_approval" and not again.get("human_decision")


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_naming_a_tenant_in_the_request_changes_nothing(world):
    mine = world.act("alpha", read(target="emp-1777")).json()["request_id"]
    spoofs = [{"X-Tenant": "alpha"}, {"X-Tenant-Id": "alpha"}, {"Host": "alpha.veto.example"}]
    for extra in spoofs:
        r = world.c.get("/v1/requests?tenant=alpha&tenant_id=alpha", headers={**world.h("beta", "admin"), **extra})
        assert r.status_code == 200 and mine not in json.dumps(r.json())
    body = {**read(), "tenant": "alpha", "tenant_id": "alpha"}
    r = world.act("beta", body)
    assert r.status_code in (200, 403) and "alpha" not in json.dumps(r.json().get("requested_action", {}))
    assert world.c.get(f"/v1/actions/{mine}", headers=world.h("beta", "ops-agent-1")).status_code == 404


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_same_agent_id_in_two_tenants_are_different_principals(world):
    a, b = world.keys["alpha"]["ops-agent-1"], world.keys["beta"]["ops-agent-1"]
    assert a != b
    assert world.c.get("/v1/auth/me", headers=bearer(a)).json()["tenant"] == "alpha"
    assert world.c.get("/v1/auth/me", headers=bearer(b)).json()["tenant"] == "beta"
    listing = world.c.get("/v1/admin/principals", headers=world.h("alpha", "admin")).json()
    world.c.delete(f"/v1/admin/keys/{listing[0]['keys'][0]['key_id']}", headers=world.h("alpha", "admin"))
    assert world.c.get("/v1/auth/me", headers=bearer(b)).status_code == 200      # beta's key is untouched


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_admins_only_see_and_change_their_own_tenants_principals(world):
    beta_view = world.c.get("/v1/admin/principals", headers=world.h("beta", "admin")).json()
    beta_key_id = next(k["key_id"] for p in beta_view if p["id"] == "ops-agent-1" for k in p["keys"])
    assert world.c.delete(f"/v1/admin/keys/{beta_key_id}", headers=world.h("alpha", "admin")).status_code == 404
    off = world.c.post("/v1/admin/principals/ops-agent-1/disable", headers=world.h("alpha", "admin"))
    assert off.status_code == 200
    assert world.c.get("/v1/auth/me", headers=world.h("beta", "ops-agent-1")).status_code == 200   # beta unaffected
    assert world.c.get("/v1/auth/me", headers=world.h("alpha", "ops-agent-1")).status_code == 401
    alpha_ids = {p["id"] for p in world.c.get("/v1/admin/principals", headers=world.h("alpha", "admin")).json()}
    assert "ops-agent-1" in alpha_ids and len(alpha_ids) == 7                           # 6 added + the first admin


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_observations_and_taint_do_not_cross_tenants(world):
    oid = "obs-00001"
    obs = {"schema_version": "0.1", "observation_id": oid, "source": "mail.inbox", "type": "email",
           "timestamp": "2026-10-11T10:00:00Z", "data": {}}
    assert world.c.post("/v1/observations", json=obs, headers=world.h("alpha", "ops-agent-1")).status_code == 200
    # alpha's agent is tainted; beta's agent with the same id is not, and can reuse the same observation id
    export = _action("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "all", {"row_count": 20}, why="x")
    assert world.act("alpha", export).json()["decision"] == "block"
    assert world.act("beta", export).json()["status"] == "executed"
    assert world.c.post("/v1/observations", json=obs, headers=world.h("beta", "ops-agent-1")).status_code == 200
    # referencing alpha's observation from beta resolves to nothing trustworthy, not to alpha's record
    ref = _action("gate-agent-1", "UNLOCK_DOOR", "door", "door-3", {"duration_s": 5, "subject_id": "emp-1042"},
                  why="x", obs=["obs-00777"], inputs=[{"ref": "obs-00777", "origin": "operator_input"}])
    assert world.act("beta", ref, who="gate-agent-1").json()["decision"] == "block"


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_containment_is_per_tenant_and_the_platform_switch_overrides_all(world):
    ok = ("allow", "allow_monitor")
    on = world.c.post("/v1/containment", json={"active": True}, headers=world.h("alpha", "human-op"))
    assert on.status_code == 200
    assert world.act("alpha", read()).json()["decision"] == "block"
    assert world.act("beta", read()).json()["decision"] in ok                            # beta keeps working
    world.c.post("/v1/containment", json={"active": False}, headers=world.h("alpha", "human-op"))
    r = world.c.post("/v1/platform/containment", json={"active": True, "reason": "drill"}, headers=bearer(PLATFORM))
    assert r.status_code == 200
    assert world.act("alpha", read()).json()["decision"] == "block"
    assert world.act("beta", read()).json()["decision"] == "block"
    world.c.post("/v1/containment", json={"active": False}, headers=world.h("beta", "human-op"))   # cannot override
    assert world.act("beta", read()).json()["decision"] == "block"
    world.c.post("/v1/platform/containment", json={"active": False}, headers=bearer(PLATFORM))
    assert world.act("alpha", read()).json()["decision"] in ok and world.act("beta", read()).json()["decision"] in ok


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_suspended_tenant_is_locked_out_and_others_are_not(world):
    assert world.c.post("/v1/platform/tenants/alpha/suspend", headers=bearer(PLATFORM)).status_code == 200
    for who in ("ops-agent-1", "admin", "human-view"):
        assert world.c.get("/v1/auth/me", headers=world.h("alpha", who)).status_code == 403
    assert world.act("alpha", read()).status_code == 403
    assert world.act("beta", read()).status_code == 200
    world.c.post("/v1/platform/tenants/alpha/resume", headers=bearer(PLATFORM))
    assert world.act("alpha", read()).status_code == 200


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_the_platform_cannot_act_inside_a_tenant_and_tenants_cannot_use_the_platform(world):
    p = bearer(PLATFORM)
    for method, path in (("get", "/v1/state"), ("get", "/v1/audit"), ("get", "/v1/requests"),
                         ("get", "/v1/admin/principals"), ("post", "/v1/containment")):
        r = getattr(world.c, method)(path, headers=p, **({"json": {"active": True}} if method == "post" else {}))
        assert r.status_code == 403, path
    assert world.c.post("/v1/actions", json=read(), headers=p).status_code == 403
    for who in ("admin", "human-op", "ops-agent-1"):
        assert world.c.get("/v1/platform/tenants", headers=world.h("alpha", who)).status_code == 403
        h = world.h("alpha", who)
        assert world.c.post("/v1/platform/containment", json={"active": True}, headers=h).status_code == 403
        assert world.c.post("/v1/platform/tenants", json={"id": "evil"}, headers=h).status_code == 403


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_platform_listing_shows_counts_and_health_only(world):
    world.act("alpha", read(target="emp-1888"))
    listing = world.c.get("/v1/platform/tenants", headers=bearer(PLATFORM)).json()
    assert {t["id"] for t in listing} >= {"alpha", "beta", "default"}
    assert set(listing[0]) == {"id", "name", "status", "created_at", "records", "loaded", "containment"}
    assert "emp-1888" not in json.dumps(listing)
    state = world.c.get("/v1/platform/state", headers=bearer(PLATFORM)).json()
    assert state["chain"]["ok"] and "emp-1888" not in json.dumps(state)


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_platform_actions_are_audited_on_their_own_chain(world):
    world.c.post("/v1/platform/tenants/beta/suspend", headers=bearer(PLATFORM))
    world.c.post("/v1/platform/containment", json={"active": True, "reason": "x"}, headers=bearer(PLATFORM))
    log = open_audit(world.app.state.db_target, "_platform")
    actions = [r["requested_action"]["action"] for r in log.all()]
    assert actions[-2:] == ["SUSPEND_TENANT", "PLATFORM_CONTAINMENT"] and "CREATE_TENANT" in actions
    assert log.verify()["ok"]
    dup = world.c.post("/v1/platform/tenants", json={"id": "alpha"}, headers=bearer(PLATFORM))
    assert dup.status_code == 409
    for bad_id in ("Bad Id!", "_platform"):
        r = world.c.post("/v1/platform/tenants", json={"id": bad_id}, headers=bearer(PLATFORM))
        assert r.status_code in (400, 422)


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_each_tenant_runs_its_own_policy(world):
    strict = DEFAULT_POLICY.read_text().replace("  - id: allow-read-personnel", "  - id: allow-read-personnel-disabled")
    strict = strict.replace("    effect: allow\n    when:\n      all:\n        - action: { eq: READ_PERSONNEL }",
                            "    effect: deny\n    when:\n      all:\n        - action: { eq: READ_PERSONNEL }")
    world.add_tenant("gamma", strict)
    assert world.act("alpha", read()).json()["decision"] in ("allow", "allow_monitor")
    assert world.act("gamma", read()).json()["decision"] == "block"
    broken = {"id": "delta", "policy": "not: [a policy"}
    assert world.c.post("/v1/platform/tenants", json=broken, headers=bearer(PLATFORM)).status_code == 422
    again = world.c.post("/v1/platform/tenants", json={"id": "delta"}, headers=bearer(PLATFORM))
    assert again.status_code == 200                                                  # nothing was half-created


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_flooding_by_one_tenant_does_not_throttle_another(target, monkeypatch):
    w = World(target, monkeypatch, agent_rate=(60, 3))
    codes = [w.act("alpha", read()).status_code for _ in range(8)]
    assert 429 in codes
    assert w.act("beta", read()).status_code == 200                                  # same agent id, own bucket


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_chains_are_independent_and_numbered_per_tenant(world):
    for _ in range(5):
        world.act("alpha", read())
    a = world.c.get("/v1/audit", headers=world.h("alpha", "admin")).json()
    b = world.c.get("/v1/audit", headers=world.h("beta", "admin")).json()
    assert [r["seq"] for r in b] == list(range(1, len(b) + 1))                       # beta's numbering ignores alpha
    assert [r["seq"] for r in a] == list(range(1, len(a) + 1)) and len(a) > len(b)
    assert {r["tenant"] for r in a} == {"alpha"} and {r["tenant"] for r in b} == {"beta"}
    assert a[0]["prev_hash"] == "0" * 64 and b[0]["prev_hash"] == "0" * 64


def _tamper_sql(target, sql):
    if target.startswith("postgres"):
        import psycopg
        with psycopg.connect(target, autocommit=True) as c:
            c.execute("ALTER TABLE audit DISABLE TRIGGER USER")
            c.execute("SET row_security = off")
            c.execute(sql)
            c.execute("ALTER TABLE audit ENABLE TRIGGER USER")
    else:
        db = sqlite3.connect(target)
        db.execute("DROP TRIGGER audit_no_update")
        db.execute(sql)
        db.commit()


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_tampering_with_one_tenants_chain_leaves_the_others_intact(world):
    for t in ("alpha", "beta"):
        world.act(t, read())
    _tamper_sql(world.app.state.db_target, "UPDATE audit SET record = replace(record, 'allow', 'xxxxx') "
                "WHERE tenant = 'alpha' AND record LIKE '%READ_PERSONNEL%'")
    assert world.c.get("/v1/audit/verify", headers=world.h("alpha", "admin")).json()["ok"] is False
    assert world.c.get("/v1/audit/verify", headers=world.h("beta", "admin")).json()["ok"] is True


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_record_moved_to_another_tenant_fails_verification(world):
    world.act("alpha", read())
    _tamper_sql(world.app.state.db_target, "UPDATE audit SET tenant = 'beta' WHERE tenant = 'alpha' "
                "AND record LIKE '%READ_PERSONNEL%'")
    v = world.c.get("/v1/audit/verify", headers=world.h("beta", "admin")).json()
    assert v["ok"] is False and v["detail"] == "record belongs to another tenant"


def test_databases_from_before_tenancy_open_as_the_default_tenant(tmp_path):
    path = str(tmp_path / "legacy.db")
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, request_id TEXT NOT NULL,
      record TEXT NOT NULL, record_hash TEXT NOT NULL);
    CREATE TABLE principals (id TEXT PRIMARY KEY, roles TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
      created_at REAL NOT NULL);
    CREATE TABLE api_keys (key_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id),
      key_hash TEXT UNIQUE NOT NULL, prefix TEXT NOT NULL, created_at REAL NOT NULL, last_used REAL, revoked_at REAL);
    """)
    rec = seal({"schema_version": "0.1", "request_id": "req-old", "agent_id": "ops-agent-1", "action_hash": "a" * 64,
                "decision": "block", "policies_evaluated": []}, "0" * 64)
    rec.pop("tenant")                                        # exactly what the old code wrote
    rec["record_hash"] = sha256_hex(canonical_json({k: v for k, v in rec.items() if k != "record_hash"}))
    db.execute("INSERT INTO audit (event_id, request_id, record, record_hash) VALUES (?, ?, ?, ?)",
               (rec["event_id"], "req-old", canonical_json(rec), rec["record_hash"]))
    db.execute("INSERT INTO principals (id, roles, created_at) VALUES ('old-admin', 'admin,viewer', 1.0)")
    old_key = "veto_legacy-key-legacy-key-legacy-00"
    import hashlib
    db.execute("INSERT INTO api_keys (key_id, principal_id, key_hash, prefix, created_at) VALUES ('key-old', "
               "'old-admin', ?, 'veto_legacy', 1.0)", (hashlib.sha256(old_key.encode()).hexdigest(),))
    db.commit()
    db.close()
    log = AuditLog(path)                                     # default tenant
    assert log.verify()["ok"] and log.count() == 1
    nxt = log.append({"schema_version": "0.1", "request_id": "req-new", "agent_id": "ops-agent-1",
                      "action_hash": "b" * 64, "decision": "block", "policies_evaluated": []})
    assert nxt["seq"] == 2 and log.verify()["ok"]
    assert AuditLog(path, "alpha").count() == 0              # the old rows belong to default only
    store = PrincipalStore(path)
    p = store.authenticate(old_key)
    assert p.tenant == "default" and p.id == "old-admin" and p.has("admin")
    assert store.list_principals(tenant="default")[0]["id"] == "old-admin"
    assert store.list_principals(tenant="alpha") == []


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_audit_objects_refuse_invalid_tenant_ids(target):
    for bad in ("", "Alpha", "a;drop", "x" * 41, "1abc", "../x"):
        with pytest.raises(ValueError):
            open_audit(target, bad)


@pytest.mark.skipif(not __import__("os").environ.get("VETO_TEST_PG_DSN"), reason="VETO_TEST_PG_DSN not set")
def test_postgres_row_level_security_hides_other_tenants_even_from_a_buggy_query(tmp_path):
    """The gateway's database role sees only the rows of the tenant its connection is pinned to, whatever SQL runs."""
    import os
    import uuid

    import psycopg
    import psycopg.conninfo
    base = os.environ["VETO_TEST_PG_DSN"]
    schema, role = "t_" + uuid.uuid4().hex[:10], "veto_rls_" + uuid.uuid4().hex[:8]
    sep = "&" if "?" in base else "?"
    admin_dsn = f"{base}{sep}options=-csearch_path%3D{schema}"
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"CREATE SCHEMA {schema}")
        c.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'rls-test'")
    try:
        a, b = open_audit(admin_dsn, "alpha"), open_audit(admin_dsn, "beta")           # as owner: creates the table
        for log in (a, b):
            for i in range(3):
                log.append({"schema_version": "0.1", "request_id": f"req-{log.tenant}-{i}", "agent_id": "x",
                            "action_hash": "a" * 64, "decision": "block", "policies_evaluated": []})
        with psycopg.connect(base, autocommit=True) as c:
            c.execute(f"GRANT USAGE ON SCHEMA {schema} TO {role}")
            c.execute(f"GRANT SELECT, INSERT ON {schema}.audit TO {role}")
            c.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA {schema} TO {role}")
        user_dsn = psycopg.conninfo.make_conninfo(admin_dsn, user=role, password="rls-test")
        from veto.audit.postgres import PostgresAuditLog
        alpha = PostgresAuditLog(user_dsn, "alpha", migrate=False)        # least-privilege role: no DDL
        raw = alpha._conn().execute("SELECT DISTINCT tenant FROM audit").fetchall()    # a query with NO tenant filter
        assert raw == [("alpha",)]
        assert alpha._conn().execute("SELECT count(*) FROM audit WHERE tenant = 'beta'").fetchone() == (0,)
        alpha._db.rollback()
        with pytest.raises(psycopg.Error):                                  # cannot insert rows for another tenant
            alpha._conn().execute(
                "INSERT INTO audit (event_id, request_id, record, record_hash, tenant, tseq) "
                "VALUES ('evt-x', 'r', '{}', 'h', 'beta', 99)")
        alpha._db.rollback()
        with pytest.raises(psycopg.Error):                                  # and has no right to switch the table off
            alpha._conn().execute("ALTER TABLE audit DISABLE ROW LEVEL SECURITY")
        alpha._db.rollback()
        assert alpha.verify()["ok"] and PostgresAuditLog(user_dsn, "beta", migrate=False).verify()["ok"]
    finally:
        with psycopg.connect(base, autocommit=True) as c:
            c.execute(f"DROP SCHEMA {schema} CASCADE")
            c.execute(f"DROP OWNED BY {role}")
            c.execute(f"DROP ROLE {role}")

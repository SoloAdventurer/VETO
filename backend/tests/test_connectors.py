"""Outbound connectors (DECISIONS D-030): the Execution Gateway acts on a customer's system through a signed webhook,
the target cannot be turned against our own network, and secrets stay sealed. SQLite always; PostgreSQL if set."""

import hashlib
import hmac
import json
import pathlib
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import BACKENDS
from test_tenancy import World, read
from veto.canonical import action_hash
from veto.execution import connectors, netguard
from veto.gateway.scenarios import _action

pytest.importorskip("cryptography")

PUBLIC = "93.184.216.34"
URL = "https://hooks.customer.example/secret-token-abc123/run"
KEY = "k" * 40


def public_resolver(host, port, **kw):
    return [(2, 1, 6, "", (PUBLIC, port))]


class Fake:
    """Records outbound calls; behaviour is set per test."""

    def __init__(self):
        self.calls = []
        self.reply = (200, b'{"summary": "done in customer system"}')
        self.error = None

    def __call__(self, url, body, headers, timeout):
        self.calls.append({"url": url, "body": body, "headers": headers, "timeout": timeout})
        if self.error:
            raise self.error
        return self.reply


@pytest.fixture(autouse=True)
def secret_key(monkeypatch):
    monkeypatch.setenv(connectors.KEY_ENV, KEY)


@pytest.fixture
def fake():
    return Fake()


@pytest.fixture
def world(target, monkeypatch, fake):
    return World(target, monkeypatch, connector_net=connectors.Net(transport=fake, resolver=public_resolver))


def define(w, tenant, name="crm", who="admin", **over):
    spec = {"url": URL, "verbs": ["READ_PERSONNEL"], **over}
    return w.c.put(f"/v1/admin/connectors/{name}", json=spec, headers=w.h(tenant, who))


def records(w, tenant="alpha"):
    return w.c.get("/v1/audit?limit=5000", headers=w.h(tenant, "admin")).json()


def verify_sig(header, secret, body):
    t, v1 = (p.split("=", 1)[1] for p in header.split(","))
    return hmac.compare_digest(v1, hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest())


# ---------------------------------------------------------------------------------------------- the happy path
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_an_allowed_action_is_sent_to_the_customers_system_signed_and_bound_to_the_hash(world, fake):
    made = define(world, "alpha").json()
    assert made["signing_secret"].startswith("vsec_")
    out = world.act("alpha", read(target="emp-1042")).json()
    assert out["decision"] in ("allow", "allow_monitor") and out["status"] == "executed_unverified"
    assert out["execution"]["adapter"] == "webhook:crm" and "customer system" in out["execution"]["result_summary"]
    assert out["verification"]["status"] == "skipped"                     # VETO cannot inspect the other system
    [call] = fake.calls
    body = json.loads(call["body"])
    assert body["type"] == "veto.action" and body["tenant"] == "alpha" and body["decision"] == "allow"
    assert body["request_id"] == out["request_id"] and body["action_hash"] == out["action_hash"]
    assert action_hash(body["action"]) == out["action_hash"]              # the receiver can recompute the binding
    assert verify_sig(call["headers"]["X-VETO-Signature"], made["signing_secret"], call["body"])
    assert call["headers"]["Idempotency-Key"] == out["request_id"] and call["url"] == URL
    assert world.c.get("/v1/audit/verify", headers=world.h("alpha", "admin")).json()["ok"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_held_action_is_sent_only_after_a_human_approves_it(world, fake):
    define(world, "alpha", verbs=["UPDATE_CLEARANCE"])
    held = world.act("alpha", _action("admin-agent-1", "UPDATE_CLEARANCE", "personnel", "emp-1001",
                                      {"new_level": 2}, why="x"), who="admin-agent-1").json()
    assert held["status"] == "pending_approval" and fake.calls == []
    done = world.c.post(f"/v1/approvals/{held['request_id']}", json={"outcome": "approved"},
                        headers=world.h("alpha", "human-ap")).json()
    assert done["status"] == "executed_unverified" and json.loads(fake.calls[0]["body"])["decision"] == "approved"
    other = world.act("alpha", _action("admin-agent-1", "UPDATE_CLEARANCE", "personnel", "emp-1002",
                                       {"new_level": 2}, why="x"), who="admin-agent-1").json()
    world.c.post(f"/v1/approvals/{other['request_id']}", json={"outcome": "rejected"},
                 headers=world.h("alpha", "human-ap"))
    assert len(fake.calls) == 1                                           # a rejection never reaches the customer


# ---------------------------------------------------------------------------------------------- never when VETO says no
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_blocked_actions_and_containment_never_reach_the_connector(world, fake):
    define(world, "alpha", verbs=["READ_PERSONNEL", "DELETE_RECORD"])
    out = world.act("alpha", _action("ops-agent-1", "DELETE_RECORD", "personnel", "emp-1042", {}, why="x")).json()
    assert out["decision"] == "block"
    world.c.post("/v1/containment", json={"active": True, "reason": "test"}, headers=world.h("alpha", "human-op"))
    assert world.act("alpha", read()).json()["decision"] == "block"
    assert fake.calls == []
    assert world.c.post("/v1/admin/connectors/crm/ping", headers=world.h("alpha", "admin")).json()["ok"] is False
    assert fake.calls == []                                               # not even a ping during containment


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_stolen_decision_token_or_changed_action_cannot_reach_the_connector(world, fake):
    define(world, "alpha", verbs=["READ_PERSONNEL"])
    svc = world.app.state.runtimes.get("alpha")
    act = {"agent_id": "ops-agent-1", "action": "READ_PERSONNEL", "target": {"resource": "personnel", "id": "emp-1"},
           "parameters": {}}
    h = action_hash(act)
    ok = svc.signer.sign("req-x", h, "allow")
    changed = {**act, "target": {"resource": "personnel", "id": "emp-2"}}
    assert svc.execution.execute(request_id="req-x", action=changed, ahash=h, decision_label="allow",
                                 tag=ok)["status"] == "not_executed"
    assert svc.execution.execute(request_id="req-x", action=act, ahash=h, decision_label="allow",
                                 tag="0" * 64)["status"] == "not_executed"
    assert fake.calls == []
    svc.containment = True                                                # a valid token still cannot pass containment
    res = svc.execution.execute(request_id="req-x", action=act, ahash=h, decision_label="allow", tag=ok)
    assert res["status"] == "not_executed" and "containment" in res["result_summary"] and fake.calls == []
    svc.containment = False
    assert svc.execution.execute(request_id="req-x", action=act, ahash=h, decision_label="allow",
                                 tag=ok)["status"] == "executed" and len(fake.calls) == 1


# ---------------------------------------------------------------------------------------------- failure handling
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_failures_are_reported_honestly_and_a_dead_endpoint_is_paused(world, fake):
    define(world, "alpha")
    fake.reply = (500, b"boom")
    first = world.act("alpha", read()).json()
    assert first["status"] == "failed" and "HTTP 500" in first["execution"]["result_summary"]
    fake.reply = (403, b"nope")
    assert "HTTP 403" in world.act("alpha", read()).json()["execution"]["result_summary"]
    fake.error = netguard.TransportError("TimeoutError after the request was sent", sent=True)
    unknown = world.act("alpha", read()).json()
    assert unknown["status"] == "failed" and "outcome is unknown" in unknown["execution"]["result_summary"]
    assert world.act("alpha", read()).json()["status"] == "failed"      # the third counted failure (4xx does not count)
    n = len(fake.calls)
    paused = world.act("alpha", read()).json()          # three failures in a row: stop calling for a while
    assert "paused" in paused["execution"]["result_summary"] and len(fake.calls) == n
    assert "customer.example" not in json.dumps(paused) and "secret-token" not in json.dumps(paused)


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_failed_executions_do_not_count_toward_limits(world, fake):
    define(world, "alpha", verbs=["EXPORT_INCIDENT_LOG"])
    fake.reply = (502, b"")
    exp = _action("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "log-1", {"row_count": 10}, why="x")
    a = world.act("alpha", exp).json()
    b = world.act("alpha", exp).json()
    assert a["status"] in ("failed", "blocked", "pending_approval") and b["decision"] == a["decision"]


# ---------------------------------------------------------------------------------------------- routing
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_only_routed_verbs_use_the_connector_and_disabled_or_deleted_ones_fall_back(world, fake):
    define(world, "alpha", verbs=["UPDATE_CLEARANCE"])
    out = world.act("alpha", read()).json()
    assert out["execution"]["adapter"] == "mock_security_ops" and fake.calls == []
    define(world, "alpha", name="crm2", verbs=["READ_PERSONNEL"], enabled=False)
    assert world.act("alpha", read()).json()["execution"]["adapter"] == "mock_security_ops"
    define(world, "alpha", name="crm2", verbs=["READ_PERSONNEL"], enabled=True)
    assert world.act("alpha", read()).json()["execution"]["adapter"] == "webhook:crm2"
    assert world.c.delete("/v1/admin/connectors/crm2", headers=world.h("alpha", "admin")).status_code == 200
    assert world.act("alpha", read()).json()["execution"]["adapter"] == "mock_security_ops"


# ---------------------------------------------------------------------------------------------- definitions are checked
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
@pytest.mark.parametrize("bad", [
    {"url": "http://hooks.customer.example/x"},                            # not https
    {"url": "https://user:pw@hooks.customer.example/x"},                   # credentials in the url
    {"url": "https://hooks.customer.example:22/x"},                        # port
    {"url": "https://hooks.customer.example/ x"},                          # whitespace
    {"url": "https://169.254.169.254/latest/meta-data"},                   # cloud metadata
    {"url": "https://10.0.0.5/x"}, {"url": "https://127.0.0.1/x"}, {"url": "https://[::1]/x"},
    {"url": "https://[::ffff:127.0.0.1]/x"}, {"url": "https://100.64.0.1/x"}, {"url": "https://0.0.0.0/x"},
    {"url": "ftp://hooks.customer.example/x"}, {"url": ""}, {"url": None},
    {"verbs": []}, {"verbs": ["FORMAT_DISK"]}, {"verbs": "READ_PERSONNEL"},
    {"headers": {"Host": "evil"}}, {"headers": {"X-VETO-Signature": "forged"}},
    {"headers": {"A": "1", "B": "2", "C": "3", "D": "4"}},
    {"headers": {"Authorization": "line\nbreak"}}, {"timeout_s": 99}, {"timeout_s": 0}, {"surprise": 1},
])
def test_unsafe_or_malformed_connector_definitions_are_refused_and_not_stored(world, bad):
    assert define(world, "alpha", **bad).status_code == 422
    assert world.c.get("/v1/admin/connectors", headers=world.h("alpha", "admin")).json()["connectors"] == []


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_name_that_resolves_to_a_private_address_is_refused(target, monkeypatch, fake):
    def private(host, port, **kw):
        return [(2, 1, 6, "", ("10.1.2.3", port))]
    w = World(target, monkeypatch, connector_net=connectors.Net(transport=fake, resolver=private))
    r = define(w, "alpha")
    assert r.status_code == 422 and "non-public" in r.text
    mixed = connectors.Net(resolver=lambda h, p, **k: [(2, 1, 6, "", (PUBLIC, p)), (2, 1, 6, "", ("192.168.0.9", p))])
    with pytest.raises(connectors.ConnectorError):
        connectors.define("alpha", "x", {"url": URL, "verbs": ["READ_PERSONNEL"]}, None, mixed)


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_dns_that_changes_after_the_check_is_caught_at_call_time(target, monkeypatch):
    answers = [PUBLIC]

    def flip(host, port, **kw):
        return [(2, 1, 6, "", (answers[0], port))]
    w = World(target, monkeypatch, connector_net=connectors.Net(resolver=flip))      # real transport, fake DNS
    assert define(w, "alpha").status_code == 200
    answers[0] = "169.254.169.254"                                                   # the name now points inside
    out = w.act("alpha", read()).json()
    assert out["status"] == "failed" and "not allowed" in out["execution"]["result_summary"]


# ---------------------------------------------------------------------------------------------- secrets and roles
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_secrets_are_shown_once_and_never_logged_or_listed(world, fake):
    made = define(world, "alpha").json()
    secret = made["signing_secret"]
    assert define(world, "alpha").json().get("signing_secret") is None            # redefining keeps the same secret
    call = (world.act("alpha", read()), fake.calls[-1])
    assert verify_sig(call[1]["headers"]["X-VETO-Signature"], secret, call[1]["body"])
    listing = world.c.get("/v1/admin/connectors", headers=world.h("alpha", "admin")).json()
    blob = json.dumps([listing, records(world), world.c.get("/v1/state", headers=world.h("alpha", "admin")).json()])
    for needle in (secret, "secret-token-abc123", "hooks.customer.example/"):
        assert needle not in blob
    assert listing["connectors"][0]["host"] == "hooks.customer.example"
    rotated = define(world, "alpha", rotate_secret=True).json()
    assert rotated["signing_secret"] != secret and rotated["fingerprint"] != made["fingerprint"]
    acts = [x["requested_action"]["action"] for x in records(world)]
    assert acts.count("CONNECTOR_SET") == 3


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_only_admins_manage_connectors(world):
    for who in ("ops-agent-1", "human-op", "human-ap", "human-view"):
        assert define(world, "alpha", who=who).status_code == 403
        assert world.c.get("/v1/admin/connectors", headers=world.h("alpha", who)).status_code == 403
        assert world.c.post("/v1/admin/connectors/crm/ping", headers=world.h("alpha", who)).status_code == 403


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_connectors_are_unavailable_without_a_storage_key(world, monkeypatch):
    monkeypatch.delenv(connectors.KEY_ENV)
    r = define(world, "alpha")
    assert r.status_code == 503 and "VETO_SECRET_KEY" in r.text
    assert world.c.get("/v1/admin/connectors", headers=world.h("alpha", "admin")).json()["storage_ready"] is False


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_the_wrong_key_or_a_tampered_blob_fails_closed(world, fake, monkeypatch):
    define(world, "alpha")
    monkeypatch.setenv(connectors.KEY_ENV, "z" * 40)
    out = world.act("alpha", read()).json()
    assert out["status"] == "failed" and fake.calls == []


# ---------------------------------------------------------------------------------------------- tenants
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_connectors_never_cross_tenants(world, fake):
    define(world, "alpha")
    assert world.c.get("/v1/admin/connectors", headers=world.h("beta", "admin")).json()["connectors"] == []
    assert world.c.delete("/v1/admin/connectors/crm", headers=world.h("beta", "admin")).status_code == 404
    assert world.c.post("/v1/admin/connectors/crm/ping", headers=world.h("beta", "admin")).status_code == 404
    out = world.act("beta", read()).json()
    assert out["execution"]["adapter"] == "mock_security_ops" and fake.calls == []
    # a sealed blob copied into another tenant (or under another name) does not open
    store = world.app.state.principals
    row = store.connector_rows("alpha")[0]
    store.put_connector("beta", "crm", row["meta"], row["sealed"], "mallory")
    store.put_connector("alpha", "renamed", row["meta"], row["sealed"], "mallory")
    assert world.act("beta", read()).json()["status"] == "failed"
    assert fake.calls == []
    with pytest.raises(connectors.ConnectorError):
        connectors._open("alpha", "renamed", row["sealed"])


def test_decryption_exists_only_inside_the_execution_package():
    root = pathlib.Path(connectors.__file__).resolve().parents[1]
    for path in root.rglob("*.py"):
        if path.parent.name == "execution":
            continue
        text = path.read_text()
        assert "connectors._open" not in text and "AESGCM" not in text and ".decrypt(" not in text, path


# ---------------------------------------------------------------------------------------------- the real transport
def test_netguard_url_rules():
    assert netguard.parse_url("https://a.example/x?y=1") == ("a.example", 443, "/x?y=1")
    assert netguard.parse_url("https://a.example:8443")[1:] == (8443, "/")
    for bad in ("http://a.example", "https://a.example:80", "https://u@a.example", "https://", "a.example",
                "https://a.example/" + "x" * 3000):
        with pytest.raises(netguard.UnsafeTarget):
            netguard.parse_url(bad)
    with pytest.raises(netguard.UnsafeTarget):
        netguard.resolve_public("x.example", 443, lambda *a, **k: [])


@pytest.fixture
def tls_server(tmp_path):
    if not subprocess.run(["which", "openssl"], capture_output=True).stdout:
        pytest.skip("openssl not available")
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append({"path": self.path, "headers": dict(self.headers),
                         "body": self.rfile.read(int(self.headers["Content-Length"]))})
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", "https://169.254.169.254/")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"summary": "tls ok"}')

        def log_message(self, *a):
            pass

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", 8443), H)
    except OSError:
        pytest.skip("port 8443 busy")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    client = ssl.create_default_context(cafile=str(cert))
    yield seen, client
    srv.shutdown()


@pytest.mark.parametrize("target", ["sqlite"], indirect=True)
def test_the_real_transport_verifies_the_certificate_pins_the_address_and_ignores_redirects(
        tls_server, target, monkeypatch):
    seen, ctx = tls_server

    def transport(url, body, headers, timeout):
        return netguard.post(url, body, headers, timeout, allow_private=True, context=ctx)
    w = World(target, monkeypatch, connector_net=connectors.Net(transport=transport, resolver=public_resolver))
    assert define(w, "alpha", url="https://localhost:8443/hook").status_code == 200
    out = w.act("alpha", read()).json()
    assert out["status"] == "executed_unverified" and "tls ok" in out["execution"]["result_summary"]
    assert seen[0]["path"] == "/hook" and seen[0]["headers"]["X-VETO-Request-Id"] == out["request_id"]
    define(w, "alpha", name="redir", url="https://localhost:8443/redirect", verbs=["EXPORT_INCIDENT_LOG"])
    exp = _action("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "log-1", {"row_count": 1}, why="x")
    r = w.act("alpha", exp)
    assert r.json()["status"] != "executed" or len(seen) == 2          # a 302 is a failure; it is never followed
    # a certificate the client does not trust is refused
    bad = netguard.post
    with pytest.raises(netguard.TransportError):
        bad("https://localhost:8443/hook", b"{}", {}, 3, allow_private=True)

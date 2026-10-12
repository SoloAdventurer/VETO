"""External timestamping of the audit chain (DECISIONS D-031). A real RFC 3161 authority is built locally with
OpenSSL, so the request, the reply parsing and the signature check run against genuine tokens. SQLite always;
PostgreSQL when VETO_TEST_PG_DSN is set."""

import base64
import json
import shutil

import pytest
from conftest import BACKENDS
from test_tenancy import World, read
from veto.audit import rfc3161
from veto.audit.anchor import AnchorConfig
from veto.devtools.local_tsa import Authority

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")

@pytest.fixture
def tsa(tmp_path):
    return Authority(tmp_path)


@pytest.fixture
def world(target, monkeypatch, tsa):
    cfg = AnchorConfig(tsa_url="https://tsa.example/tsr", ca_file=tsa.ca, interval_s=0, poster=tsa)
    return World(target, monkeypatch, anchoring=cfg)


def act(w, n=3):
    for i in range(n):
        w.act("alpha", read(target=f"emp-10{i}"))


def anchors(w, tenant="alpha", who="human-view"):
    return w.c.get("/v1/anchors", headers=w.h(tenant, who)).json()


# ---------------------------------------------------------------------------------------------- protocol
def test_request_and_reply_round_trip_against_a_real_authority(tsa):
    digest = rfc3161.anchor_digest("alpha", 7, "ab" * 32)
    query, nonce = rfc3161.build_request(digest)
    out = tsa.reply(query)
    parsed = rfc3161.parse_response(out)
    assert parsed.status in (0, 1) and parsed.imprint == digest and parsed.nonce == nonce
    assert parsed.gen_time and parsed.gen_time.endswith("Z")
    rfc3161.check_reply(parsed, digest, nonce)
    rfc3161.openssl_verify(out, digest, tsa.ca)                              # the signature is genuine
    with pytest.raises(rfc3161.TimestampError):
        rfc3161.openssl_verify(out, rfc3161.anchor_digest("alpha", 8, "ab" * 32), tsa.ca)   # different digest
    (tsa.d.parent / "other").mkdir()
    other = Authority(tsa.d.parent / "other")
    with pytest.raises(rfc3161.TimestampError):
        rfc3161.openssl_verify(out, digest, other.ca)                         # a different authority's key


def test_a_token_for_another_digest_or_nonce_is_refused_even_without_a_ca(tsa):
    digest = rfc3161.anchor_digest("alpha", 7, "ab" * 32)
    other, _ = rfc3161.build_request(rfc3161.anchor_digest("alpha", 8, "cd" * 32), nonce=5)
    parsed = rfc3161.parse_response(tsa.reply(other))
    with pytest.raises(rfc3161.TimestampError, match="different digest"):
        rfc3161.check_reply(parsed, digest, 5)
    with pytest.raises(rfc3161.TimestampError, match="nonce"):
        rfc3161.check_reply(parsed, rfc3161.anchor_digest("alpha", 8, "cd" * 32), 6)
    with pytest.raises(rfc3161.TimestampError):
        rfc3161.parse_response(b"\x30\x82\xff\xff")                       # truncated DER


def test_the_digest_binds_tenant_position_and_head():
    base = rfc3161.anchor_digest("alpha", 1, "aa")
    assert len({base, rfc3161.anchor_digest("beta", 1, "aa"), rfc3161.anchor_digest("alpha", 2, "aa"),
                rfc3161.anchor_digest("alpha", 1, "bb")}) == 4


# ---------------------------------------------------------------------------------------------- the service
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_anchoring_stores_a_verifiable_receipt_and_skips_when_nothing_changed(world, tsa):
    act(world)
    r = world.c.post("/v1/anchors", headers=world.h("alpha", "admin"))
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["seq"] > 0 and a["signature_checked"] is True and a["gen_time"].endswith("Z")
    again = world.c.post("/v1/anchors", headers=world.h("alpha", "admin")).json()
    assert "nothing new" in again["detail"] and len(tsa.requests) == 1
    listing = anchors(world)
    assert listing["enabled"] and listing["authority"] == "tsa.example" and len(listing["anchors"]) == 1
    rec = world.c.get(f"/v1/anchors/{a['seq']}/receipt", headers=world.h("alpha", "human-view")).json()
    out = base64.b64decode(rec["tsr_base64"])
    rfc3161.openssl_verify(out, bytes.fromhex(rec["digest_sha256"]), tsa.ca)           # an auditor can do this offline
    log = world.c.get("/v1/audit?limit=5000", headers=world.h("alpha", "admin")).json()
    assert log[a["seq"] - 1]["record_hash"] == rec["head_hash"]
    act(world, 2)
    assert world.c.post("/v1/anchors", headers=world.h("alpha", "admin")).json()["seq"] > a["seq"]
    assert world.c.get("/v1/anchors/verify", headers=world.h("alpha", "human-view")).json()["ok"] is True


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_perfectly_rewritten_chain_still_fails_against_the_timestamp(target, monkeypatch, tsa):
    if "postgres" in target:
        pytest.skip("rewrite simulation uses the SQLite file")
    w = World(target, monkeypatch, anchoring=AnchorConfig("https://tsa.example/tsr", tsa.ca, 0, poster=tsa))
    act(w, 4)
    w.c.post("/v1/anchors", headers=w.h("alpha", "admin"))
    assert w.c.get("/v1/audit/verify", headers=w.h("alpha", "admin")).json()["ok"]
    # An attacker with write access to the database file edits record 2 and recomputes every later hash.
    import sqlite3
    db = sqlite3.connect(target)
    db.execute("DROP TRIGGER audit_no_update")
    rows = db.execute("SELECT rowid, COALESCE(tseq, seq), record FROM audit WHERE tenant = 'alpha' "
                      "ORDER BY seq").fetchall()
    prev = None
    for rowid, seq, text in rows:
        rec = json.loads(text)
        if seq == 2:
            rec["decision_reason"] = "edited after the fact"
        if prev is not None:
            rec["prev_hash"] = prev
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        from veto.canonical import canonical_json, sha256_hex
        rec["record_hash"] = sha256_hex(canonical_json(body))
        prev = rec["record_hash"]
        db.execute("UPDATE audit SET record = ?, record_hash = ? WHERE rowid = ?", (canonical_json(rec), prev, rowid))
    db.commit()
    assert w.c.get("/v1/audit/verify", headers=w.h("alpha", "admin")).json()["ok"] is True   # the chain alone is fooled
    check = w.c.get("/v1/anchors/verify", headers=w.h("alpha", "human-view")).json()
    assert check["ok"] is False and "rewritten" in check["anchors"][0]["detail"]            # the timestamp is not


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_truncated_log_is_detected(target, monkeypatch, tsa):
    if "postgres" in target:
        pytest.skip("truncation simulation uses the SQLite file")
    w = World(target, monkeypatch, anchoring=AnchorConfig("https://tsa.example/tsr", tsa.ca, 0, poster=tsa))
    act(w, 4)
    w.c.post("/v1/anchors", headers=w.h("alpha", "admin"))
    import sqlite3
    db = sqlite3.connect(target)
    db.execute("DROP TRIGGER audit_no_delete")
    db.execute("DELETE FROM audit WHERE tenant = 'alpha' AND COALESCE(tseq, seq) > 3")
    db.commit()
    check = w.c.get("/v1/anchors/verify", headers=w.h("alpha", "admin")).json()
    assert check["ok"] is False and "shorter" in check["anchors"][0]["detail"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
@pytest.mark.parametrize("mode", ["http500", "garbage", "refuse", "wrongdigest", "wrongnonce"])
def test_a_bad_authority_reply_is_never_stored(world, tsa, mode):
    act(world)
    tsa.mode = mode
    r = world.c.post("/v1/anchors", headers=world.h("alpha", "admin"))
    assert r.status_code == 502, r.text
    assert anchors(world)["anchors"] == [] and anchors(world)["last_error"]
    tsa.mode = "ok"
    assert world.c.post("/v1/anchors", headers=world.h("alpha", "admin")).status_code == 200      # recovers


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_reply_signed_by_the_wrong_authority_is_refused_when_a_ca_is_configured(target, monkeypatch, tsa, tmp_path):
    rogue_dir = tmp_path / "rogue"
    rogue_dir.mkdir()
    rogue = Authority(rogue_dir)
    cfg = AnchorConfig("https://tsa.example/tsr", tsa.ca, 0, poster=rogue)           # we trust tsa, rogue answers
    w = World(target, monkeypatch, anchoring=cfg)
    act(w)
    r = w.c.post("/v1/anchors", headers=w.h("alpha", "admin"))
    assert r.status_code == 502 and "did not verify" in r.text and anchors(w)["anchors"] == []


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_broken_chain_is_not_anchored(target, monkeypatch, tsa):
    if "postgres" in target:
        pytest.skip("tampering simulation uses the SQLite file")
    w = World(target, monkeypatch, anchoring=AnchorConfig("https://tsa.example/tsr", tsa.ca, 0, poster=tsa))
    act(w, 3)
    import sqlite3
    db = sqlite3.connect(target)
    db.execute("DROP TRIGGER audit_no_update")
    row = db.execute("SELECT rowid, record FROM audit WHERE tenant = 'alpha' ORDER BY seq LIMIT 1 OFFSET 1").fetchone()
    db.execute("UPDATE audit SET record = ? WHERE rowid = ?", (row[1].replace('"decision":"allow"', '"decision":"xxx"'),
                                                                row[0]))
    db.commit()
    r = w.c.post("/v1/anchors", headers=w.h("alpha", "admin"))
    assert r.status_code == 502 and "not anchoring" in r.text and tsa.requests == []


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_only_admins_trigger_and_tenants_see_only_their_own_anchors(world):
    act(world)
    for who in ("ops-agent-1", "human-op", "human-ap", "human-view"):
        assert world.c.post("/v1/anchors", headers=world.h("alpha", who)).status_code == 403
    assert world.c.get("/v1/anchors", headers=world.h("alpha", "ops-agent-1")).status_code == 403
    world.c.post("/v1/anchors", headers=world.h("alpha", "admin"))
    seq = anchors(world)["anchors"][0]["seq"]
    assert anchors(world, "beta")["anchors"] == []
    assert world.c.get(f"/v1/anchors/{seq}/receipt", headers=world.h("beta", "admin")).status_code == 404
    assert world.c.get("/v1/anchors/999/receipt", headers=world.h("alpha", "admin")).status_code == 404


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_run_once_covers_every_tenant_and_the_platform_chain(world, tsa):
    act(world)
    world.act("beta", read())
    anch = world.app.state.anchorer
    out = anch.run_once()
    assert out["alpha"].startswith("anchored") and out["beta"].startswith("anchored")
    assert out["_platform"].startswith("anchored")                                    # tenant creation events
    assert world.c.get("/v1/platform/anchors", headers={"Authorization": "Bearer veto_test-platform-admin-key-000000"}
                       ).json()["anchors"]
    assert set(anch.run_once().values()) == {"nothing new"}


@pytest.mark.parametrize("target", ["sqlite"], indirect=True)
def test_timestamping_is_off_by_default(target, monkeypatch):
    w = World(target, monkeypatch)
    assert anchors(w)["enabled"] is False
    assert w.c.post("/v1/anchors", headers=w.h("alpha", "admin")).status_code == 503


def test_the_background_thread_anchors_by_itself(tmp_path, monkeypatch, tsa):
    monkeypatch.setenv("VETO_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("VETO_AUTH_DB", str(tmp_path / "a.db"))
    from fastapi.testclient import TestClient
    from veto.gateway.app import create_app
    cfg = AnchorConfig("https://tsa.example/tsr", tsa.ca, 0.2, poster=tsa)
    app = create_app(demo=True, bootstrap_key="veto_test-bootstrap-admin-key-000000",
                     platform_key="veto_test-platform-admin-key-000000", anchoring=cfg)
    app.state.anchorer.start()
    c = TestClient(app)
    c.post("/v1/actions", json=read(), headers={"Authorization": "Bearer veto_test-bootstrap-admin-key-000000"})
    import time
    for _ in range(40):
        if app.state.principals.list_anchors("default"):
            break
        time.sleep(0.1)
    app.state.anchorer.stop()
    assert app.state.principals.list_anchors("default") or app.state.principals.list_anchors("_platform")


@pytest.mark.parametrize("target", ["sqlite"], indirect=True)
def test_the_auditor_script_verifies_a_receipt_offline_and_catches_an_altered_log(world, tsa, tmp_path):
    import importlib.util
    import pathlib
    import sys
    act(world)
    a = world.c.post("/v1/anchors", headers=world.h("alpha", "admin")).json()
    receipt = tmp_path / "receipt.json"
    got = world.c.get(f"/v1/anchors/{a['seq']}/receipt", headers=world.h("alpha", "admin")).json()
    receipt.write_text(json.dumps(got))
    log = world.c.get("/v1/audit?limit=5000", headers=world.h("alpha", "admin")).json()
    audit = tmp_path / "audit.json"
    audit.write_text(json.dumps(log))
    path = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "verify_receipt.py"
    spec = importlib.util.spec_from_file_location("verify_receipt", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(sys, "argv", ["x", str(receipt), "--ca", tsa.ca, "--audit", str(audit)])
        assert mod.main() == 0
        log[a["seq"] - 1]["decision_reason"] = "changed"
        audit.write_text(json.dumps(log))
        assert mod.main() == 1
        other = tmp_path / "other"
        other.mkdir()
        monkey.setattr(sys, "argv", ["x", str(receipt), "--ca", Authority(other).ca])
        assert mod.main() == 1                                                  # wrong authority certificate
    finally:
        monkey.undo()

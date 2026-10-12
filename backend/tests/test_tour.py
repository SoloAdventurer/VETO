"""The guided tour (scripts/tour.py) is documentation people run; keep it working."""

import importlib.util
import pathlib
import shutil

import pytest

pytest.importorskip("cryptography")
pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")


def test_the_tour_runs_end_to_end_and_shows_every_promised_outcome(capsys, monkeypatch):
    path = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "tour.py"
    spec = importlib.util.spec_from_file_location("veto_tour", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main() == 0
    out = capsys.readouterr().out
    for needle in ("decision: allow -> executed", "Authority claimed from untrusted content",
                   "alice activates her own: 403",
                   "reads are frozen", "blocked=True executed=False", "receiver checks the signature: true",
                   "receiver recomputes the action hash: true", "hash chain says: chain intact   <- fooled",
                   "TAMPERED: the record at this position differs"):
        assert needle in out, needle

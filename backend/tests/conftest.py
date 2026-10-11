import os
import pathlib
import sys
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


# ---- storage backends shared by the audit and multi-gateway tests (SQLite always, PostgreSQL if configured) ----
PG = os.environ.get("VETO_TEST_PG_DSN")
BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG, reason="VETO_TEST_PG_DSN not set"))]


@pytest.fixture
def target(request, tmp_path):
    if request.param == "sqlite":
        yield str(tmp_path / "a.db")
        return
    import psycopg
    schema = "t_" + uuid.uuid4().hex[:10]
    with psycopg.connect(PG, autocommit=True) as c:
        c.execute(f"CREATE SCHEMA {schema}")
    sep = "&" if "?" in PG else "?"
    yield f"{PG}{sep}options=-csearch_path%3D{schema}"
    with psycopg.connect(PG, autocommit=True) as c:
        c.execute(f"DROP SCHEMA {schema} CASCADE")



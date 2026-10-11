#!/usr/bin/env bash
# Same checks as GitHub Actions. Run before every push to main.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pip install -q --break-system-packages pytest jsonschema pyyaml ruff fastapi uvicorn httpx "psycopg[binary]" 2>/dev/null || python3 -m pip install -q pytest jsonschema pyyaml ruff fastapi uvicorn httpx "psycopg[binary]"
python3 scripts/check_invariants.py
python3 -m ruff check backend scripts
python3 -m pytest backend/tests -q
echo "CI OK"

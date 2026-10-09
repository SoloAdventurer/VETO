"""Repository paths. Layout: <root>/backend/veto/paths.py -> root is two levels above the package."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ.get("VETO_ROOT", Path(__file__).resolve().parents[2]))
SCHEMAS_DIR = ROOT / "schemas"
DEFAULT_POLICY = ROOT / "policies" / "examples" / "security-demo.yaml"
UI_DIR = Path(os.environ.get("VETO_UI_DIR", ROOT / "frontend" / "dist"))

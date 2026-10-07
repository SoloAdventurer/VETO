#!/usr/bin/env python3
"""Static checks for VETO's non-negotiable invariants. Exit 1 on any violation."""
import ast
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
errors: list[str] = []

# --- 1. Policy evaluation must be deterministic and offline (CLAUDE.md invariant 3) ---
BANNED_IN_POLICY = {"requests", "httpx", "urllib", "urllib3", "socket", "aiohttp", "http",
                    "openai", "anthropic", "random", "secrets", "subprocess", "sklearn", "torch"}
# --- 2. No dynamic code execution anywhere in backend (invariant 7) ---
BANNED_CALLS = {"eval", "exec", "compile", "__import__"}

for path in (ROOT / "backend" / "veto").rglob("*.py"):
    rel = path.relative_to(ROOT)
    tree = ast.parse(path.read_text(), filename=str(rel))
    in_policy = "policy" in path.relative_to(ROOT / "backend" / "veto").parts[:1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in BANNED_CALLS:
            errors.append(f"{rel}:{node.lineno}: banned call {node.func.id}() (closed grammar, no dynamic code)")
        if in_policy:
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m in BANNED_IN_POLICY:
                    errors.append(f"{rel}:{node.lineno}: policy package may not import '{m}' (must be offline)")

# --- 3. Only the execution package may import credential-bearing adapters' secrets ---
for path in (ROOT / "backend" / "veto").rglob("*.py"):
    parts = path.relative_to(ROOT / "backend" / "veto").parts
    if parts and parts[0] in {"policy", "risk", "anomaly", "provenance"}:
        txt = path.read_text()
        if re.search(r"os\.environ|getenv|credential|api_key|password", txt, re.I):
            errors.append(f"{path.relative_to(ROOT)}: decision-side package touches credentials/env")

# --- 4. Domain-agnostic repo: no product-specific references (D-005) ---
FORBIDDEN = re.compile(r"shifaa|myhealth|3yadti|pharmatech", re.I)
ALLOWED = {"DECISIONS.md", "CLAUDE.md", "scripts/check_invariants.py", "backend/tests/test_repo_hygiene.py"}
tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
for f in tracked:
    if f in ALLOWED or f.endswith((".pdf", ".png", ".jpg")):
        continue
    p = ROOT / f
    if p.is_file():
        try:
            if FORBIDDEN.search(p.read_text()):
                errors.append(f"{f}: contains product-specific reference (keep core domain-agnostic, see D-005)")
        except UnicodeDecodeError:
            pass

# --- 5. Secrets ---
SECRET = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{32,}"
)
for f in tracked:
    p = ROOT / f
    if p.is_file() and not f.endswith((".pdf", ".png", ".jpg", ".gz")):
        try:
            if SECRET.search(p.read_text()):
                errors.append(f"{f}: looks like a committed secret")
        except UnicodeDecodeError:
            pass
if any(f == ".env" or f.endswith("/.env") for f in tracked):
    errors.append(".env is tracked")

# --- 6. No LICENSE until IP settled (D-009) ---
if any(f.upper() in {"LICENSE", "LICENSE.MD", "LICENSE.TXT"} for f in tracked):
    errors.append("LICENSE present but D-009 (IP) is open; remove or log a superseding decision first")

if errors:
    print("INVARIANT CHECK FAILED:")
    print("\n".join(" - " + e for e in errors))
    sys.exit(1)
print("invariant checks passed")

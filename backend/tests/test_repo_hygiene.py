import pathlib
import subprocess
import sys


def test_invariants_script_passes():
    root = pathlib.Path(__file__).resolve().parents[2]
    r = subprocess.run([sys.executable, str(root / "scripts/check_invariants.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr

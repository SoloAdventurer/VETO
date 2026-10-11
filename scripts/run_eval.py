#!/usr/bin/env python3
"""Run the VETO evaluation and write experiments/results/. Exit 1 if the full system has any false allow."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from veto.evaluation.dataset import generate  # noqa: E402
from veto.evaluation.runner import evaluate, render_markdown, trusted_personnel  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--out", default=str(ROOT / "experiments" / "results"))
    args = ap.parse_args()
    cases = generate(args.seed, args.scale, trusted_personnel())
    res = evaluate(cases, cross_tenant=max(4, round(40 * args.scale)))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(render_markdown(res, args.seed, len(cases)))
    (out / "results.json").write_text(json.dumps(res, indent=1))
    print((out / "report.md").read_text())
    return 1 if res["summary"]["full"]["false_allows"] else 0


if __name__ == "__main__":
    sys.exit(main())

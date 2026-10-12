#!/usr/bin/env python3
"""Check a VETO timestamp receipt on your own machine, without trusting the VETO server.

  python3 scripts/verify_receipt.py receipt.json --ca tsa-chain.pem [--audit audit.json]

receipt.json   the reply of GET /v1/anchors/{seq}/receipt
--ca           the time-stamp authority's certificate chain (PEM) that YOU obtained from the authority
--audit        optional: the reply of GET /v1/audit?limit=100000, to confirm the log still matches the receipt

Needs the 'openssl' command. Exit code 0 only if every check passes.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from veto.audit.chain import verify_chain  # noqa: E402
from veto.audit.rfc3161 import TimestampError, anchor_digest, openssl_verify, parse_response  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("receipt")
    ap.add_argument("--ca", required=True)
    ap.add_argument("--audit")
    args = ap.parse_args()
    r = json.loads(Path(args.receipt).read_text())
    ok = True

    def check(label: str, good: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and good
        print(f"[{'ok' if good else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))

    digest = anchor_digest(r["tenant"], r["seq"], r["head_hash"])
    check("receipt digest matches tenant, position and head hash", digest.hex() == r["digest_sha256"])
    data = base64.b64decode(r["tsr_base64"])
    try:
        openssl_verify(data, digest, args.ca)
        check("authority's signature is valid for this digest", True)
        parsed = parse_response(data)
        check("time stated by the authority", True, parsed.gen_time or "?")
    except TimestampError as exc:
        check("authority's signature is valid for this digest", False, str(exc))
    if args.audit:
        log = json.loads(Path(args.audit).read_text())
        chain = verify_chain(log, r["tenant"])
        check("exported log is an intact hash chain", chain["ok"], chain["detail"])
        at = next((x for x in log if x["seq"] == r["seq"]), None)
        check("the log has the anchored record, unchanged", bool(at) and at["record_hash"] == r["head_hash"],
              "record missing (log truncated?)" if at is None else "")
    print("\nRESULT:", "all checks passed" if ok else "NOT VERIFIED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

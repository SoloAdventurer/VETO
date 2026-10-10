#!/usr/bin/env python3
"""Manage VETO principals and API keys over the admin API.

  export VETO_URL=http://localhost:8000 VETO_ADMIN_KEY=veto_...
  python3 scripts/veto_admin.py list
  python3 scripts/veto_admin.py create ops-agent-1 agent        # roles: agent | operator approver viewer admin
  python3 scripts/veto_admin.py key ops-agent-1                 # prints the new key ONCE
  python3 scripts/veto_admin.py revoke key-1a2b3c4d5e6f
  python3 scripts/veto_admin.py disable ops-agent-1
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


def call(method: str, path: str, body: dict | None = None) -> object:
    url = os.environ.get("VETO_URL", "http://localhost:8000").rstrip("/") + path
    key = os.environ.get("VETO_ADMIN_KEY")
    if not key:
        sys.exit("set VETO_ADMIN_KEY to an admin API key")
    req = urllib.request.Request(  # noqa: S310 (operator-supplied gateway URL)
        url, method=method, data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as res:  # noqa: S310
            return json.load(res)
    except urllib.error.HTTPError as exc:
        sys.exit(f"HTTP {exc.code}: {exc.read().decode()[:300]}")


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit(__doc__)
    cmd, args = argv[0], argv[1:]
    if cmd == "list":
        for p in call("GET", "/v1/admin/principals"):  # type: ignore[union-attr]
            live = [k["key_id"] for k in p["keys"] if not k["revoked"]]
            print(f"{p['id']:24} {','.join(p['roles']):40} {'DISABLED' if p['disabled'] else 'active':8} keys={live}")
    elif cmd == "create" and len(args) >= 2:
        print(call("POST", "/v1/admin/principals", {"id": args[0], "roles": args[1:]}))
    elif cmd == "key" and len(args) == 1:
        res = call("POST", f"/v1/admin/principals/{args[0]}/keys")
        print(f"key_id: {res['key_id']}\nkey:    {res['key']}\n(shown once; store it now)")  # type: ignore[index]
    elif cmd == "revoke" and len(args) == 1:
        print(call("DELETE", f"/v1/admin/keys/{args[0]}"))
    elif cmd == "disable" and len(args) == 1:
        print(call("POST", f"/v1/admin/principals/{args[0]}/disable"))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])

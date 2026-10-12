"""A local RFC 3161 time-stamp authority backed by the OpenSSL command line, for tests and the guided tour only.

It is NOT a trustworthy authority (anyone running it can sign any time). It exists so the timestamping code can be
exercised end to end without internet access. Production uses a public authority (DECISIONS D-031).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from veto.audit import rfc3161

CONF = """[tsa]
default_tsa = t
[t]
dir = {d}
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/tsa.crt
certs = {d}/tsa.crt
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = no
ess_cert_id_alg = sha256
"""


class Authority:
    """A time-stamp authority backed by `openssl ts -reply`, with switches for misbehaviour."""

    def __init__(self, d: Path):
        d = Path(d)
        d.mkdir(parents=True, exist_ok=True)
        self.d = d
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/tsa.key",
                        "-out", f"{d}/tsa.crt", "-days", "2", "-subj", "/CN=Test TSA",
                        "-addext", "extendedKeyUsage=critical,timeStamping"], check=True, capture_output=True)
        (d / "serial").write_text("01\n")
        (d / "tsa.cnf").write_text(CONF.format(d=d))
        self.requests = []
        self.mode = "ok"                  # ok | refuse | http500 | garbage | wrongdigest | wrongnonce
        self.ca = str(d / "tsa.crt")

    def reply(self, query: bytes) -> bytes:
        self.requests.append(query)
        (self.d / "q.tsq").write_bytes(query)
        subprocess.run(["openssl", "ts", "-reply", "-config", str(self.d / "tsa.cnf"), "-queryfile",
                        str(self.d / "q.tsq"), "-out", str(self.d / "r.tsr")], check=True, capture_output=True)
        return (self.d / "r.tsr").read_bytes()

    def __call__(self, url, body, headers, timeout):
        assert headers["Content-Type"] == "application/timestamp-query"
        if self.mode == "http500":
            return 500, b""
        if self.mode == "garbage":
            return 200, b"not der at all"
        if self.mode == "refuse":
            return 200, bytes.fromhex("30053003020122")                           # status 34 (rejection), no token
        if self.mode == "wrongdigest":                                          # a valid token for some other digest
            other, _ = rfc3161.build_request(b"\x00" * 32)
            return 200, self.reply(other)
        if self.mode == "wrongnonce":
            req, _ = rfc3161.build_request(_query_digest(body), nonce=12345)
            return 200, self.reply(req)
        return 200, self.reply(body)


def _query_digest(query: bytes) -> bytes:
    i = query.index(bytes.fromhex("0420")) + 2
    return query[i:i + 32]

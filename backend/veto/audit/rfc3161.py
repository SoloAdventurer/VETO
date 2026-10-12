"""RFC 3161 time-stamp requests and responses, small and dependency-free (DECISIONS D-031).

We build the request ourselves (a fixed, tiny DER structure), read just enough of the reply to refuse an unusable one
(status, the digest it covers, our nonce, the time it states), and leave the cryptographic check of the authority's
signature to `openssl ts -verify`, which an auditor can also run on their own machine from the stored receipt.
"""

from __future__ import annotations

import hashlib
import secrets
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

OID_SHA256 = bytes.fromhex("0609608648016503040201")
GRANTED = (0, 1)


class TimestampError(Exception):
    pass


def _len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _int(n: int) -> bytes:
    return _tlv(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def anchor_digest(tenant: str, seq: int, head_hash: str) -> bytes:
    """What is actually timestamped: the chain head, bound to its tenant and position."""
    return hashlib.sha256(f"veto-anchor-v1|{tenant}|{seq}|{head_hash}".encode()).digest()


def build_request(digest: bytes, nonce: int | None = None) -> tuple[bytes, int]:
    if len(digest) != 32:
        raise TimestampError("digest must be 32 bytes (SHA-256)")
    nonce = nonce if nonce is not None else secrets.randbits(63) + 1
    imprint = _tlv(0x30, _tlv(0x30, OID_SHA256 + b"\x05\x00") + _tlv(0x04, digest))
    return _tlv(0x30, _int(1) + imprint + _int(nonce) + _tlv(0x01, b"\xff")), nonce


def _read(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, content start, content end) of the TLV at pos."""
    try:
        tag, first = data[pos], data[pos + 1]
        pos += 2
        if first & 0x80:
            n = first & 0x7F
            if n == 0 or n > 4:
                raise TimestampError("unsupported DER length")
            length = int.from_bytes(data[pos:pos + n], "big")
            pos += n
        else:
            length = first
    except IndexError as exc:
        raise TimestampError("truncated DER") from exc
    if pos + length > len(data):
        raise TimestampError("truncated DER")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """(tag, content start, content end, element start) for each child in data[start:end]."""
    out, pos = [], start
    while pos < end:
        tag, s, e = _read(data, pos)
        out.append((tag, s, e, pos))
        pos = e
    return out


@dataclass
class Parsed:
    status: int
    token: bytes | None = None
    gen_time: str | None = None
    imprint: bytes | None = None
    nonce: int | None = None


def parse_response(data: bytes) -> Parsed:
    try:
        tag, s, e = _read(data, 0)
        if tag != 0x30:
            raise TimestampError("not a TimeStampResp")
        top = _children(data, s, e)
        stag, ss, se, _ = top[0]
        status = int.from_bytes(data[_children(data, ss, se)[0][1]:_children(data, ss, se)[0][2]], "big")
        if status not in GRANTED:
            return Parsed(status)
        tok_start, tok_end = top[1][3], top[1][2]
        token = data[tok_start:tok_end]
        ci = _children(data, top[1][1], top[1][2])                # OID, [0] content
        signed = _children(data, ci[1][1], ci[1][2])[0]            # SignedData
        parts = _children(data, signed[1], signed[2])
        encap = _children(data, parts[2][1], parts[2][2])          # OID, [0] eContent
        octet = _children(data, encap[1][1], encap[1][2])[0]       # OCTET STRING
        info = _children(data, octet[1], octet[2])[0]              # TSTInfo SEQUENCE
        fields = _children(data, info[1], info[2])
        imprint_seq = _children(data, fields[2][1], fields[2][2])
        imprint = data[imprint_seq[1][1]:imprint_seq[1][2]]
        gen = next(f for f in fields if f[0] == 0x18)
        gen_time = data[gen[1]:gen[2]].decode("ascii")
        nonce = next((int.from_bytes(data[f[1]:f[2]], "big") for f in fields[fields.index(gen) + 1:]
                      if f[0] == 0x02), None)
        return Parsed(status, token, gen_time, imprint, nonce)
    except (IndexError, StopIteration, ValueError) as exc:
        raise TimestampError("unreadable TimeStampResp") from exc


def check_reply(parsed: Parsed, digest: bytes, nonce: int) -> None:
    """Refuse a reply that does not cover our digest or does not echo our nonce (a replayed or substituted token)."""
    if parsed.status not in GRANTED or parsed.token is None:
        raise TimestampError(f"timestamp authority refused the request (status {parsed.status})")
    if parsed.imprint != digest:
        raise TimestampError("the token covers a different digest")
    if parsed.nonce != nonce:
        raise TimestampError("the token does not echo our nonce")


def openssl_verify(response: bytes, digest: bytes, ca_file: str, timeout: float = 20.0) -> None:
    """Full cryptographic check of the authority's signature with the OpenSSL command-line tool."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "r.tsr"
        f.write_bytes(response)
        try:
            run = subprocess.run(
                ["openssl", "ts", "-verify", "-in", str(f), "-digest", digest.hex(), "-CAfile", ca_file],
                capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise TimestampError("openssl is not installed, cannot verify the timestamp") from exc
        except subprocess.TimeoutExpired as exc:
            raise TimestampError("openssl timed out") from exc
    if run.returncode != 0 or "Verification: OK" not in run.stdout + run.stderr:
        raise TimestampError("the timestamp signature did not verify: " + (run.stderr or run.stdout).strip()[-200:])

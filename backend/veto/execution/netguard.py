"""Outbound HTTPS with SSRF protection (DECISIONS D-030).

A connector's URL is chosen by a tenant administrator, so it is untrusted input to the machine that holds the
network position. Rules, checked when a connector is defined AND again on every call (DNS can change):
  * https only, no credentials in the URL, port 443 or 8443, a normal length
  * every address the name resolves to must be a global unicast address (no loopback, private, link-local,
    carrier-grade NAT, multicast, reserved, or IPv4-mapped forms of those): cloud metadata services and the
    private network that holds the resources (invariant 5) are therefore unreachable
  * the connection goes to the address that was checked (pinned), not to a second lookup, with the certificate
    verified against the original host name
  * no redirects, a hard timeout, and a cap on how much of the response is read
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from collections.abc import Callable
from urllib.parse import urlsplit

ALLOWED_PORTS = (443, 8443)
ALLOWED_HTTP_PORTS = (80, 8080)
MAX_URL_CHARS = 2048
MAX_RESPONSE_BYTES = 65_536

Resolver = Callable[..., list]


class UnsafeTarget(Exception):
    """The URL or the addresses behind it are not allowed. The message never contains the URL (it can be a secret)."""


class TransportError(Exception):
    """The call failed. `sent` is True when the request may have reached the other side (outcome unknown)."""

    def __init__(self, message: str, sent: bool = False) -> None:
        super().__init__(message)
        self.sent = sent


def parse_url(url: str, allow_http: bool = False) -> tuple[str, int, str]:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        raise UnsafeTarget(f"url must be a string of 1-{MAX_URL_CHARS} characters")
    if any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise UnsafeTarget("url contains spaces, control or non-ASCII characters")
    parts = urlsplit(url)
    if parts.scheme != "https" and not (allow_http and parts.scheme == "http"):
        raise UnsafeTarget("url must use https" + (" (or http)" if allow_http else ""))
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UnsafeTarget("url must not contain credentials")
    host = parts.hostname
    try:
        port = parts.port or (80 if parts.scheme == "http" else 443)
    except ValueError as exc:
        raise UnsafeTarget("url has an invalid port") from exc
    if not host:
        raise UnsafeTarget("url has no host")
    ports = ALLOWED_HTTP_PORTS if parts.scheme == "http" else ALLOWED_PORTS
    if port not in ports:
        raise UnsafeTarget(f"port must be one of {ports}")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, path


def resolve_public(host: str, port: int, resolver: Resolver = socket.getaddrinfo,
                   allow_private: bool = False) -> list[str]:
    """All addresses for `host`, every one of which must be global. Raises UnsafeTarget otherwise."""
    try:
        literal = ipaddress.ip_address(host)             # an address needs no lookup; no resolver may rewrite it
        infos = [(0, 0, 0, "", (str(literal), port))]
    except ValueError:
        try:
            infos = resolver(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UnsafeTarget("host name does not resolve") from exc
    addrs: list[str] = []
    for info in infos:
        raw = info[4][0].split("%")[0]
        ip = ipaddress.ip_address(raw)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not allow_private and not ip.is_global:
            raise UnsafeTarget("host resolves to a non-public address")
        if raw not in addrs:
            addrs.append(raw)
    if not addrs:
        raise UnsafeTarget("host name does not resolve")
    return addrs


def validate_url(url: str, resolver: Resolver = socket.getaddrinfo) -> str:
    """Definition-time check. Returns the host (safe to display)."""
    host, port, _ = parse_url(url)
    resolve_public(host, port, resolver)
    return host


class _Pinned(http.client.HTTPSConnection):
    """Connects to a vetted address while verifying the certificate for the original host name."""

    def __init__(self, host: str, port: int, ip: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)    # type: ignore[attr-defined]


class _PinnedHttp(http.client.HTTPConnection):
    """Plain HTTP to a vetted address. Only for operator-chosen endpoints whose replies are signed (RFC 3161)."""

    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def post(url: str, body: bytes, headers: dict[str, str], timeout: float, *, resolver: Resolver = socket.getaddrinfo,
         context: ssl.SSLContext | None = None, allow_private: bool = False,
         allow_http: bool = False) -> tuple[int, bytes]:
    """POST `body`. `context` and `allow_private` exist for tests against a local server; production never sets them.
    `allow_http` is for the timestamp authority only (its replies carry their own signature)."""
    host, port, path = parse_url(url, allow_http)
    plain = url.startswith("http://")
    ips = resolve_public(host, port, resolver, allow_private)
    ctx = context or ssl.create_default_context()
    last: Exception | None = None
    for ip in ips:
        conn: http.client.HTTPConnection = (_PinnedHttp(host, port, ip, timeout) if plain
                                            else _Pinned(host, port, ip, timeout, ctx))
        try:
            try:
                conn.connect()
            except (OSError, ssl.SSLError) as exc:
                last = exc
                continue                                          # nothing was sent: try the next vetted address
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read(MAX_RESPONSE_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                raise TransportError(f"{type(exc).__name__} after the request was sent", sent=True) from exc
            if len(data) > MAX_RESPONSE_BYTES:
                data = data[:MAX_RESPONSE_BYTES]
            return resp.status, data
        finally:
            conn.close()
    raise TransportError(f"could not connect ({type(last).__name__ if last else 'no address'})", sent=False)

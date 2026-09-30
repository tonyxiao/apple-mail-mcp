"""Loopback-only, authenticated Streamable HTTP inbound adapter.

The token is read once at startup; rotate it by restarting the service.
Every endpoint, including health, shares the same authentication boundary.
"""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import os
from pathlib import Path
import stat
import sys
from urllib.parse import urlsplit

from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

MAX_REQUEST_BYTES = 1024 * 1024


def load_token(path: str | Path) -> bytes:
    """Open without following symlinks, and validate the opened inode."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
                raise ValueError("token file must be owned by this user with mode 0400 or 0600")
            raw = stream.read(4099)
            if len(raw) > 4098:
                raise ValueError("token file is too large")
            token = raw.rstrip(b"\r\n")
    except OSError:
        raise ValueError("token file cannot be opened securely") from None
    if not 32 <= len(token) <= 4096 or any(c < 33 or c > 126 for c in token):
        raise ValueError("token file must contain 32–4096 printable ASCII characters without whitespace")
    return token


class _Boundary:
    """Pure ASGI middleware: authenticate before buffering a bounded body."""

    def __init__(self, app: ASGIApp, token: bytes, hosts: list[str], origins: list[str]):
        self.app, self.token = app, token
        self.hosts, self.origins = frozenset(hosts), frozenset(origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = scope["headers"]

        def values(name: bytes) -> list[bytes]:
            return [value for key, value in headers if key.lower() == name]

        authorization = values(b"authorization")
        if len(authorization) != 1 or not hmac.compare_digest(
                authorization[0], b"Bearer " + self.token):
            await JSONResponse({"error": "unauthorized"}, status_code=401,
                               headers={"WWW-Authenticate": "Bearer"})(scope, receive, send)
            return
        hosts, origins = values(b"host"), values(b"origin")
        if (len(hosts) != 1 or hosts[0].decode("latin-1") not in self.hosts
                or len(origins) > 1
                or (origins and origins[0].decode("latin-1") not in self.origins)):
            await JSONResponse({"error": "untrusted host or origin"}, status_code=403)(scope, receive, send)
            return
        lengths = values(b"content-length")
        if lengths:
            try:
                declared = int(lengths[0]) if len(lengths) == 1 else -1
            except ValueError:
                declared = -1
            if declared < 0:
                await JSONResponse({"error": "invalid content length"}, status_code=400)(scope, receive, send)
                return
            if declared > MAX_REQUEST_BYTES:
                await JSONResponse({"error": "request too large"}, status_code=413)(scope, receive, send)
                return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_REQUEST_BYTES:
                await JSONResponse({"error": "request too large"}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(*, token_file: str | Path, host: str = "127.0.0.1", port: int = 58435,
               name: str = "apple-mail", allowed_origins: list[str] | None = None) -> ASGIApp:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("host must be a literal loopback IP address") from None
    if not address.is_loopback:
        raise ValueError("host must be a literal loopback IP address")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    origins = list(allowed_origins or [])
    for origin in origins:
        parsed = urlsplit(origin)
        if (parsed.scheme not in ("https", "http") or not parsed.hostname
                or parsed.username or parsed.password or parsed.path
                or parsed.query or parsed.fragment or "*" in origin):
            raise ValueError("allowed origin must be an exact http(s) origin without a path")
    token = load_token(token_file)
    authority = f"[{address}]" if address.version == 6 else str(address)
    hosts = [f"{authority}:{port}", f"localhost:{port}"]
    from .server import _build_mcp_server

    server = _build_mcp_server(name=name)
    app = server.streamable_http_app(
        stateless_http=True, json_response=True, host=host,
        max_request_body_size=MAX_REQUEST_BYTES,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins),
    )

    async def health(request):
        return JSONResponse({"ok": True})

    app.routes.append(Route("/healthz", health, methods=["GET"]))
    return _Boundary(app, token, hosts, origins)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apple-mailbox-mcp http")
    parser.add_argument("--host", default="127.0.0.1", help="literal loopback address")
    parser.add_argument("--port", type=int, default=58435)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--name", default="apple-mail", help="MCP backend identity")
    parser.add_argument("--allowed-origin", action="append", default=[], help="exact browser origin (repeatable)")
    args = parser.parse_args(argv)
    try:
        app = create_app(token_file=args.token_file, host=args.host, port=args.port,
                         name=args.name, allowed_origins=args.allowed_origin)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False, access_log=False,
                log_level="warning")
    return 0

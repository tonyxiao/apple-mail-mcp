"""Authenticated HTTP boundary and MCP round trips against fixture mail."""
import asyncio
import os
import socket
import subprocess
import time

import pytest
import httpx2 as httpx
from starlette.testclient import TestClient

from email_mcp import cli

TOKEN = "a" * 48
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def token_file(tmp_path):
    path = tmp_path / "token"
    path.write_text(TOKEN + "\n")
    path.chmod(0o600)
    return path


def app(tmp_path, **kwargs):
    from email_mcp.http import create_app
    return create_app(token_file=token_file(tmp_path), **kwargs)


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"},
                                     {"Authorization": TOKEN}])
def test_http_requires_bearer_for_mcp_and_health(tmp_path, headers):
    with TestClient(app(tmp_path), base_url="http://127.0.0.1:58435") as client:
        for path in ("/mcp", "/healthz"):
            response = client.get(path, headers=headers)
            assert response.status_code == 401
            assert TOKEN not in response.text


def test_health_is_minimal_and_authenticated(tmp_path):
    with TestClient(app(tmp_path), base_url="http://127.0.0.1:58435") as client:
        assert client.get("/healthz", headers=AUTH).json() == {"ok": True}


@pytest.mark.parametrize("headers", [
    {"Host": "attacker.invalid:58435"},
    {"Host": "127.0.0.1:9999"},
    {"Origin": "https://attacker.invalid"},
    {"Origin": "null"},
])
def test_rejects_untrusted_host_and_origin(tmp_path, headers):
    with TestClient(app(tmp_path), base_url="http://127.0.0.1:58435") as client:
        assert client.get("/healthz", headers=AUTH | headers).status_code == 403


def test_accepts_explicit_origin(tmp_path):
    with TestClient(app(tmp_path, allowed_origins=["https://mail.example.com"]),
                    base_url="http://127.0.0.1:58435") as client:
        assert client.get("/healthz", headers=AUTH | {
            "Origin": "https://mail.example.com"}).status_code == 200


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o700])
def test_token_file_requires_private_permissions(tmp_path, mode):
    from email_mcp.http import load_token
    path = token_file(tmp_path)
    path.chmod(mode)
    with pytest.raises(ValueError, match="token file"):
        load_token(path)


def test_missing_short_and_symlink_token_files_fail_closed(tmp_path):
    from email_mcp.http import load_token
    with pytest.raises(ValueError, match="token file"):
        load_token(tmp_path / "missing")
    path = token_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="token file"):
        load_token(link)
    path.write_text("short")
    with pytest.raises(ValueError, match="token file"):
        load_token(path)


def test_token_file_requires_current_user_ownership(tmp_path, monkeypatch):
    from email_mcp.http import load_token
    monkeypatch.setattr(os, "getuid", lambda: 999999)
    with pytest.raises(ValueError, match="token file"):
        load_token(token_file(tmp_path))


def test_token_file_cannot_hide_content_beyond_read_limit(tmp_path):
    from email_mcp.http import load_token
    path = token_file(tmp_path)
    path.write_text("a" * 4096 + "\n" + "hidden-content")
    with pytest.raises(ValueError, match="token file"):
        load_token(path)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.1", "localhost"])
def test_binding_rejects_non_literal_loopback(tmp_path, host):
    with pytest.raises(ValueError, match="loopback"):
        app(tmp_path, host=host)


def test_limits_request_body(tmp_path):
    with TestClient(app(tmp_path), base_url="http://127.0.0.1:58435") as client:
        response = client.post("/mcp", headers=AUTH, content=b"x" * (1024 * 1024 + 1))
        assert response.status_code == 413


def test_limits_chunked_request_without_content_length(tmp_path):
    with TestClient(app(tmp_path), base_url="http://127.0.0.1:58435") as client:
        response = client.post("/mcp", headers=AUTH,
                               content=iter([b"x" * (512 * 1024)] * 3))
        assert response.status_code == 413


@pytest.mark.parametrize("duplicate,status", [("Authorization", 401), ("Host", 403), ("Origin", 403)])
def test_rejects_duplicate_security_headers(tmp_path, duplicate, status):
    headers = list(AUTH.items())
    if duplicate == "Authorization":
        headers.append((duplicate, f"Bearer {TOKEN}"))
    else:
        value = "127.0.0.1:58435" if duplicate == "Host" else "https://mail.example.com"
        headers.extend([(duplicate, value), (duplicate, value)])
    with TestClient(app(tmp_path, allowed_origins=["https://mail.example.com"]),
                    base_url="http://127.0.0.1:58435") as client:
        assert client.get("/healthz", headers=headers).status_code == status


@pytest.mark.parametrize("origin", ["*", "null", "https://mail.example.com/",
                                     "https://user:password@mail.example.com"])
def test_requires_exact_origin_configuration(tmp_path, origin):
    with pytest.raises(ValueError, match="origin"):
        app(tmp_path, allowed_origins=[origin])


def test_http_cli_rejects_missing_token_without_serving(tmp_path, capsys):
    result = cli.main(["http", "--token-file", str(tmp_path / "missing")])
    assert result == 2
    assert "token file" in capsys.readouterr().err


def test_real_http_initialize_discovery_query_and_schema(tmp_path, mail_fixture, monkeypatch):
    monkeypatch.setenv("EMAIL_MCP_MAIL_DIR", str(mail_fixture))
    monkeypatch.setenv("EMAIL_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("EMAIL_MCP_READ_ONLY", "0")
    from tests.test_mcp_wire import ALL_TOOLS
    with TestClient(app(tmp_path, name="apple-mail-tx-m5"),
                    base_url="http://127.0.0.1:58435") as client:
        def rpc(method, params):
            response = client.post("/mcp", headers=AUTH | {
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-06-18",
            }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            assert response.status_code == 200, response.text
            return response.json()["result"]

        initialized = rpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "http-test", "version": "0"},
        })
        assert initialized["serverInfo"]["name"] == "apple-mail-tx-m5"
        assert {t["name"] for t in rpc("tools/list", {})["tools"]} == ALL_TOOLS
        query = rpc("tools/call", {"name": "query_mail_sql", "arguments": {
            "sql": "SELECT count(*) AS n FROM messages"}})["structuredContent"]
        assert query["ok"] and query["rows"][0][0] > 0
        schema = rpc("tools/call", {"name": "get_mail_schema", "arguments": {
            "tables": ["messages"]}})["structuredContent"]
        assert schema["ok"] and schema["tables"][0]["name"] == "messages"


def test_cli_serves_real_tcp_and_sdk_client(tmp_path, mail_fixture):
    """Exercise the shipped entry point, Uvicorn and SDK client together."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    import httpx2
    from tests.test_mcp_wire import ALL_TOOLS, _server_command, _server_env

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    path = token_file(tmp_path)
    process = subprocess.Popen(
        _server_command() + ["http", "--host", "127.0.0.1", "--port", str(port),
                             "--token-file", str(path), "--name", "apple-mail-cs-mini"],
        env=_server_env(tmp_path, mail_fixture, EMAIL_MCP_READ_ONLY="0"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        with httpx.Client(timeout=1, trust_env=False) as probe:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "HTTP CLI exited before becoming ready"
                try:
                    response = probe.get(url + "/healthz", headers=AUTH)
                    if response.status_code == 200:
                        break
                except httpx.ConnectError:
                    pass
                assert time.monotonic() < deadline, "HTTP CLI did not become ready"
                time.sleep(0.05)
            assert probe.get(url + "/healthz").status_code == 401

        async def talk():
            async with httpx2.AsyncClient(headers=AUTH, trust_env=False) as http_client:
                async with streamable_http_client(url + "/mcp", http_client=http_client) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        initialized = await session.initialize()
                        assert initialized.server_info.name == "apple-mail-cs-mini"
                        assert {t.name for t in (await session.list_tools()).tools} == ALL_TOOLS
                        query = await session.call_tool("query_mail_sql", {"sql": "SELECT 7 AS n"})
                        assert query.structured_content["rows"] == [[7]]
                        schema = await session.call_tool("get_mail_schema", {"tables": ["messages"]})
                        assert schema.structured_content["tables"][0]["name"] == "messages"

        asyncio.run(asyncio.wait_for(talk(), 15))
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
        assert TOKEN.encode() not in stdout + stderr
        assert b"fixture topic" not in stdout + stderr

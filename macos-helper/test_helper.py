"""Native embedded-process tests; all mail and state are disposable fixtures."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import plistlib
import shutil
import socket
import subprocess
import sys
import time

import httpx2 as httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "macos-helper/build.py"
pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="native macOS app")


def test_native_builder_exists():
    assert BUILD.is_file(), "dedicated embedded helper builder is missing"


@pytest.fixture(scope="module")
def helper(tmp_path_factory):
    directory = tmp_path_factory.mktemp("embedded-helper")
    site = directory / "site-packages"
    site.mkdir()
    # A real installed package, not editable .pth hooks (site is disabled).
    import mcp
    dependency_site = Path(mcp.__file__).resolve().parent.parent
    for dependency in dependency_site.iterdir():
        if dependency.name.startswith(("__editable", "email_mcp", "apple_mailbox")):
            continue
        (site / dependency.name).symlink_to(dependency)
    shutil.copytree(ROOT / "email_mcp", site / "email_mcp")
    # Even a .pth in the explicit dependency site must never execute.
    (site / "unsafe.pth").write_text("import os; os._exit(91)\n")
    (site / "sitecustomize.py").write_text("import os; os._exit(92)\n")
    bundle = directory / "Apple Mayo MCP.app"
    subprocess.run([sys.executable, str(BUILD), "--python", sys.executable,
                    "--site-packages", str(site), "--output", str(bundle)], check=True)
    return bundle


def executable(helper):
    return helper / "Contents/MacOS/apple-mayo-mcp"


def environment(tmp_path):
    from tests.conftest import _build_envelope_index, _build_emlx_tree
    mail = tmp_path / "V10"
    _build_envelope_index(mail / "MailData/Envelope Index")
    _build_emlx_tree(mail)
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("EMAIL_MCP_", "APPLE_MAIL_MCP_", "PYTHON"))}
    env.update(HOME=str(home), EMAIL_MCP_MAIL_DIR=str(mail),
               EMAIL_MCP_STATE_DIR=str(tmp_path / "state"))
    return env


@pytest.mark.parametrize("args", [
    ["-c", "print('unsafe')"], ["-m", "email_mcp.cli"], ["http"], ["--help"],
    ["--fts", "--limit", "999999"], ["--stdio", "--selftest"],
    ["--sql", "fts"], ["--sql"], ["--sql", "query", "SELECT 1", "--unknown"],
])
def test_rejects_arbitrary_modes_and_arguments(helper, tmp_path, args):
    result = subprocess.run([str(executable(helper)), *args], env=environment(tmp_path),
                            capture_output=True, timeout=10)
    assert result.returncode == 2


def test_codesigned_bundle_has_dedicated_identity(helper):
    plist = plistlib.loads((helper / "Contents/Info.plist").read_bytes())
    assert plist["CFBundleIdentifier"] == "com.tonyxiao.apple-mayo-mcp"
    assert plist["CFBundleExecutable"] == "apple-mayo-mcp"
    subprocess.run(["codesign", "--verify", "--strict", str(helper)], check=True)
    result = subprocess.run(["codesign", "-d", "--verbose=4", str(helper)],
                            capture_output=True, check=True)
    assert b"Identifier=com.tonyxiao.apple-mayo-mcp" in result.stderr
    assert b"Signature=adhoc" in result.stderr
    assert b"runtime" in result.stderr
    entitlements = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(helper)],
                                 capture_output=True, check=True)
    assert plistlib.loads(entitlements.stdout) == {
        "com.apple.security.cs.disable-library-validation": True,
    }
    designated = subprocess.run(["codesign", "-d", "-r-", str(helper)], capture_output=True, check=True)
    assert b"designated =>" in designated.stdout


def poison_python_environment(env, tmp_path):
    malicious = tmp_path / "poison"
    malicious.mkdir()
    marker = tmp_path / "python-env-was-loaded"
    code = f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\nraise RuntimeError('untrusted import')\n"
    for name in ["sitecustomize.py", "email_mcp.py", "json.py"]:
        (malicious / name).write_text(code)
    env.update(PYTHONPATH=str(malicious), PYTHONHOME=str(malicious),
               PYTHONSTARTUP=str(malicious / "sitecustomize.py"),
               PYTHONUSERBASE=str(malicious), PYTHONINSPECT="1")
    return malicious, marker


def test_native_sql_ignores_python_environment_and_cwd(helper, tmp_path):
    env = environment(tmp_path)
    cwd, marker = poison_python_environment(env, tmp_path)
    result = subprocess.run([str(executable(helper)), "--sql", "query", "SELECT 7 AS n"],
                            env=env, cwd=cwd, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode()
    assert json.loads(result.stdout)["rows"] == [[7]]
    assert not marker.exists()
    denied = subprocess.run([str(executable(helper)), "--sql", "query", "DELETE FROM messages"],
                            env=env, cwd=cwd, capture_output=True, timeout=15)
    assert denied.returncode != 0
    assert not json.loads(denied.stdout)["ok"]


def test_hardened_runtime_ignores_dyld_insertion(helper, tmp_path):
    env = environment(tmp_path)
    source = tmp_path / "injected.c"
    source.write_text('#include <stdio.h>\n#include <stdlib.h>\n'
                      '__attribute__((constructor)) static void injected(void) {'
                      'FILE *f=fopen(getenv("HELPER_POISON_MARKER"),"w"); if(f){fputs("loaded",f);fclose(f);}}\n')
    library = tmp_path / "injected.dylib"
    subprocess.run(["cc", "-dynamiclib", str(source), "-o", str(library)], check=True)
    subprocess.run(["codesign", "--sign", "-", str(library)], check=True)
    marker = tmp_path / "dyld-was-loaded"
    env.update(DYLD_INSERT_LIBRARIES=str(library), DYLD_LIBRARY_PATH=str(tmp_path),
               HELPER_POISON_MARKER=str(marker))
    result = subprocess.run([str(executable(helper)), "--sql", "query", "SELECT 7 AS n"],
                            env=env, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode()
    assert json.loads(result.stdout)["rows"] == [[7]]
    assert not marker.exists()


def test_fixed_fts_sync_and_stdio_modes(helper, tmp_path):
    env = environment(tmp_path)
    result = subprocess.run([str(executable(helper)), "--fts"], env=env,
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode()
    result = subprocess.run([str(executable(helper)), "--stdio"], env=env,
                            input=b"", capture_output=True, timeout=15)
    assert result.returncode == 0 and result.stdout == b""


@pytest.mark.parametrize("key,value", [
    ("APPLE_MAIL_MCP_HOST", "0.0.0.0"), ("APPLE_MAIL_MCP_PORT", "8080"),
    ("APPLE_MAIL_MCP_NAME", "arbitrary"), ("APPLE_MAIL_MCP_ORIGIN", "http://mail.invalid"),
    ("APPLE_MAIL_MCP_TOKEN_FILE", "relative/token"), ("PYTHONPATH", "/tmp/unsafe"),
])
def test_rejects_unsafe_configuration(helper, tmp_path, key, value):
    env = environment(tmp_path)
    config = tmp_path / "service.env"
    values = {"APPLE_MAIL_MCP_NAME": "apple-mail-tx-m5",
              "APPLE_MAIL_MCP_ORIGIN": "https://mail.example.com",
              "APPLE_MAIL_MCP_TOKEN_FILE": "/tmp/nonexistent-private-token", key: value}
    config.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    config.chmod(0o600)
    env["APPLE_MAIL_MCP_ENV_FILE"] = str(config)
    result = subprocess.run([str(executable(helper))], env=env, capture_output=True, timeout=10)
    assert result.returncode == 2


@pytest.mark.parametrize("kind", ["public", "symlink", "duplicate"])
def test_rejects_insecure_configuration_files(helper, tmp_path, kind):
    env = environment(tmp_path)
    config = tmp_path / "service.env"
    config.write_text("EMAIL_MCP_STATE_DIR=/tmp/state\n")
    config.chmod(0o600)
    if kind == "public":
        config.chmod(0o644)
    elif kind == "symlink":
        link = tmp_path / "link.env"
        link.symlink_to(config)
        config = link
    else:
        config.write_text("EMAIL_MCP_STATE_DIR=/tmp/state\n" * 2)
    env["APPLE_MAIL_MCP_ENV_FILE"] = str(config)
    result = subprocess.run([str(executable(helper)), "--stdio"], env=env,
                            input=b"", capture_output=True, timeout=10)
    assert result.returncode == 2


def test_embedded_http_native_pid_and_mail_sql(helper, tmp_path):
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", 58435))
        except OSError:
            pytest.skip("fixed helper port 58435 is occupied; do not change a live service for tests")
    env = environment(tmp_path)
    cwd, marker = poison_python_environment(env, tmp_path)
    token = tmp_path / "token"
    token.write_text("t" * 48)
    token.chmod(0o600)
    # Config is parsed as data. No source/eval, and no arbitrary env keys.
    config = tmp_path / "service.env"
    config.write_text("APPLE_MAIL_MCP_NAME=apple-mail-tx-m5\n"
                      "APPLE_MAIL_MCP_ORIGIN=https://tx-m5.meteor-ruffe.ts.net\n"
                      "APPLE_MAIL_MCP_HUB_ORIGIN=https://mcphub.meteor-ruffe.ts.net\n"
                      f"APPLE_MAIL_MCP_TOKEN_FILE='{token}'\n")
    config.chmod(0o600)
    env["APPLE_MAIL_MCP_ENV_FILE"] = str(config)
    process = subprocess.Popen([str(executable(helper))], env=env, cwd=cwd,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with httpx.Client(timeout=2, trust_env=False) as client:
            headers = {"Authorization": "Bearer " + "t" * 48,
                       "Accept": "application/json, text/event-stream"}
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "native helper exited before readiness"
                try:
                    if client.get("http://127.0.0.1:58435/healthz", headers=headers).status_code == 200:
                        break
                except httpx.ConnectError:
                    pass
                assert time.monotonic() < deadline
                time.sleep(0.05)
            assert client.get("http://127.0.0.1:58435/healthz").status_code == 401
            def rpc(method, params):
                response = client.post("http://127.0.0.1:58435/mcp", headers=headers,
                                       json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
                assert response.status_code == 200, response.text
                return response.json()["result"]
            initialized = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "native-helper-test", "version": "0"}})
            assert initialized["serverInfo"]["name"] == "apple-mail-tx-m5"
            assert len(rpc("tools/list", {})["tools"]) == 23
            query = rpc("tools/call", {"name": "query_mail_sql", "arguments": {
                "sql": "SELECT count(*) FROM messages"}})["structuredContent"]
            assert query["ok"] and query["rows"][0][0] > 0
            schema = rpc("tools/call", {"name": "get_mail_schema", "arguments": {
                "tables": ["messages"]}})["structuredContent"]
            assert schema["ok"] and schema["tables"][0]["name"] == "messages"
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        buffer = ctypes.create_string_buffer(4096)
        assert libproc.proc_pidpath(process.pid, buffer, len(buffer)) > 0
        assert Path(os.fsdecode(buffer.value)).resolve() == executable(helper).resolve()
        comm = subprocess.check_output(["ps", "-p", str(process.pid), "-o", "comm="], text=True).strip()
        assert "apple-mayo-mcp" in comm and "python" not in comm.lower()
        assert not marker.exists()
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
        assert b"t" * 48 not in stdout + stderr

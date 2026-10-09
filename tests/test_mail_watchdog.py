"""tools/mail_watchdog.py: decision rules over injected seams — no Mail."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest


def _load():
    path = Path(__file__).resolve().parent.parent / "tools" / "mail_watchdog.py"
    spec = importlib.util.spec_from_file_location("mail_watchdog", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mail_watchdog = _load()
MailWatchdog = mail_watchdog.MailWatchdog

MINUTE = 60.0


class FakeMail:
    """Stands in for every side effect the watchdog may cause."""

    def __init__(self, *, pid=1296, rowid=526728, stalled=False):
        self.pid = pid
        self.rowid = rowid
        self.stalled = stalled
        self.calls: list[str] = []

    def running_pid(self):
        return self.pid

    def newest_rowid(self):
        return self.rowid

    def connections_stalled(self, pid):
        self.calls.append("lsof")
        return self.stalled

    def sample(self, pid, path):
        self.calls.append(f"sample:{pid}")
        path.write_text("stack")

    def terminate(self, pid):
        self.calls.append(f"terminate:{pid}")
        self.pid = None

    def launch(self):
        self.calls.append("launch")
        self.pid = 4242


@pytest.fixture
def state(tmp_path):
    return tmp_path / "mail-watchdog"


def run(fake, state, minute):
    return MailWatchdog(fake, state, clock=lambda: minute * MINUTE).run()


def stale(fake, state):
    """Observe the index once at minute 0 so later passes see it stand still."""
    run(fake, state, 0)
    fake.calls.clear()


BACKSTOP = mail_watchdog.BACKSTOP_AFTER / MINUTE


def test_first_pass_never_acts_on_missing_history(state):
    fake = FakeMail(stalled=True)
    assert run(fake, state, 5000)["status"] == "healthy"
    assert fake.calls == []


def test_new_mail_is_healthy_without_inspecting_mail(state):
    fake = FakeMail(stalled=True)
    stale(fake, state)
    fake.rowid += 5
    assert run(fake, state, 45)["status"] == "healthy"
    assert fake.calls == []


def test_quiet_inbox_with_live_connections_is_left_alone(state):
    """Measured 2026-10-09: a healthy Mail times out on scripted account
    queries too, so only the network state may tell a quiet inbox from a
    wedge."""
    fake = FakeMail(stalled=False)
    stale(fake, state)
    for minute in range(30, 300):
        report = run(fake, state, minute)
    assert report["status"] == "quiet"
    assert report["consecutive_failures"] == 0
    assert not any(c.startswith("terminate") for c in fake.calls)


def test_restarts_after_repeated_stalled_connections(state):
    fake = FakeMail(stalled=True)
    stale(fake, state)
    first, second = run(fake, state, 30), run(fake, state, 31)
    assert first["status"] == second["status"] == "unresponsive"
    assert first["evidence"] == "connections_stalled"
    assert not any(c.startswith("terminate") for c in fake.calls)

    third = run(fake, state, 32)
    assert third["status"] == "restarted"
    assert fake.calls[-3:] == ["sample:1296", "terminate:1296", "launch"]
    assert third["sample"].endswith(".txt")
    assert third["consecutive_failures"] == 0


def test_a_recovered_connection_resets_the_count(state):
    fake = FakeMail(stalled=True)
    stale(fake, state)
    run(fake, state, 30)
    run(fake, state, 31)
    fake.stalled = False
    assert run(fake, state, 32)["consecutive_failures"] == 0
    fake.stalled = True
    assert run(fake, state, 33)["status"] == "unresponsive"


def test_long_silence_backstop_restarts_even_with_live_connections(state):
    fake = FakeMail(stalled=False)
    stale(fake, state)
    reports = [run(fake, state, BACKSTOP + m) for m in range(3)]
    assert reports[0]["evidence"] == "long_silence"
    assert reports[-1]["status"] == "restarted"


def test_restart_opens_a_fresh_window_instead_of_looping(state):
    fake = FakeMail(stalled=False)
    stale(fake, state)
    for m in range(3):
        run(fake, state, BACKSTOP + m)
    fake.calls.clear()
    for m in range(3, 600):
        report = run(fake, state, BACKSTOP + m)
    assert "launch" not in fake.calls
    assert report["status"] == "quiet"


def test_restart_cooldown_prevents_a_restart_loop(state):
    fake = FakeMail(stalled=True)
    stale(fake, state)
    for minute in (30, 31, 32):
        run(fake, state, minute)
    fake.calls.clear()
    for minute in range(62, 70):
        report = run(fake, state, minute)
    assert report["status"] == "unresponsive"
    assert report["cooldown_until"]
    assert "launch" not in fake.calls


def test_missing_mail_is_launched(state):
    fake = FakeMail(pid=None)
    report = run(fake, state, 10)
    assert report["status"] == "launched"
    assert fake.calls == ["launch"]


def test_missing_mail_is_not_relaunched_inside_the_cooldown(state):
    fake = FakeMail(pid=None)
    run(fake, state, 10)
    fake.pid = None
    assert run(fake, state, 11)["status"] == "not_running"
    assert fake.calls == ["launch"]


def test_unreadable_index_is_reported_not_acted_on(state):
    fake = FakeMail(rowid=None, stalled=True)
    for minute in range(0, 100, 10):
        assert run(fake, state, minute)["status"] == "index_unavailable"
    assert fake.calls == []


def test_samples_are_pruned_to_the_newest_few(state):
    fake = FakeMail(stalled=True)
    stale(fake, state)
    minute = 30
    for _ in range(mail_watchdog.KEEP_SAMPLES + 2):
        for _ in range(mail_watchdog.FAILURES_BEFORE_RESTART):
            run(fake, state, minute)
            minute += 1
        minute += 120
        fake.pid = 1296
    assert len(list(state.glob("sample-*.txt"))) == mail_watchdog.KEEP_SAMPLES


def test_state_survives_a_corrupt_file(state):
    fake = FakeMail(stalled=True)
    stale(fake, state)
    (state / "state.json").write_text("{not json")
    assert run(fake, state, 30)["status"] == "healthy"
    report = run(fake, state, 60)
    assert report["consecutive_failures"] == 1
    assert json.loads((state / "state.json").read_text())["consecutive_failures"] == 1


def test_newest_rowid_reads_the_fts_index(tmp_path):
    db = tmp_path / "fts.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO meta VALUES ('last_rowid', '527477')")
    conn.commit()
    conn.close()
    assert mail_watchdog.SystemMail(db).newest_rowid() == 527477
    assert mail_watchdog.SystemMail(tmp_path / "absent.db").newest_rowid() is None


LSOF_HEADER = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
WEDGED_LSOF = LSOF_HEADER + "".join(
    f"Mail 1296 claudia {fd}u IPv6 0x1 0t0 TCP "
    f"[2600:1700::7abe]:{port}->[2607:f8b0:4002:c05::6c]:993 (CLOSE_WAIT)\n"
    for fd, port in ((30, 53732), (31, 54587), (32, 57623))
)


@pytest.mark.parametrize("output,stalled", [
    (WEDGED_LSOF, True),
    (WEDGED_LSOF.replace("(CLOSE_WAIT)\n", "(ESTABLISHED)\n", 1), False),
    (LSOF_HEADER, False),
])
def test_connections_stalled_reads_lsof(monkeypatch, output, stalled):
    class Done:
        stdout = output

    monkeypatch.setattr(mail_watchdog.subprocess, "run", lambda *a, **k: Done)
    assert mail_watchdog.SystemMail(Path("/nonexistent")).connections_stalled(1296) is stalled


def test_main_reports_errors_instead_of_crashing(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("EMAIL_MCP_STATE_DIR", str(tmp_path))

    def boom(self):
        raise RuntimeError("pgrep exploded")

    monkeypatch.setattr(mail_watchdog.SystemMail, "running_pid", boom)
    assert mail_watchdog.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "error"
    assert "pgrep exploded" in report["error"]


def test_plist_runs_the_installed_copy_every_minute(tmp_path):
    plist = mail_watchdog.plist_content(tmp_path / "w.py", tmp_path / "w.log")
    assert "<string>/usr/bin/python3</string>" in plist
    assert f"<string>{tmp_path / 'w.py'}</string>" in plist
    assert "<key>StartInterval</key><integer>60</integer>" in plist


def test_live_https_does_not_mask_stalled_imap(monkeypatch):
    class Done:
        stdout = WEDGED_LSOF + (
            "Mail 1296 claudia 40u IPv6 0x1 0t0 TCP "
            "[2600:1700::7abe]:60001->[17.248.0.1]:443 (ESTABLISHED)\n")

    monkeypatch.setattr(mail_watchdog.subprocess, "run", lambda *a, **k: Done)
    assert mail_watchdog.SystemMail(Path("/nonexistent")).connections_stalled(1296)

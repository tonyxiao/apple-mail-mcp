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
ProbeResult = mail_watchdog.ProbeResult

MINUTE = 60.0


class FakeMail:
    """Stands in for every side effect the watchdog may cause."""

    def __init__(self, *, pid=1296, rowid=526728, probe=ProbeResult.OK,
                 stalled=False):
        self.pid = pid
        self.rowid = rowid
        self.probe_result = probe
        self.stalled = stalled
        self.calls: list[str] = []

    def running_pid(self):
        return self.pid

    def newest_rowid(self):
        return self.rowid

    def probe(self, timeout):
        self.calls.append("probe")
        return self.probe_result

    def connections_stalled(self, pid):
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


def test_first_pass_never_acts_on_missing_history(state):
    fake = FakeMail(probe=ProbeResult.TIMEOUT)
    assert run(fake, state, 500)["status"] == "healthy"
    assert fake.calls == []


def test_new_mail_is_healthy_without_poking_mail(state):
    fake = FakeMail(probe=ProbeResult.TIMEOUT)
    stale(fake, state)
    fake.rowid += 5
    report = run(fake, state, 45)
    assert report["status"] == "healthy"
    assert fake.calls == []


def test_quiet_index_with_responsive_mail_is_quiet_and_clears_failures(state):
    fake = FakeMail(probe=ProbeResult.TIMEOUT)
    stale(fake, state)
    run(fake, state, 30)
    fake.probe_result = ProbeResult.OK
    report = run(fake, state, 31)
    assert report["status"] == "quiet"
    assert report["consecutive_failures"] == 0


def test_restarts_only_after_repeated_unanswered_probes(state):
    fake = FakeMail(probe=ProbeResult.TIMEOUT)
    stale(fake, state)
    first, second = run(fake, state, 30), run(fake, state, 31)
    assert first["status"] == second["status"] == "unresponsive"
    assert first["evidence"] == "probe_timeout"
    assert not any(c.startswith("terminate") for c in fake.calls)

    third = run(fake, state, 32)
    assert third["status"] == "restarted"
    assert fake.calls[-3:] == ["sample:1296", "terminate:1296", "launch"]
    assert third["sample"].endswith(".txt")
    assert third["consecutive_failures"] == 0


def test_restart_cooldown_prevents_a_restart_loop(state):
    fake = FakeMail(probe=ProbeResult.TIMEOUT)
    stale(fake, state)
    for minute in (30, 31, 32):
        run(fake, state, minute)
    fake.calls.clear()
    for minute in (33, 34, 35, 36):
        report = run(fake, state, minute)
    assert report["status"] == "unresponsive"
    assert report["cooldown_until"]
    assert "launch" not in fake.calls


def test_unauthorized_probe_never_counts_toward_a_restart(state):
    fake = FakeMail(probe=ProbeResult.UNAVAILABLE)
    stale(fake, state)
    for minute in range(30, 40):
        report = run(fake, state, minute)
    assert report["status"] == "probe_unavailable"
    assert report["consecutive_failures"] == 0
    assert not any(c.startswith("terminate") for c in fake.calls)


def test_stalled_connections_stand_in_for_an_unauthorized_probe(state):
    """The 2026-10-05 wedge also left every IMAP socket in CLOSE_WAIT —
    evidence that needs no Apple Events grant."""
    fake = FakeMail(probe=ProbeResult.UNAVAILABLE, stalled=True)
    stale(fake, state)
    for minute in (30, 31):
        report = run(fake, state, minute)
        assert report["status"] == "unresponsive"
        assert report["evidence"] == "connections_stalled"
    assert run(fake, state, 32)["status"] == "restarted"


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
    fake = FakeMail(rowid=None, probe=ProbeResult.TIMEOUT)
    for minute in range(0, 100, 10):
        assert run(fake, state, minute)["status"] == "index_unavailable"
    assert fake.calls == []


def test_samples_are_pruned_to_the_newest_few(state):
    fake = FakeMail(probe=ProbeResult.TIMEOUT)
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
    fake = FakeMail(probe=ProbeResult.TIMEOUT)
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

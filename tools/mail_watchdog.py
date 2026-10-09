#!/usr/bin/env python3
"""Keep the Mail.app this MCP reads from alive.

Mail can wedge with its sync engine deadlocked on its own database lock
and then sit silently for days: observed 2026-10-05, nineteen threads parked
in EDPersistenceDatabaseConnectionPool, every IMAP socket in CLOSE_WAIT, and
no new message for four days. Nothing inside Mail recovers from that; only a
relaunch does.

A standalone script on its own launchd interval, deliberately outside the
signed apple-mail-mcp executable: it needs no Full Disk Access, so it runs
under a stock Python and ships without a rebuild or a new TCC grant.

Mail's own store is TCC-protected, so activity is read from the MCP's FTS
index instead (<state root>/fts/fts.db, meta.last_rowid), which the FTS job
advances whenever Mail stores a message. Once that has stood still for
STALE_AFTER, the watchdog looks at Mail's mail-server sockets: a quiet inbox
keeps live connections, the wedge left every one in CLOSE_WAIT. As a
backstop for wedges with some other signature, BACKSTOP_AFTER of total
silence across every account also counts. FAILURES_BEFORE_RESTART bad passes
in a row trigger one relaunch (with a stack sample kept for diagnosis), and
RESTART_COOLDOWN bounds how often that can happen.

Apple Events are deliberately not consulted. Measured 2026-10-09: the wedged
Mail's main thread sat idle and would have answered a trivial event, while a
healthy, syncing Mail timed out on `count accounts` for minutes on end.

Usage:
  mail_watchdog.py                     # one pass, JSON report on stdout
  mail_watchdog.py --install-launchd   # copy to a stable path, run every 60s
  mail_watchdog.py --uninstall-launchd
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STALE_AFTER = 30 * 60
BACKSTOP_AFTER = 12 * 60 * 60
FAILURES_BEFORE_RESTART = 3
RESTART_COOLDOWN = 60 * 60
LAUNCH_COOLDOWN = 5 * 60
KEEP_SAMPLES = 5

LAUNCHD_LABEL = "com.tonyxiao.apple-mail-watchdog"



def state_root() -> Path:
    raw = os.environ.get("EMAIL_MCP_STATE_DIR", "").strip()
    return Path(raw) if raw else Path.home() / ".email-mcp"


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def _within(since: float, window: float, now: float) -> bool:
    """True while `now` is inside `window` seconds after `since`; a zero
    `since` means the event never happened."""
    return bool(since) and now < since + window


class SystemMail:
    """The real Mail.app side effects; every call is bounded in time."""

    def __init__(self, fts_db: Path):
        self._fts_db = fts_db

    def running_pid(self) -> int | None:
        proc = subprocess.run(["pgrep", "-x", "Mail"], capture_output=True,
                              text=True, timeout=10)
        pids = [int(p) for p in proc.stdout.split() if p.isdigit()]
        return pids[0] if pids else None

    def newest_rowid(self) -> int | None:
        if not self._fts_db.exists():
            return None
        uri = f"{self._fts_db.as_uri()}?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'last_rowid'").fetchone()
        finally:
            conn.close()
        return int(row[0]) if row and str(row[0]).isdigit() else None

    def connections_stalled(self, pid: int) -> bool:
        """True when Mail holds IMAP sockets and the server has closed every
        one of them (CLOSE_WAIT) without Mail noticing. HTTPS (iCloud,
        CloudKit) is ignored: it stays up independently of the IMAP engine."""
        proc = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP"],
                              capture_output=True, text=True, timeout=15)
        states = [line.rsplit("(", 1)[-1].rstrip(")")
                  for line in proc.stdout.splitlines()[1:]
                  if any(f":{port} " in line + " " for port in (993, 143))]
        return bool(states) and all(s == "CLOSE_WAIT" for s in states)

    def sample(self, pid: int, path: Path) -> None:
        subprocess.run(["sample", str(pid), "3", "-mayDie", "-file", str(path)],
                       capture_output=True, timeout=60)
        if path.exists():
            path.chmod(0o600)  # stacks name mailboxes and accounts

    def terminate(self, pid: int) -> None:
        for sig, wait in ((15, 15.0), (9, 5.0)):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                return
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return
                time.sleep(0.5)

    def launch(self) -> None:
        subprocess.run(["open", "-a", "Mail"], capture_output=True, timeout=30)


class MailWatchdog:
    def __init__(self, mail, state_dir: Path, *, clock=time.time):
        self._mail = mail
        self._dir = state_dir
        self._clock = clock

    def run(self) -> dict:
        now = self._clock()
        state = self._load()
        report = self._decide(now, state)
        report["consecutive_failures"] = state["consecutive_failures"]
        self._save(state)
        return report

    def _decide(self, now: float, state: dict) -> dict:
        pid = self._mail.running_pid()
        if pid is None:
            if _within(state["last_launch_at"], LAUNCH_COOLDOWN, now):
                return {"status": "not_running"}
            self._mail.launch()
            state["last_launch_at"] = now
            state["consecutive_failures"] = 0
            return {"status": "launched"}

        rowid = self._mail.newest_rowid()
        if rowid is None:
            return {"status": "index_unavailable"}
        if rowid != state["last_rowid"]:
            state.update(last_rowid=rowid, rowid_changed_at=now)
        idle = max(0.0, now - state["rowid_changed_at"])
        if idle < STALE_AFTER:
            state["consecutive_failures"] = 0
            return {"status": "healthy", "idle_seconds": int(idle)}

        if self._mail.connections_stalled(pid):
            evidence = "connections_stalled"
        elif idle >= BACKSTOP_AFTER:
            evidence = "long_silence"
        else:
            state["consecutive_failures"] = 0
            return {"status": "quiet", "idle_seconds": int(idle)}

        state["consecutive_failures"] += 1
        report = {"status": "unresponsive", "idle_seconds": int(idle),
                  "evidence": evidence}
        if state["consecutive_failures"] < FAILURES_BEFORE_RESTART:
            return report
        if _within(state["last_restart_at"], RESTART_COOLDOWN, now):
            report["cooldown_until"] = _iso(state["last_restart_at"] + RESTART_COOLDOWN)
            return report

        stamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%d-%H%M%S")
        sample = self._dir / f"sample-{stamp}.txt"
        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._mail.sample(pid, sample)
        self._mail.terminate(pid)
        self._mail.launch()
        self._prune_samples()
        # A fresh Mail gets a fresh silence window, or the backstop would
        # relaunch it again the moment the cooldown lapsed.
        state.update(last_restart_at=now, last_launch_at=now,
                     rowid_changed_at=now, consecutive_failures=0)
        return {"status": "restarted", "idle_seconds": int(idle),
                "killed_pid": pid, "sample": str(sample)}

    def _prune_samples(self) -> None:
        for old in sorted(self._dir.glob("sample-*.txt"))[:-KEEP_SAMPLES]:
            old.unlink(missing_ok=True)

    def _load(self) -> dict:
        now = self._clock()
        # A first run counts as fresh activity: never act on missing history.
        state = {"consecutive_failures": 0, "last_restart_at": 0.0,
                 "last_launch_at": 0.0, "last_rowid": -1,
                 "rowid_changed_at": now}
        try:
            saved = json.loads((self._dir / "state.json").read_text())
        except (OSError, ValueError):
            return state
        if isinstance(saved, dict):
            for key, default in state.items():
                value = saved.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    state[key] = type(default)(value)
        return state

    def _save(self, state: dict) -> None:
        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self._dir / "state.json.tmp"
        tmp.write_text(json.dumps(state))
        tmp.chmod(0o600)
        os.replace(tmp, self._dir / "state.json")


# ---------------------------------------------------------------------- #
# launchd                                                                 #
# ---------------------------------------------------------------------- #

def _installed_script() -> Path:
    return Path.home() / ".local" / "share" / "apple-mail-mcp" / "mail_watchdog.py"


def _plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def plist_content(script: Path, log: Path) -> str:
    env = ""
    if os.environ.get("EMAIL_MCP_STATE_DIR"):
        env = ("  <key>EnvironmentVariables</key><dict>"
               "<key>EMAIL_MCP_STATE_DIR</key>"
               f"<string>{state_root()}</string></dict>\n")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/python3</string><string>{script}</string>
  </array>
{env}  <key>StartInterval</key><integer>60</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"""


def install_launchd() -> str:
    script = _installed_script()
    script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(__file__, script)
    log = Path.home() / "Library" / "Logs" / "apple-mail-watchdog.log"
    plist = _plist_path()
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_text(plist_content(script, log))
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", domain, str(plist)], capture_output=True)
    proc = subprocess.run(["launchctl", "bootstrap", domain, str(plist)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return f"bootstrap failed: {proc.stderr.strip()}"
    return f"installed {LAUNCHD_LABEL} (every 60s) running {script}, log: {log}"


def uninstall_launchd() -> str:
    plist = _plist_path()
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(plist)],
                   capture_output=True)
    plist.unlink(missing_ok=True)
    return f"removed {LAUNCHD_LABEL}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Relaunch a wedged Mail.app.")
    parser.add_argument("--install-launchd", action="store_true")
    parser.add_argument("--uninstall-launchd", action="store_true")
    args = parser.parse_args(argv)
    if args.install_launchd:
        print(install_launchd())
        return 0
    if args.uninstall_launchd:
        print(uninstall_launchd())
        return 0
    root = state_root()
    watchdog = MailWatchdog(SystemMail(root / "fts" / "fts.db"),
                            root / "mail-watchdog")
    try:
        report = watchdog.run()
    except Exception as error:  # report, exit cleanly, try again next interval
        report = {"status": "error", "error": f"{type(error).__name__}: {error}"}
    report["at"] = _iso(time.time())
    print(json.dumps(report), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

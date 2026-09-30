"""Bounded SQLite reads against two fixed, locally configured mail stores."""
from __future__ import annotations

import base64
import dataclasses
import functools
import json
import math
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from ..domain.errors import InvalidInput, MailUnavailable
from ..domain.sql import (
    MailSchema,
    SqlColumn,
    SqlForeignKey,
    SqlIndex,
    SqlQueryResult,
    SqlTable,
    SqlValue,
)

MAX_ROWS = 5000
MAX_BYTES = 1_048_576
MAX_TIMEOUT = 10.0
_READ_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
                 sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
_FILE_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"}


def _authorize(action, arg1, arg2, database, source):
    # FTS5 queries check data_version internally. This one read-only PRAGMA
    # needs no bypass for writes or schema changes.
    if action == sqlite3.SQLITE_PRAGMA and arg1 == "data_version" and arg2 is None:
        return sqlite3.SQLITE_OK
    if action not in _READ_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or arg1 or "").lower() in _FILE_FUNCTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _deadline_check(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise InvalidInput("SQL execution deadline exceeded; narrow the query")


def _limits(conn: sqlite3.Connection, deadline: float) -> None:
    _deadline_check(deadline)
    conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
    conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536)
    conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 512)
    conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)


def _sql_errors(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except sqlite3.Error as exc:
            if getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_INTERRUPT:
                raise InvalidInput("SQL execution deadline exceeded; narrow the query") from exc
            raise InvalidInput(f"SQL operation rejected: {exc}") from exc
    return wrapped


class ReadOnlyMailSql:
    def __init__(self, mail_path: Path, fts_path: Path):
        self.paths = {"mail": mail_path, "fts": fts_path}

    def _connect(self, database: str, timeout: float = 5.0) -> sqlite3.Connection:
        if database not in self.paths:
            raise InvalidInput("database must be 'mail' or 'fts'; paths are not accepted")
        path = self.paths[database]
        if not path.is_file():
            raise MailUnavailable(
                f"The {database} database is unavailable",
                fix="Download mail in Mail.app, or build the body index with the fts command.",
            )
        conn = None
        try:
            conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True,
                                   timeout=min(timeout, 1.0))
            conn.enable_load_extension(False)
            conn.execute("PRAGMA query_only=ON")
            return conn
        except Exception as exc:
            if conn is not None:
                conn.close()
            raise MailUnavailable(f"Cannot open the {database} database: {exc}") from exc

    @_sql_errors
    def query(self, sql: str, database: str = "mail",
              params: dict[str, SqlValue] | None = None,
              max_rows: int = 500, timeout_seconds: float = 5.0) -> SqlQueryResult:
        if not isinstance(sql, str) or not sql.strip() or len(sql.encode()) > 65536:
            raise InvalidInput("sql must be a non-empty statement of at most 65536 bytes")
        if type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS:
            raise InvalidInput(f"max_rows must be between 1 and {MAX_ROWS}")
        if (not isinstance(timeout_seconds, (int, float))
                or isinstance(timeout_seconds, bool)
                or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= MAX_TIMEOUT):
            raise InvalidInput("timeout_seconds must be greater than zero and at most 10")
        if params is not None and (not isinstance(params, dict) or any(
            not isinstance(k, str) or not isinstance(v, (str, int, float, bool, type(None)))
            or (isinstance(v, float) and not math.isfinite(v)) for k, v in params.items()
        )):
            raise InvalidInput("params must map named parameters to scalar JSON values")
        started = time.monotonic()
        deadline = started + timeout_seconds
        rows = []
        reason = None
        size = 0
        with closing(self._connect(database, timeout_seconds)) as conn:
            _limits(conn, deadline)
            # FTS5's xConnect performs internal schema/pragma actions. Initialize
            # only existing FTS tables on the already read-only connection before
            # installing the authorizer on all caller-controlled SQL.
            for name, ddl in conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'"):
                _deadline_check(deadline)
                if ddl and "using fts5" in ddl.lower():
                    conn.execute(f"SELECT rowid FROM {_quote(name)} LIMIT 0")
            conn.set_authorizer(_authorize)
            try:
                _deadline_check(deadline)
                cursor = conn.execute(sql, params or {})
                _deadline_check(deadline)
                if cursor.description is None:
                    raise InvalidInput("Only a single read-only query is accepted")
                columns = [item[0] for item in cursor.description]
                metadata = SqlQueryResult(database, columns, [], 0.0, True, "max_bytes", max_rows)
                size = len(json.dumps({"ok": True, **dataclasses.asdict(metadata)},
                                      ensure_ascii=False).encode()) + 100
                while row := cursor.fetchone():
                    _deadline_check(deadline)
                    if len(rows) == max_rows:
                        reason = "max_rows"
                        break
                    encoded = [
                        {"encoding": "base64", "data": base64.b64encode(v).decode(), "bytes": len(v)}
                        if isinstance(v, bytes) else v for v in row
                    ]
                    row_size = len(json.dumps(encoded, ensure_ascii=False).encode()) + 2
                    if size + row_size > MAX_BYTES:
                        reason = "max_bytes"
                        break
                    size += row_size
                    rows.append(encoded)
                _deadline_check(deadline)
            except sqlite3.Error as exc:
                if time.monotonic() >= deadline:
                    raise InvalidInput("SQL execution deadline exceeded; narrow the query") from exc
                raise InvalidInput(f"SQL query rejected: {exc}") from exc
        return SqlQueryResult(database, columns, rows,
                              round((time.monotonic() - started) * 1000, 3),
                              reason is not None, reason, max_rows)

    @_sql_errors
    def schema(self, database: str = "mail", tables: list[str] | None = None) -> MailSchema:
        if tables is not None and (not isinstance(tables, list)
                                  or not all(isinstance(t, str) for t in tables)):
            raise InvalidInput("tables must be a list of table or view names")
        if tables is not None and (len(tables) > 128 or any(len(t.encode()) > 512 for t in tables)):
            raise InvalidInput("Request at most 128 table names, each at most 512 bytes")
        result = []
        deadline = time.monotonic() + 5.0
        with closing(self._connect(database)) as conn:
            _limits(conn, deadline)
            query = ("SELECT name,type,sql FROM sqlite_master WHERE type IN ('table','view') "
                     "AND name NOT LIKE 'sqlite_%'")
            bindings = ()
            if tables is not None:
                if not tables:
                    query += " AND 0"
                else:
                    query += " AND name IN (" + ",".join("?" for _ in tables) + ")"
                    bindings = tuple(tables)
            entries = []
            catalog_bytes = 0
            for entry in conn.execute(query + " ORDER BY name", bindings):
                _deadline_check(deadline)
                catalog_bytes += len(json.dumps(entry).encode())
                if len(entries) == 512 or catalog_bytes > MAX_BYTES:
                    raise InvalidInput("Schema is too large; request specific tables")
                entries.append(entry)
            known = {r[0] for r in entries}
            unknown = set(tables or []) - known
            if unknown:
                raise InvalidInput("Unknown table: " + ", ".join(sorted(unknown)))
            for name, kind, ddl in entries:
                _deadline_check(deadline)
                if tables is not None and name not in tables:
                    continue
                columns = [SqlColumn(r[1], r[2], bool(r[3]), r[4], r[5], r[6])
                           for r in conn.execute(f"PRAGMA table_xinfo({_quote(name)})")]
                indexes = []
                for idx in conn.execute(f"PRAGMA index_list({_quote(name)})"):
                    _deadline_check(deadline)
                    if len(indexes) == 512:
                        raise InvalidInput("Too many indexes; request a narrower schema")
                    idx_ddl = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (idx[1],)).fetchone()
                    indexes.append(SqlIndex(
                        idx[1], bool(idx[2]),
                        [r[2] for r in conn.execute(f"PRAGMA index_info({_quote(idx[1])})")],
                        idx_ddl[0] if idx_ddl else None,
                    ))
                fks = [SqlForeignKey(r[2], r[3], r[4], r[5], r[6])
                       for r in conn.execute(f"PRAGMA foreign_key_list({_quote(name)})")]
                result.append(SqlTable(name, kind, ddl, columns, indexes, fks))
                if len(json.dumps([dataclasses.asdict(t) for t in result]).encode()) > MAX_BYTES:
                    raise InvalidInput("Schema exceeds response budget; request specific tables")
            _deadline_check(deadline)
        notes = ["Read-only local snapshot; Apple Mail may still be synchronizing.",
                 "Foreign keys are declared constraints; inspect DDL and notes for other relationships."]
        examples = ["SELECT name, type FROM sqlite_master ORDER BY name"]
        if database == "mail":
            notes += ["Apple's private schema varies by macOS version.",
                      "When present: messages.sender = addresses.ROWID; recipients.message = messages.ROWID; recipients.type 0 is To, 1 is Cc.",
                      "Gmail label membership uses labels.message_id = messages.ROWID and labels.mailbox_id = mailboxes.ROWID; messages.mailbox alone misses labels."]
            if {"messages", "addresses"} <= known:
                examples.append("SELECT a.address, count(*) AS messages FROM messages m JOIN addresses a ON a.ROWID=m.sender GROUP BY a.address ORDER BY messages DESC LIMIT 20")
        else:
            notes += ["FTS docs.rowid corresponds to the Envelope Index messages.ROWID; this is a derived index, not the complete mailbox.",
                      "Inspect docs.status and meta for coverage and freshness before interpreting no matches."]
            if "body_fts" in known:
                examples.append("SELECT rowid FROM body_fts WHERE body_fts MATCH :query LIMIT 50")
        schema = MailSchema(database, result, notes, examples)
        if len(json.dumps(dataclasses.asdict(schema)).encode()) > MAX_BYTES:
            raise InvalidInput("Schema exceeds response budget; request specific tables")
        return schema

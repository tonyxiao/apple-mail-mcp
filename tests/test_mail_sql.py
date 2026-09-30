"""Real SQLite contracts for read-only queries and schema discovery."""
from __future__ import annotations

import json
import sqlite3

import pytest

from email_mcp import bootstrap, state
from email_mcp.domain.errors import InvalidInput, MailUnavailable


@pytest.fixture
def databases(tmp_path, monkeypatch):
    mail = tmp_path / "Mail"
    (mail / "MailData").mkdir(parents=True)
    envelope = mail / "MailData" / "Envelope Index"
    with sqlite3.connect(envelope) as conn:
        conn.executescript("""
            CREATE TABLE addresses (id INTEGER PRIMARY KEY, address TEXT NOT NULL);
            CREATE TABLE messages (id INTEGER PRIMARY KEY, sender INTEGER,
                subject TEXT, raw BLOB, FOREIGN KEY(sender) REFERENCES addresses(id));
            CREATE INDEX messages_sender ON messages(sender);
            INSERT INTO addresses VALUES (1, 'alice@example.com'), (2, 'bob@test.org');
            INSERT INTO messages VALUES (1, 1, 'invoice', X'00FF'),
                (2, 1, 'receipt', NULL), (3, 2, 'hello', NULL);
        """)
    monkeypatch.setenv("EMAIL_MCP_MAIL_DIR", str(mail))
    monkeypatch.setenv("EMAIL_MCP_STATE_DIR", str(tmp_path / "state"))
    state.State.resolve().adopt()
    fts = tmp_path / "state" / "fts" / "fts.db"
    fts.parent.mkdir()
    with sqlite3.connect(fts) as conn:
        conn.execute("CREATE VIRTUAL TABLE body_fts USING fts5(body)")
        conn.executemany("INSERT INTO body_fts VALUES (?)", [("invoice due",), ("hello",)])
    return envelope, fts


def test_join_aggregate_and_named_parameters(databases):
    result = bootstrap.get_sql_reader().query(
        "WITH selected AS (SELECT * FROM messages WHERE id > :after) "
        "SELECT a.address, count(*) AS n FROM selected m "
        "JOIN addresses a ON a.id=m.sender GROUP BY a.address ORDER BY n DESC",
        params={"after": 0},
    )
    assert result.columns == ["address", "n"]
    assert result.rows == [["alice@example.com", 2], ["bob@test.org", 1]]
    assert not result.truncated


def test_fts_match_reads_the_body_index(databases):
    result = bootstrap.get_sql_reader().query(
        "SELECT rowid, body FROM body_fts WHERE body_fts MATCH :query",
        database="fts", params={"query": "invoice"},
    )
    assert result.rows == [[1, "invoice due"]]


@pytest.mark.parametrize("sql", [
    "DELETE FROM messages",
    "UPDATE messages SET subject='changed'",
    "INSERT INTO messages(id) VALUES(4)",
    "DROP TABLE messages",
    "CREATE TABLE extra(x)",
    "PRAGMA query_only=OFF",
    "PRAGMA writable_schema=ON",
    "ATTACH DATABASE ':memory:' AS other",
    "DETACH DATABASE main",
    "VACUUM INTO 'copied.db'",
    "BEGIN IMMEDIATE",
    "SELECT load_extension('anything')",
    "SELECT writefile('anything','data')",
    "SELECT readfile('anything')",
    "SELECT 1; DELETE FROM messages",
])
def test_mutations_and_file_access_are_rejected(databases, sql):
    with pytest.raises(InvalidInput):
        bootstrap.get_sql_reader().query(sql)
    with sqlite3.connect(databases[0]) as conn:
        assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 3
        assert conn.execute("SELECT subject FROM messages WHERE id=1").fetchone()[0] == "invoice"


def test_result_limit_reports_truncation(databases):
    result = bootstrap.get_sql_reader().query("SELECT id FROM messages ORDER BY id", max_rows=2)
    assert result.rows == [[1], [2]]
    assert result.truncated
    assert result.truncation_reason == "max_rows"


def test_empty_result_retains_column_names(databases):
    result = bootstrap.get_sql_reader().query("SELECT id, subject FROM messages WHERE id=99")
    assert result.columns == ["id", "subject"]
    assert result.rows == []
    assert not result.truncated


def test_binary_cells_are_explicitly_encoded(databases):
    result = bootstrap.get_sql_reader().query("SELECT raw FROM messages WHERE id=1")
    assert result.rows == [[{"encoding": "base64", "data": "AP8=", "bytes": 2}]]


def test_expensive_recursive_query_is_interrupted(databases):
    with pytest.raises(InvalidInput, match="deadline"):
        bootstrap.get_sql_reader().query(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) "
            "SELECT sum(x) FROM n", timeout_seconds=0.01,
        )


def test_large_cell_is_rejected_before_returning_it(databases):
    with pytest.raises(InvalidInput):
        bootstrap.get_sql_reader().query("SELECT zeroblob(10000000)")


def test_total_result_including_metadata_fits_byte_budget(databases):
    from dataclasses import asdict

    result = bootstrap.get_sql_reader().query(
        "WITH n(x) AS (VALUES(1),(2),(3),(4)) "
        "SELECT printf('%.*c',262130,'x') AS content FROM n"
    )
    assert result.truncated
    assert result.truncation_reason == "max_bytes"
    assert len(json.dumps({"ok": True, **asdict(result)}, ensure_ascii=False).encode()) <= 1048576


def test_final_envelope_and_mcp_text_fit_byte_budget(databases):
    from email_mcp.mcp_api import tool_query_mail_sql

    result = tool_query_mail_sql(
        "WITH n(x) AS (VALUES(1),(2),(3),(4)) "
        "SELECT printf('%.*c',262050,'x') AS content FROM n"
    )
    assert result["ok"]
    assert len(json.dumps(result, indent=2, ensure_ascii=False).encode()) <= 1048576


def test_opt_in_budget_counts_metadata_added_to_the_envelope():
    from email_mcp import envelope

    @envelope.tool(budget_bytes=1048576)
    def query_result():
        return {"columns": ["content"], "rows": [["x" * 262050]] * 4,
                "truncated": False, "truncation_reason": None,
                "diagnostic_metadata": {"detail": "x" * 4096}}

    result = query_result()
    assert result["truncated"]
    assert result["truncation_reason"] == "max_bytes"
    assert len(result["rows"]) == 3
    assert len(json.dumps(result, indent=2, ensure_ascii=False).encode()) <= 1048576


def test_deadline_covers_initialization_even_for_trivial_query(databases):
    with pytest.raises(InvalidInput, match="deadline"):
        bootstrap.get_sql_reader().query("SELECT 1", timeout_seconds=0.000001)


def test_schema_inspection_has_a_deadline(databases, monkeypatch):
    from email_mcp.adapters import sql

    ticks = iter([0.0, 10.0])
    monkeypatch.setattr(sql.time, "monotonic", lambda: next(ticks, 10.0))
    with pytest.raises(InvalidInput, match="deadline"):
        bootstrap.get_sql_reader().schema()


@pytest.mark.parametrize("kwargs", [
    {"database": "/tmp/arbitrary.db"}, {"max_rows": 0}, {"max_rows": 100000},
    {"timeout_seconds": 0}, {"timeout_seconds": 1000},
    {"params": {"x": {"nested": "object"}}},
])
def test_invalid_options_are_rejected(databases, kwargs):
    with pytest.raises(InvalidInput):
        bootstrap.get_sql_reader().query("SELECT 1", **kwargs)


def test_schema_reports_columns_indexes_and_declared_relationships(databases):
    schema = bootstrap.get_sql_reader().schema(tables=["messages"])
    assert schema.database == "mail"
    assert len(schema.tables) == 1
    table = schema.tables[0]
    assert table.name == "messages"
    assert [c.name for c in table.columns] == ["id", "sender", "subject", "raw"]
    assert table.columns[0].primary_key == 1
    assert table.indexes[0].name == "messages_sender"
    assert table.indexes[0].columns == ["sender"]
    assert table.foreign_keys[0].table == "addresses"
    assert table.foreign_keys[0].from_column == "sender"
    assert table.foreign_keys[0].to_column == "id"
    assert "CREATE TABLE messages" in table.sql


def test_fts_schema_includes_the_virtual_table_ddl(databases):
    schema = bootstrap.get_sql_reader().schema(database="fts", tables=["body_fts"])
    assert "USING fts5" in schema.tables[0].sql


def test_unknown_table_is_a_clear_error(databases):
    with pytest.raises(InvalidInput, match="Unknown table"):
        bootstrap.get_sql_reader().schema(tables=["absent"])


def test_missing_index_is_not_created(databases):
    databases[1].unlink()
    with pytest.raises(MailUnavailable):
        bootstrap.get_sql_reader().query("SELECT 1", database="fts")
    assert not databases[1].exists()


def test_tools_return_the_standard_envelope(databases):
    from email_mcp import mcp_api
    result = mcp_api.tool_query_mail_sql("SELECT count(*) AS n FROM messages")
    assert result["ok"] is True
    assert result["rows"] == [[3]]
    schema = mcp_api.tool_get_mail_schema(tables=["addresses"])
    assert schema["ok"] is True
    assert schema["tables"][0]["columns"][1]["name"] == "address"
    denied = mcp_api.tool_query_mail_sql("DELETE FROM messages")
    assert denied["ok"] is False
    assert denied["code"] == "invalid_input"


def test_cli_uses_the_same_query_and_schema_functions(databases, capsys):
    from email_mcp import cli
    assert cli.main(["sql", "query", "SELECT :number AS n", "--params", '{"number":7}']) == 0
    assert json.loads(capsys.readouterr().out)["rows"] == [[7]]
    assert cli.main(["sql", "schema", "--table", "messages"]) == 0
    assert json.loads(capsys.readouterr().out)["tables"][0]["name"] == "messages"

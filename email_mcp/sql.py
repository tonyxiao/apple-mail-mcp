"""CLI adapter for the same read-only SQL tools exposed over MCP."""
from __future__ import annotations

import argparse
import json

from .mcp_api import tool_get_mail_schema, tool_query_mail_sql


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apple-mailbox-mcp sql")
    commands = parser.add_subparsers(dest="command", required=True)
    query = commands.add_parser("query", help="Run a bounded read-only query")
    query.add_argument("sql")
    query.add_argument("--database", choices=["mail", "fts"], default="mail")
    query.add_argument("--params", default="{}", help="Named scalar parameters as JSON")
    query.add_argument("--max-rows", type=int, default=500)
    query.add_argument("--timeout-seconds", type=float, default=5.0)
    schema = commands.add_parser("schema", help="Inspect tables, columns, indexes and relationships")
    schema.add_argument("--database", choices=["mail", "fts"], default="mail")
    schema.add_argument("--table", action="append", dest="tables")
    args = parser.parse_args(argv)
    if args.command == "query":
        try:
            params = json.loads(args.params)
        except ValueError:
            parser.error("--params must be valid JSON")
        result = tool_query_mail_sql(args.sql, args.database, params,
                                     args.max_rows, args.timeout_seconds)
    else:
        result = tool_get_mail_schema(args.database, args.tables)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1

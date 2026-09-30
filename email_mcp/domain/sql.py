"""Protocol-independent results for local, read-only SQL access."""
from __future__ import annotations

from dataclasses import dataclass

SqlValue = str | int | float | bool | None
SqlCell = str | int | float | None | dict[str, str | int]


@dataclass(frozen=True)
class SqlQueryResult:
    database: str
    columns: list[str]
    rows: list[list[SqlCell]]
    elapsed_ms: float
    truncated: bool
    truncation_reason: str | None
    max_rows: int


@dataclass(frozen=True)
class SqlColumn:
    name: str
    type: str
    not_null: bool
    default: str | None
    primary_key: int
    hidden: int


@dataclass(frozen=True)
class SqlIndex:
    name: str
    unique: bool
    columns: list[str | None]
    sql: str | None


@dataclass(frozen=True)
class SqlForeignKey:
    table: str
    from_column: str
    to_column: str | None
    on_update: str
    on_delete: str


@dataclass(frozen=True)
class SqlTable:
    name: str
    type: str
    sql: str | None
    columns: list[SqlColumn]
    indexes: list[SqlIndex]
    foreign_keys: list[SqlForeignKey]


@dataclass(frozen=True)
class MailSchema:
    database: str
    tables: list[SqlTable]
    notes: list[str]
    examples: list[str]

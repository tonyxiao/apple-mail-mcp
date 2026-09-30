# Read-only SQL and schema discovery

This fork adds two tools to the upstream Apple Mail MCP server. Both are
available in `EMAIL_MCP_READ_ONLY=1` sessions and use the same functions as the CLI.
They operate entirely on local databases and do not ask Mail.app to scan messages.

| Tool | Purpose |
|---|---|
| `get_mail_schema(database="mail", tables=null)` | Inspect tables/views, columns, declared types, primary keys, indexes, declared foreign keys, DDL, relationship notes and example queries. |
| `query_mail_sql(sql, database="mail", params=null, max_rows=500, timeout_seconds=5)` | Execute one bounded read-only query with named scalar parameters. |

`database="mail"` selects Apple's live `MailData/Envelope Index` under the active
Mail directory. `database="fts"` selects the existing derived body index under the
configured state root. These are aliases; clients cannot supply a filesystem path
or attach another database. `EMAIL_MCP_MAIL_DIR` and `EMAIL_MCP_STATE_DIR` retain
their upstream meaning. A missing database is reported, never created.

## Client workflow

1. Call `get_mail_schema` on the desired database. Pass `tables` to narrow a large
   schema response. Schema discovery contains no sampled email contents.
2. Use the returned column names, DDL and relationship notes to construct a query.
3. Pass values through `params` using `:name` placeholders.
4. Check `truncated` and `truncation_reason` before interpreting results as complete.

Results contain `columns`, row arrays, `database`, `elapsed_ms`, `max_rows`, and
explicit truncation metadata inside the usual `ok` envelope. Binary cells are
objects with `encoding="base64"`, `data`, and byte count. No column value is silently
shortened. Rows exceeding SQLite's size bound fail; an output-budget limit reports
truncation. Use a narrower projection or `substr` to inspect a large field.

The maximum row count is 5,000, the maximum deadline is ten seconds, and the JSON
result budget is 1 MiB. A progress handler interrupts expensive SQL; lock waits
are capped at one second. SQL text is limited to 65,536 bytes. Connections use
`mode=ro`, `query_only`, and a SQLite authorizer. Writes, DDL, transaction commands,
database attachment, extension loading and file-access functions are blocked.
The harmless read-only `data_version` PRAGMA is allowed because FTS5 uses it.

## CLI examples

```sh
apple-mailbox-mcp sql schema --table messages --table addresses --table labels

apple-mailbox-mcp sql query \
  'SELECT a.address, count(*) AS messages FROM messages m JOIN addresses a ON a.ROWID=m.sender GROUP BY a.address ORDER BY messages DESC LIMIT :limit' \
  --params '{"limit":20}'

apple-mailbox-mcp sql schema --database fts --table docs --table body_fts

apple-mailbox-mcp sql query \
  'SELECT rowid FROM body_fts WHERE body_fts MATCH :query LIMIT :limit' \
  --database fts --params '{"query":"invoice","limit":50}'
```

Commands print JSON; an `ok:false` result exits with code 1.

## Labels and recipient domains

Apple's schema can change across macOS releases. Query the live schema first.
On the tested store, Gmail label membership uses `labels`, rather than only the
primary `messages.mailbox`. A dated-label sender-domain report is:

```sql
SELECT lower(substr(a.address, instr(a.address, '@') + 1)) AS domain,
       count(DISTINCT m.ROWID) AS messages
FROM messages m
JOIN labels l ON l.message_id = m.ROWID
JOIN mailboxes b ON b.ROWID = l.mailbox_id
JOIN addresses a ON a.ROWID = m.sender
WHERE b.url LIKE :mailbox_pattern
  AND m.deleted = 0
  AND instr(a.address, '@') > 0
GROUP BY domain
ORDER BY messages DESC, domain;
```

Use `{"mailbox_pattern":"%/inbox-YYYY-MM-DD"}` as parameters. To group by **To**
recipient instead, join `recipients r ON r.message=m.ROWID AND r.type=0` and use
`r.address` for the address join. A message with multiple To domains appears in
multiple groups.

The live metadata database and body index have different coverage. Mail may still
be downloading, and FTS retries can lag newly available bodies. Use `docs.status`,
the index `meta` table and the existing diagnostics to assess completeness.
These tools do not install a background updater or change MCP Hub configuration.

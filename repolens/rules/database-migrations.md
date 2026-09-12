# Database migrations: check the change before it runs

**Rule.** A migration is the one step in a deploy that runs against data you cannot
regenerate. Before it merges, it must fit the version table, add no NOT NULL column
without a default, and leave every row-secured table FORCEd and every view over one
`security_invoker`.

## Why

Each of these fails in a way that looks like something else:

| shape | what actually happens |
|---|---|
| a revision id wider than the version column (Alembic: `VARCHAR(32)`) | the DDL applies, then recording the revision fails and PostgreSQL rolls the whole migration back. The error names a string truncation, far from the file name that caused it |
| `add_column(Column(..., nullable=False))` with no `server_default` | passes against an empty test database and fails against every environment that has rows |
| `ENABLE ROW LEVEL SECURITY` without `FORCE` | the table's owner is exempt from its own policies. Harmless until the application connects as the owner, and then every tenant's rows are visible, with no error |
| a view without `security_invoker` | the policies of the tables under it are evaluated as the VIEW OWNER. It keeps returning rows, just the wrong ones, the moment owner and caller differ |
| `CREATE INDEX` on an existing table without `CONCURRENTLY` | writes to the table wait for the whole build. Invisible on a small table; the lock grows with the rows |

None of these is caught by a test suite that migrates an empty database, which is the
only kind most CI has.

## How it is checked

```bash
repolens report --only migrations      # all six rules, as findings
repolens report --check                # fails on a NEW one at medium confidence or above
```

The migrations are read with the AST, not a regex over the file: SQL is usually built in
f-strings inside a loop over tables, and only the functions other than `downgrade()` are
read. Configure the location, the version column width and the opt-in rule under
`[scan.migrations]`:

```toml
[scan.migrations]
roots = ["backend/alembic/versions"]   # default: every alembic/versions and migrations/versions
revision_max_length = 32
require_rls = false                     # true: a table created in rls_schemas must be secured
rls_schemas = []
```

## What it cannot see

A table name computed at run time is matched by its template, so "is THIS table
FORCEd?" falls back to the migration: an f-string ENABLE counts as paired with an
f-string FORCE in the same file. Whether a table is empty, the one case where a NOT NULL
column without a default is harmless, needs the database. So does whether the role the
application connects as owns the tables, which decides whether a missing FORCE matters
today or only later.

<!--
Historical document, restored verbatim except that identifiers of the repository the
toolkit was extracted from are generalised. Do not otherwise edit the body below this comment.

Source: docs/roadmap.md as it stood from the initial 0.2.0 commit f73033c through d255c02
(unchanged in between), and the text downstream tickets cite from the vendored copy's
`docs/roadmap.md`. It was replaced by the 0.3.0 rewrite
in eb015d3 ("docs: publish audited scope roadmap and API client contracts").
Relative links inside it point at the 0.2 layout and may no longer resolve.
-->

# repolens roadmap

Status at 0.2.0 plus the fixes below (2026-09-11). This page lists four things:
1. The defects the audit found, and how each was fixed.
2. What is still open, with the task that tracks it.
3. Moving repolens into its own repository. The procedure is in
   [installation.md](installation.md#making-it-a-separate-repository).
4. What a robust product needs next: Python, PostgreSQL, JavaScript/TypeScript, and C#.

## 1. Fixed

### In 0.2.0

| area | defect | effect before the fix |
|---|---|---|
| report baseline | a set of fingerprints, not a count | a second identical finding in the same file read as known |
| report commands | a crashed check was recorded as a finding | `--update-baseline` accepted a broken gate; `--check` passed from then on |
| report CLI | `--check --update-baseline` was accepted | the check could only pass |
| report baseline | unreadable JSON read as "no baseline" or "empty" | a refusal for the wrong reason, or every finding new |
| ruff / bandit adapters | a null ruff code; bandit `UNDEFINED` severity | a crash, or a finding with no valid severity |
| SQL detector | `"..." + uid + "..."` missed; `LIMIT {int(x)}` flagged | a false negative on the classic injection shape; a false positive on a safe one |
| performance detector | a comprehension's first iterable counted per item; `find(limit=n)` unseen | false N+1 and unbounded-query findings |
| capability index (JS) | the comment stripper did not know strings | `"image/*"` opened a block comment and hid 45 lines of a live file from every detector |
| artefacts | a deleted marked file's tag was never refreshed | the map kept naming a file that no longer exists |
| hooks | the interpreter path was unquoted; CRLF on Windows | a path with a space split in two, and `\|\| true` swallowed the failure |
| gates | `[[report.commands]]` counted as executed | nothing ran the report, yet its commands passed as "reachable" |
| impact | the index cache was not keyed on config | a config change served a stale graph |
| paths | `rel()` returned backslashes on Windows | fingerprints and baselines differed by OS |
| shims | `sys.path.append` | an installed older repolens shadowed the checkout |
| merge-driver installer | took the first `python3` | a Python older than 3.11 has no `tomllib`, and the driver failed |
| `.gitignore` | all of `.repolens/` ignored | no baseline could be committed, so `--check` had nothing to compare |
| lens / owners | `RecursionError` on a deeply nested file | one file crashed the whole run |

### After 0.2.0: the eleven recorded defects

Each was listed here as "found and not fixed". All eleven are now fixed, and each has a
test in `tests/test_scan.py` or `tests/test_impact.py`.

| # | defect | the fix |
|---|---|---|
| 1 | `lens --lookup` could serve a stale index | the index records a stamp of the tree (file sizes and mtimes, the registry, the settings). A lookup whose stamp differs rebuilds first, and says so on stderr |
| 2 | non-ASCII paths were not matched | every git call reads NUL-separated output (`-z`) with `core.quotePath=false`: `core/git.py`, `artefacts verify` and `regenerate`, and the lens churn |
| 3 | router-level auth and prefixes were missed | `scan/mounts.py` follows `APIRouter(prefix=, dependencies=)` and `include_router(..., prefix=, dependencies=)` across modules, through imports and aliases. A route's path gains its prefixes. Its auth is the dependencies every mount has in common. `public_routes` matches either the full or the declared path |
| 4 | SQL assembled in a variable was not followed | a name passed to `execute` is traced through its writes up to the call, and the message names the variable and the line that built it |
| 5 | an allow-listed identifier was still flagged | `if x not in ALLOWED: raise/return` is a guard: against a module constant, a literal collection or `CONST.keys()`. The guard does not count once the variable is written again before the call |
| 6 | a ratchet count that fell read as a new finding | the fingerprint normalises numbers and the baseline records each one's size. A count finding is new only when its shape differs or its number rose |
| 7 | impact drew unresolved names as resolved nodes | a target reached only through an ambiguous name is drawn dashed and labelled "candidate". The review list says so. Unresolved names are grouped by name with the number of callers each covers |
| 8 | a file deleted mid-run crashed most commands | `read_text_or_none` in FeatureTrace, the lens and the report, and `OSError` handling in owners, gates and impact. The file is skipped and named |
| 9 | `owners` gave a traceback without PyYAML | it exits with `pip install 'repolens[yaml]'` |
| 10 | other Windows path joins | FeatureTrace's `rel_path` is POSIX, like `rel()`. Tested on Linux only: see GAP-TOOL-006 |
| 11 | the originating repository's domain layer imported web and database packages | fixed in that repository: its domain modules became pure, database access moved to a service module, a lifecycle error is mapped to 409 by the router, a test fails on any web, database or service import in the domain package, and the `[docs.python] exclude` is gone |

### After 0.2.0: PostgreSQL

The scanners understood FastAPI and MongoDB. PostgreSQL, the system of record in the
repository repolens came from, was visible only to the lens, and only as schema-qualified
names in one call shape.

| added | what it sees |
|---|---|
| the `migrations` report tool | Alembic migrations, read with the AST. Six rules: revision too long for the version column; NOT NULL column without a server default; RLS enabled with no FORCE; a view without `security_invoker`; CREATE INDEX without CONCURRENTLY on an existing table; and, opt-in, a table in an RLS schema that nothing secures. See [database-migrations](../repolens/rules/database-migrations.md) |
| `performance/unbounded-sql-fetch` | asyncpg `fetch()` of a SELECT with no LIMIT, and SQLAlchemy `.all()` / `.fetchall()` on a `select()` with no `.limit()`. An aggregate with no GROUP BY is one row and is not flagged. Low confidence |
| blocking calls | `psycopg2.connect`, `psycopg.connect`, `sqlalchemy.create_engine` and `pymongo.MongoClient` inside `async def` |
| lens `postgres_tables` | bare and qualified names; `execute`, `fetch*` and `exec_driver_sql`, not only `text()`; f-strings. CTEs and functions (`unnest(...)`) are skipped. A function that names an ORM class gains that class's `__tablename__` |
| impact | ORM classes give an exact `postgres_table` edge with no configuration. Without `pg_schemas`, SQL-shaped text gives probable edges |
| `repolens init` | detects `alembic/versions` and `migrations/versions` and writes `[scan.migrations]` |

## 2. Still open

Each has a task file under `tasks/` in the repository repolens came from.

| task | what |
|---|---|
| GAP-TOOL-006 | extraction and publishing: owner decisions, PyPI, the GitHub Action, the CI matrix, including the first Windows run |
| GAP-TOOL-007 | hardening before repolens runs in other people's CI |
| GAP-TOOL-008 | Python: framework adapters (Flask, Django), and def-use taint beyond SQL |
| GAP-TOOL-009 | PostgreSQL: what static reading cannot answer, and SQLAlchemy N+1 |
| GAP-TOOL-010 | JavaScript/TypeScript: a real parser, then the security and performance detectors |
| GAP-TOOL-011 | SARIF ingestion, then C# |

Two known limits, recorded so they are not rediscovered:
- **The lens's ORM join is by class name.** Two mapped classes sharing a name share their
  tables in every function that names either. The lens prints this under `limits`.
- **The migrations rules match a computed table by its template.** "Is THIS table FORCEd?"
  falls back to the migration. So an f-string ENABLE in one file, FORCEd by a loop in a
  later file, is reported at low confidence. In the repository repolens came from, the
  one such finding is `0046`, whose tables a later migration forces.

## 3. Extracting repolens into its own repository

The procedure is in
[installation.md, "Making it a separate repository"](installation.md#making-it-a-separate-repository):
what is already true, the decisions only the owner can make, publishing, the Action, the
CI matrix, plugin entry points, what stays behind, and a hardening checklist.

The short version: every repository fact is in `repolens.toml` and the package imports
nothing from the repository it came from. The coupling that matters is to frameworks:
the security and performance scans understand FastAPI, MongoDB (Motor) and PostgreSQL
(asyncpg, SQLAlchemy, Alembic). A Flask, Django, Express or Next.js codebase gets
FeatureTrace, the lens, owners, gates, artefacts, docs and the migrations checks today.
It gets **no** route-security findings.

## 4. A robust product: what to add

### Python

**Security.**
1. **Framework adapters**, one module per framework behind a plugin entry point:
   - FastAPI: router `dependencies` and `prefix` are done. `Security()` scopes are not.
   - Flask: `@login_required`, blueprints, `before_request`.
   - Django and DRF: `permission_classes`, `@permission_required`, `LoginRequiredMixin`.

   An adapter produces routes, their auth, and their object-id parameters. The existing
   BOLA and unauthenticated-mutation rules then apply unchanged.
2. **Def-use taint beyond SQL.** SQL now follows a variable to its writes. The same
   mechanism should cover:
   - `subprocess(shell=True)` and `os.system`;
   - `eval` and `exec`;
   - `pickle.loads` and `yaml.load`;
   - path joins from request input (traversal);
   - `requests` or `httpx` fetching a request-supplied URL (SSRF);
   - redirects to a request-supplied URL.
3. **Secrets**: gitleaks as an optional tool, adapted like bandit. A secret is high
   severity whatever its exposure.
4. **Dependencies**: make osv-scanner default when a lockfile exists. `pip-audit` stays
   optional.

**Performance.**
- SQLAlchemy N+1: a lazy relationship read inside a loop.
- More blocking calls in `async def`: `requests.*`, `subprocess.run`, synchronous
  `smtplib`. The last is the one that cost the original repository request latency.
- Import-time cost: `python -X importtime` as a ratcheted command.

### PostgreSQL

What static reading cannot answer needs the database. An opt-in `--dsn` mode, read-only,
would add:
- which RLS tables lack FORCE **now**, rather than what the migrations say;
- which role owns each table, which decides whether a missing FORCE matters today;
- whether a table is empty, the one case where a NOT NULL column with no default is safe;
- the live Alembic head against the files, which catches a migration applied from an
  untracked file.

### JavaScript / TypeScript

**First, a real parser.** docs coverage, the capability index and the lens frontend
records all read TS/JS with line regexes. Use **tree-sitter** (`tree-sitter` and
`tree-sitter-typescript` wheels): it is fast, needs no Node runtime, and gives
syntax-accurate exports, calls and JSX. Keep the TypeScript compiler API for the rare
check that needs types. It needs Node and a project install, which is too heavy for a
default path.

**Security.**
- XSS sinks:
  - `dangerouslySetInnerHTML` fed anything but a sanitiser's output;
  - `innerHTML =` and `document.write`;
  - `eval` and `new Function`;
  - `href={x}` where `x` can be a `javascript:` URL.
- Next.js: route handlers and server actions with no session check (`auth()`,
  `getServerSession`); middleware matchers that leave a route out; a secret exposed through
  a `NEXT_PUBLIC_` variable.
- Express: a mutating route with no auth middleware; `cors({ origin: true, credentials: true })`.
- SSRF: a server-side `fetch` or `axios` call with a request-supplied URL.
- Tools: `eslint-plugin-security` and `eslint-plugin-no-unsanitized` through ESLint's
  JSON formatter; semgrep's JS/TS rules. Both slot in as optional tools, like `semgrep`
  today.
- Dependencies: osv-scanner over `yarn.lock`, `package-lock.json` or `pnpm-lock.yaml`,
  or `npm audit --json` where there is no lockfile scanner.

**Performance.**
- HTTP N+1: an `await fetch` or `await api.get` inside a loop, or a request per list item
  in `useEffect`, where one batched call or `Promise.all` would do.
- Bundle size: a `next build` or source-map-explorer total as a ratcheted command, so a
  pull request that adds 400 KB says so.
- A client component (`"use client"`) that imports a server-only heavy module.

### C#

**What exists.** `repolens init` detects `.cs` and `.csproj` files. It writes commented
`[[report.commands]]` for `dotnet format --verify-no-changes` and
`dotnet build -warnaserror` with the .NET analysers. **Nothing in repolens parses C#.**

**What it needs**, in the order that pays off:

1. **SARIF ingestion.** This is the cheapest and biggest win. Roslyn analysers already
   write SARIF 2.1 (`dotnet build -p:ErrorLog=out.sarif,version=2.1`). A generic SARIF
   adapter turns that into repolens findings, with priority and baseline. It would
   serve semgrep and ESLint just as well. The analyser packs to recommend:
   - `Microsoft.CodeAnalysis.NetAnalyzers`: CA2100 for SQL, CA3001–CA3012 for injection,
     CA5xxx for crypto and deserialisation.
   - **Security Code Scan**, for taint through ASP.NET Core.
2. **Dependencies.** `dotnet list package --vulnerable --include-transitive --format json`
   (.NET 8 SDK and later) exits 0 whether or not it finds anything. An adapter must parse
   the JSON and turn each advisory into a finding. A bare command entry would never fail.
3. **A parser**, **tree-sitter-c-sharp**, for the structural tools. FeatureTrace markers
   are already line prefixes (`// @featuretrace:<tag>`), so adding `.cs` is mostly
   configuration. The lens, the capability-index detectors and docs coverage need
   syntax, not types. For type-resolved questions, use a small Roslyn global tool that
   emits JSON, and only if tree-sitter proves insufficient: it needs the .NET SDK
   wherever repolens runs.
4. **Docs coverage.** Count `///` XML doc comments on the `public` and `protected`
   members of public types. The compiler's own equivalent, CS1591 under
   `<GenerateDocumentationFile>`, is all or nothing; repolens adds the per-file ratchet.
   Use **DocFX** for `docs build`.
5. **ASP.NET Core route security.** This feeds the same BOLA and unauthenticated-mutation
   rules.
   - Controller actions and minimal-API endpoints.
   - `[Authorize]` and `[AllowAnonymous]` at class and action level.
   - `RequireAuthorization()`, and the fallback policy.
   - Route `{id}` parameters with no resource-based check (`IAuthorizationService.AuthorizeAsync`)
     and no filter on the caller.
   - MVC POSTs without `[ValidateAntiForgeryToken]`.
   - `FromSqlRaw($"...")` and `ExecuteSqlRaw` with interpolation.
     `FromSqlInterpolated` parameterises and is safe.
6. **Performance.**
   - EF Core N+1: a navigation property read inside a loop with no `Include`.
   - `ToList()` or `AsEnumerable()` before `Where`, which filters in memory.
   - Sync over async: `.Result`, `.Wait()`, `GetAwaiter().GetResult()`.
   - `async void` outside event handlers.
   - A new `HttpClient` per request.

## Suggested order

1. ~~The recorded defects~~: done.
2. SARIF ingestion. It unlocks C#, ESLint and semgrep at once.
3. tree-sitter for TS/JS, replacing the regexes.
4. Def-use taint beyond SQL, and the Flask and Django adapters.
5. The Next.js and Express adapters.
6. Extraction and publishing, including the GitHub Action and the Windows run.
7. The PostgreSQL `--dsn` mode.
8. C#: the parser, then docs coverage, then route security.

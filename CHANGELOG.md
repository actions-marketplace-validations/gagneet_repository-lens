# Changelog

All notable changes to repolens are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
`pyproject.toml`. Documentation sections that a release removed are kept verbatim under
[`docs/history/`](docs/history/) so that references to them still resolve.

## [Unreleased]

The stack-depth audit (merged as PR #16) and the follow-ups from a field evaluation on a large
repository. `pyproject.toml` still says 0.3.0.

### Added

**Field-evaluation follow-ups**
- `[impact] api_origins` lists configured origins (`PAYMENTS_API_URL`) that are this
  repository's API although their names say otherwise.
- `ARTIFACT_STORE_UNCONFIRMED` (info) counts and names the router/datastore artifact's
  `postgres_unverified_refs` that match no table the scan found.
- `[scan.performance] scope_key_patterns` (default empty) lowers an
  `performance/unbounded-sql-fetch` finding one severity step when every statement's
  `WHERE` compares a matching column with a value. The note is kept out of the fingerprint.
- JS/TS route registrations: `.route(path).<verb>()` chains, hapi/Fastify
  `.route({ method, path | url, handler })` objects and a router-named parameter given a
  handler by reference (`module.exports = function (app) { app.get(p, orders.list) }`) count
  as unmodelled routes, so client calls to them are info, not warnings.
- Dead-code judgements treat as entries the files a package.json names in `main`, `module`,
  `browser`, `bin` or `exports`, and every file under `app/` in a package using Expo Router.

**JavaScript / TypeScript and Next.js graph**
- Declarations include object-literal and class-field members. Every ES and CommonJS
  export form is read, including aliases, `export default memo(X)` and `export * from`
  barrels, and imports resolve through those barrels.
- `tsconfig`/`jsconfig` `paths` resolve through local `extends`. A package `extends` is
  reported as partial (`IMPORT_CONFIG_PARTIAL`).
- `new` expressions and JSX component renders (`RENDERS` edges) are recorded beside calls.
- `fetch`, SWR, axios and ky requests resolve module-constant base paths, and client base
  URLs are traced across modules. The new `[impact] client_api_base` covers a client the
  scanner cannot trace to its declaration.
- Next.js App Router pages, route groups, parallel-route slots and (optional) catch-alls,
  plus Pages Router pages and API routes. Client calls match handlers by route shape as
  `probable` edges.
- JS/TS data layers: Drizzle tables, Prisma schema models (`.prisma` files are read) and
  client accessors, TypeORM entities, Sequelize and Mongoose models, Knex tables and the
  MongoDB Node driver, each resolved through imports and barrels. A `db.<name>.<method>()`
  call is a MongoDB collection only when `db` is a MongoDB handle, so Sequelize registries,
  arrays and Prisma clients named `db` are not. A receiver bound in the file is a handle
  only when assigned from `<client>.db(...)`/`mongoose.connection.db`, typed as the driver's
  `Db`, or imported from a local module exporting one; an unbound receiver counts in a file
  importing `mongodb`/`mongoose` or in a mongo shell script. Untyped `db` parameters are no
  longer handles, which can drop collections an earlier build reported.
- Bare `&` in JSX text is re-parsed rather than reported as a parse error.

**PostgreSQL parsing, column checks and PL/pgSQL**
- `.sql` files are parsed one statement at a time. MERGE, TRUNCATE, GRANT and COPY are
  understood, and RLS, policy and trigger DDL is recovered lexically.
- SQL assembled in JS/TS variables (template fragments, ternaries, `+=`) is rebuilt with
  the spliced values as `$n`, so its tables parse. Other spliced values are named in
  `DYNAMIC_SQL`.
- Only SQL-shaped strings are parsed, so UI prose is not reported as broken SQL. The
  shape test ignores comments and quoted identifiers and accepts short aliases and
  `REFRESH`/`CALL`/`VALUES`/`TABLE`; SQL-shaped text it still rejects is `SQL_NOT_PARSED`
  (info) rather than silently dropped. In `.sql` files, text the parser only keeps as a
  generic command counts as `SQL_UNSUPPORTED_STATEMENT` only when it opens with a known
  PostgreSQL statement; anything else is `SQL_PARSE_ERROR`.
- `SQL_UNKNOWN_COLUMN` (new module `repolens/impact/columns.py`) flags a column in parsed,
  non-migration DML that the Prisma schema, or the `CREATE TABLE` DDL, does not declare.
  It is reported once per statement, with the mapped column as a hint. Columns added by
  `ALTER TABLE` join the Prisma model's; DDL in tests and fixtures is ignored; each
  package (nearest `package.json`, `pyproject.toml` or `setup.cfg`) is checked against
  its own schema, while `ALTER TABLE` additions and run-time reshaping apply repository-wide;
  unqualified names never resolve through `pg_schemas`; and a table that Knex, Sequelize,
  TypeORM or Django reshapes, or that run-time DDL can reach, is not checked. References in
  test paths, Prisma `view` blocks, and unqualified names where SQL (not a comment, string
  literal or function `SET` clause) changes `search_path` are not checked. A DDL catalog is
  not trusted when a migration in a language the scanner does not parse (Rails, Laravel,
  EF Core, Ecto, Go/Java/Rust strings, Liquibase) alters tables it cannot name. The Prisma
  provider is decided per package (CockroachDB counts as PostgreSQL), and a package with an
  unsupported provider does not borrow another package's tables.
- `SQL_PLPGSQL_OUTSIDE_BLOCK` flags top-level PL/pgSQL in a `.sql` script.
- `SQL_DIALECT_NOT_POSTGRES` (info, once per file) for a `.sql` file in another dialect
  (T-SQL, MySQL, Oracle, SQLite) or a dbt/Jinja template, instead of a parse error per
  statement. T-SQL is recognised from `GO` batches, `USE`, `SET NOCOUNT`, `EXEC sp_`,
  bracketed names and `SELECT TOP n`; such a file's tables are not recorded.
- `.sql` splitting keeps `BEGIN ATOMIC` bodies and `CREATE RULE` action lists whole and
  reads their tables; psql meta-commands are skipped (`\g`/`\gset`/`\gexec` end a
  statement) and psql variables (`:name`, `:'name'`, `:"name"`) are read as parameters,
  but not inside `E'…'` strings or array slices (`arr[:n]`); rows after
  `\copy … FROM stdin` are data. A statement with psql variables that still does not parse
  is `SQL_PARSE_ERROR`, so the analysis stays incomplete.
- A `CREATE RULE ... AS ON UPDATE TO t` event keyword is never recorded as a table.

**Python / FastAPI graph**
- Python extraction moved to `repolens/impact/python_scan.py`, with shared scan state in
  `repolens/impact/state.py`.
- FastAPI `api_route`, `add_api_route` and websocket routes; `Depends`/`Security` chains;
  request/response model edges (`ACCEPTS_MODEL`, `RETURNS_MODEL`); router prefixes
  resolved from constants and settings defaults; and sub-app mounts.
- SQLAlchemy, SQLModel and Alembic tables and foreign keys. MongoDB driver and ODM
  collections are claimed only through driver methods.
- Import-aware candidate calls include decorators, dependencies and monorepo package roots.
- A query that names a table or collection exactly seeds from that store, so words it
  shares with other names no longer crowd out the store's own chain.
- The API and CLI views take a `depth` (default `VIEW_DEPTH = 6`, maximum 8). The
  OpenAPI and Postman contracts were regenerated.

**Security findings**
- `security/sql-string-interpolation`: a value spliced into SQL text that is traced,
  within one file, to `process.argv`, request input or Next.js route
  `params`/`searchParams`. Values that cannot carry SQL text count as safe: numeric
  conversions and arithmetic, `typeof`/`Number.isInteger`/`includes` ternary guards,
  node-postgres and pg-format quoting (`%I`/`%L`), mysql/sqlstring `escape`/`escapeId` on a
  SQL connection, and placeholder lists built from `map`/`flatMap`/`Array.from` callbacks
  that read only the index or a one-argument `fill`. HTML/CSS escapers and `util.format`
  do not. SQL rebuilt from long `+` chains keeps every spliced value.
- Deployment-aware exposure for the built-in Python checks (new module
  `repolens/scan/deploy.py`). The checks read the Python server targets in systemd
  units, Dockerfiles, compose files, Procfiles, supervisord programs, shell scripts and
  Python run scripts; `package.json` scripts and test/CI/dev files only mark apps live.
  - When deployment is statically known, a route file that only an undeployed app
    reaches ranks `undeployed`. Its findings are lowered in priority, never hidden, and
    keep their fingerprints.
  - New settings: `[scan] deployment_detection` (default on) and `[scan] entrypoints`.
- FastAPI security scheme instances (`OAuth2PasswordBearer`, `HTTPBearer`, `APIKey*`
  and others, configurable as `auth_scheme_classes`) count as authentication in
  `Depends(...)`. Instances made with `auto_error=False` do not.
- A file a built-in check cannot finish, such as generated code nested past the
  recursion limit, becomes `<tool>/could-not-scan`. The rest of the tree is still
  scanned, and the analysis is marked incomplete. Inputs a tool never opened appear in
  `ToolRun.notes` and in SARIF as `executionSuccessful: false`.

**Outputs and provenance**
- `repolens analyze` and `repolens report` also write `report.html`: the same review as
  one self-contained page, with no scripts, a restrictive Content-Security-Policy and
  escaped content. Rows are capped per group and for the whole page; once the page budget
  is spent, further rule and diagnostic groups are summarised in one line instead of being
  listed, so an imported SARIF file with a distinct rule per result still gives a bounded
  page. The API exports it as `format=html`.
- `analysis.json`, the Markdown and HTML reports, SARIF, `linkage.mmd` (a closing
  `%% produced by` comment), the API response and `impact doctor` name the build that
  produced them. `analysis.json` gains `tool_build`
  (version, git commit and dirty flag, a hash of the package's shipped source and data
  files, optional extras with versions), `config_sha256` and `incomplete_reasons` (one line per cause);
  SARIF drivers carry the stamp as `properties.repolensBuild`; the Markdown and HTML
  reports and `impact doctor` print it. New module `repolens/provenance.py`.
- `analyze` prints why an analysis is incomplete instead of only `complete=False`.

**Scan inputs and resilience**
- `[impact] respect_gitignore` (default on): untracked files that git ignores are not
  scanned, by the graph or by the built-in Python checks (including `repolens scan` and
  `repolens report`, and migration discovery); both read the switch from `[impact]` and
  `.impact-tracer.json`. When git cannot list them the graph scan reads everything and
  reports `GITIGNORE_UNAVAILABLE` (info); the Python checks read everything silently.
  Deployment manifests are read even when ignored.
- `UNRESOLVED_LOCAL_IMPORT`, `UNRESOLVED_ROUTER_MOUNT` and `ROUTER_MOUNT_CYCLE` raised by
  test code (a `tests/`, `test/`, `__tests__/`, `e2e/` or `cypress/` directory, or a
  `test_*.py`, `*_test.py`, `conftest.py`, `*.test.*`, `*.spec.*` or `*.cy.*` file, in any
  language) stay in the diagnostics but no longer make the analysis incomplete. A test app
  mounting a router from a factory is not a served application. The same diagnostics in
  application code (including a `spec/`, `fixtures/` or `testdata/` directory outside a
  test directory), and test files that fail to parse or are skipped, still do.
- Every git command repolens runs (the gitignore listing, commit stamps in `analyze` and
  `repolens report`, and the artefact, lens and init commands) overrides the target's
  `core.fsmonitor`, drops inherited `GIT_*` variables and has a timeout. The dirty flag
  comes from `diff-index`/`diff-files`, which run no clean filters, instead of
  `git status`; when git cannot tell it is unknown (`+unknown`, `dirty: null`), never
  clean.
- A non-source file over `max_file_bytes` (JSON, YAML, Markdown, lock files, logs, ...) is
  `DATA_FILE_SKIPPED` (info) instead of `FILE_SKIPPED`. `package.json` and
  `tsconfig`/`jsconfig` files, which the scanner interprets, stay `FILE_SKIPPED`.
- Each whole-repository pass of the graph scan is isolated: a crash becomes
  `ANALYSIS_PASS_FAILED`, which makes the analysis incomplete, and later passes still run.
- Stores seen only through regex matches are marked unverified and left out of the default
  overview; the Mermaid map says how many were left out.

**Documentation and packaging**
- This changelog.
- `docs/history/roadmap-0.2.md` and `docs/history/installation-0.2.md` restore the 0.2
  roadmap and installation guide verbatim. See "Documentation" under 0.3.0.
- `docs/installation.md` "Vendoring a copy": a `VENDORED.json` record (upstream commit and
  tree hash) and the manual procedure to create and verify it. A
  `repolens vendor verify` command is listed in the roadmap as planned.

### Changed
- A configured origin is this repository's API only when its name, after a framework prefix
  (`NEXT_PUBLIC_`, `VITE_`, ...), is made of words such as API, BACKEND, SERVER, BASE or URL,
  or it is listed in `api_origins`. `${process.env.STRIPE_API_URL}/v1/charges` is now an
  `EXTERNAL_API_REFERENCE` instead of a link to a local `/api/v1/charges`. `EXTERNAL_API_REFERENCE`
  names the origin. `baseURL: process.env.API_URL` and `localhost`/`127.0.0.1` origins are
  configured origins (`probable`) instead of an exact local base and an external URL.
- A call matched only after skipping the path a configured origin may carry needs a literal
  segment and is always `ambiguous`. A URL of only runtime segments (`${API_URL}${path}`) and
  an open-ended or runtime-segment URL that more than `max_ambiguous_targets` handlers could
  serve (a `/api${url}` request wrapper) are `DYNAMIC_HTTP_REQUEST`: not linked and not a gap.
  Such an endpoint stores `matched_handler_count`, not the list of every handler id.
- A query-string tail (`/items${query}` where `query` is `?a=1` or "", `new URLSearchParams`,
  `"?" + x`) matches only its exact path, not every handler under the prefix.
- The base URL assumed for an untraced client is the one its package declares, else the
  repository's one. It is not added to a URL that already starts with it, and jQuery, Angular
  `HttpClient`, bare axios/ky, browser-test globals (`browser`, `cy`, `page`, `driver`) and
  unbound receivers in test code never get it.
- JS/TS SQL allow-list guards accept inline literal arrays, objects and Sets,
  `Object.keys`/`Object.values` of a literal table, the consequence of `if (guard)` and the
  code after an `if (!guard)` that throws, returns, breaks or continues. `if
  (!Number.isInteger(n)) throw` now proves `n`.
- JS string and template escapes are decoded. A query or URL with a backslash used to be
  dropped without a diagnostic; `'… = \'' + req.query.a + '\''` is now a quoted splice and
  `SQL_INJECTION_RISK`.
- Literal dynamic `import()` (`React.lazy`, `next/dynamic`) and side-effect imports load the
  whole module for dead-code judgements, and a re-export-only `index` barrel is no longer an
  entry file.
- Store references matched only by a pattern in test code or fixtures link only to stores
  other evidence found, so a vendored tool's test SQL no longer creates tables. Unvalidated
  artifact table names link only to tables the scan found by more than a pattern.
- `performance/unbounded-sql-fetch` no longer reports a `GROUP BY` whose select list is only
  group keys, aggregates and constants, in SQL text or SQLAlchemy `select(...)`/`query(...)`
  with `.group_by(...)` and `func.*` aggregates.
- A call to a path that is served only for other methods is `API_METHOD_MISMATCH` (a
  likely 405), and a live one is the finding `stack/api-method-mismatch` in a new `stack`
  tool run. A call to a path with no handler at all stays `API_CALL_WITHOUT_HANDLER`.
  Both are demoted to info when every caller is likely dead code: its module is not
  imported from any routed page, handler or entry file, or it is an exported function
  that no live module imports or calls. Exports of an entry file are never judged dead.
  Both are also info, naming the routes, when code outside test paths registers server
  routes the scanner does not model (routers under a mount prefix, NestJS controllers,
  file-based handlers, Remix/React Router `loader`/`action`, Flask/Django/… applications
  that are constructed). Look-alike receivers (`new Map().get`, client-side navigators),
  catch-alls on a listening server and framework imports with no app do not count. Literal
  `app.<verb>("/path", handler)` routes on an Express/Fastify/Hono/Polka/Elysia server the
  same file starts listening on are probable endpoints.
- JS/TS taint and SQL rebuilding are cached per binding, identifiers resolve per function
  and block, and `+` chains are folded in a loop, so reused bindings, `sql = sql + …`
  chains and sibling blocks no longer take exponential or quadratic time; right-nested URL
  concatenation stops after 64 levels instead of failing the file.
- HTTP clients the scanner cannot trace to a declaration resolve generically: a client
  bound from a hook (`const { api } = useAuth()`) or an undeclared global receiver uses
  `[impact] client_api_base`, `[impact] client_receivers`, or the repository's single
  declared client base URL. A request whose last path segment is glued to a runtime value
  (`/export.${fmt}`) matches handlers by prefix, and a runtime segment may match a literal
  handler segment; such widened matches are `ambiguous` when more than one handler fits.
  `.get(path, handler)` on a receiver made by a router factory (`express()`, `Router()`,
  `new Hono()`, `fastify()`, ...) or on an unbound `app`/`router`/`server` name is a route
  registration, not a client request; `$.get(url, callback)` is still a request.
  Optional chaining (`api?.get(...)`), `export default axios.create(...)`, a client taken
  through CommonJS `require`, and Angular `HttpClient` from `inject()` or constructor
  injection are read. A literal absolute base URL is an external API, never this
  repository's.
- HEAD requests match GET handlers, and OPTIONS requests are never reported as unhandled.
- A URL whose base is a parameter with a literal default (`function Widget({ apiBaseUrl =
  "/api" })`) uses that default. A request behind a configured origin
  (`${process.env.API_URL}/orders`) that no handler serves as spelled may match a handler
  whose route ends with its path, since the origin may carry a prefix; such matches are
  `probable`, or `ambiguous` when more than one handler fits.
- A FastAPI router built from an aliased import (`from fastapi import APIRouter as
  _APIRouter`) is resolved when it is mounted, instead of `UNRESOLVED_ROUTER_MOUNT`, also
  when a file or folder anywhere in the repository shares the framework's name (a vendored
  tool's `fastapi.py`), which leaves the import itself unbound.
- Dead-code judgement also follows destructured `require`, same-file uses of an exported
  function by value, and the entry files of Remix, SvelteKit and Next.js metadata routes.
  A repository with `.vue`, `.svelte`, `.astro` or `.mdx` files gets no dead-code
  judgements, because those files are not parsed.
- SQL interpolation taint recognises Koa, hapi, NestJS parameter decorators,
  `url.searchParams.get()` and loader/action `params`; a value looked up in a constant
  table or guarded by an allow-list check is not tainted, and prose passed to `.query()` is
  not reported.
- `[lens] javascript_parser` pins the function lens parser (`"regex"` by default, or
  `"tree-sitter"`); it is recorded in the digest, and `lens --check` refuses a digest built
  by the other parser with exit 2 instead of reporting every function as stale.
- `repolens report --require a,b` fails the run when a named tool is skipped, errors or is
  not selected. External tools are also found through `REPOLENS_TOOLS_BIN` and beside the
  interpreter running repolens.
- The built-in Python checks share one parse cache per run, so security and performance no
  longer parse the tree several times each.
- Import resolution checks candidates against the admitted file inventory lexically and
  remembers each answer, instead of calling `realpath` on every candidate. On a large
  Python repository this was most of the graph scan's time; results are unchanged.
- Parsing target Python no longer prints the target's own `SyntaxWarning`s (for example
  invalid escape sequences) to the terminal, including string annotations re-parsed for
  request models and `python -c` code in deployment manifests.
- Deployment detection is stricter: package.json scripts, tests/CI/dev files and `--reload`
  servers never make a deployment known, and a deployment format that is not interpreted
  (Kubernetes, Helm, `app.yaml`, `fly.toml`, ...) blocks the `undeployed` demotion.
  `uvicorn.run("pkg.mod:app")` in a script a manifest runs, and `python -m pkg`
  (`pkg/__main__.py`), are followed.
- Deployment detection fails closed. Nothing is demoted to `undeployed` when:
  - an application name could be more than one file;
  - a manifest cannot be read or parsed (compose flow style, quoted keys, anchors,
    `extends`/`include`, over-long command lines);
  - a compose service or final Dockerfile stage takes its command from an image, unless
    the image cannot serve the application (plain OS/interpreter images, postgres, redis,
    nginx, ...);
  - a run script changes `sys.path` or the working directory, or passes `app_dir=`;
  - a manifest symlink or directory leaves the repository;
  - a Kubernetes values file, App Engine service, Fly environment file, systemd drop-in,
    Bicep start command or a server line in a Makefile/Taskfile/Windows script exists;
  - a reachable file imports modules chosen at run time (`pkgutil.iter_modules`, a
    non-constant `import_module`). A constant `import_module("pkg.mod")` is now followed
    by reachability.
  Any error while reading manifests also leaves the deployment unknown instead of failing
  the security check. `Dockerfile-*`/`Dockerfile_*`/`Containerfile*` are read.
- `repolens docs build` imports each module pdoc would document before running pdoc.
  - A module whose import fails only because a third-party package is not installed,
    such as `repolens.api.app` without FastAPI, is left out and named ("NOT DOCUMENTED,
    dependency not installed").
  - Before, pdoc exited 1 and wrote nothing.
  - `[docs.python] missing_dependency = "fail"` restores a hard failure.
  - A first-party import error still fails the build, now before pdoc starts and
    naming the module.
- `LICENSE` and `pyproject.toml` `authors` name the Repository Lens contributors.
- The object-ownership check (`security/object-route-without-ownership-check`) no longer
  treats dependencies with one domain's scope word in their name specially. List
  dependencies that return a tenant, organisation or workspace instead of the caller in
  `[scan.security] scope_dependency_patterns` (default empty). Its remedy, the RLS remedy
  and the FeatureTrace scope remedy use generic wording.
- `docs/history/` keeps the 0.2 documents with identifiers of the repository the toolkit
  was extracted from generalised.
- `requirements-ci.txt` comments describe this repository's layout and the vendored
  layout, instead of paths from the repository the toolkit was extracted from.
- Public symbols across the package gained docstrings, so the docstring ratchet a
  vendoring repository runs is not failed by repolens's own code.

### Fixed
- The internal configured-origin marker was the text `//configured`, so a literal base
  `//configured.example.com/api` was read as a configured origin. It is now a NUL-delimited
  sentinel no URL can contain.
- A parameter default at the head of a URL is used as the base only when it starts with `/`
  or a URL scheme: `{ id = "me" }` no longer turns `${id}/profile` into `me/profile`.
- A PATCH to a GET-only catch-all route is `API_METHOD_MISMATCH`, not
  `API_CALL_WITHOUT_HANDLER`.
- `[impact] backend_api_prefix` is no longer applied twice. A route whose resolved path
  already starts with the prefix keeps its path, and the scan reports
  `API_PREFIX_ALREADY_RESOLVED`.
- `repolens lens` no longer crashes with Tree-sitter installed. The JS facts'
  calls became `(owner, called, line, kind)` tuples, and the lens still unpacked three
  values. JSX renders are no longer listed as callees.
- The docs example path in `docs/impact.md` pointed at a file that does not exist. It now points at
  `examples/example-project.impact-tracer.json`.
- Security and performance checks read `a + b + ...` chains iteratively. A generated
  3000-term concatenation no longer raises `RecursionError`.

### Upgrade notes
- **Scanner revision 9**: cached impact indexes are rebuilt. Expect fewer edges and stores:
  calls behind another service's origin become `EXTERNAL_API_REFERENCE` (list your own in
  `api_origins`), request wrappers are no longer linked to every handler (those handlers may
  now report `API_HANDLER_WITHOUT_STATIC_CALLER`), and tables only test code or an artifact's
  unvalidated list named are gone.
- **`backend_api_prefix`**: remove it from `[impact]` or `.impact-tracer.json` when the
  application declares the prefix itself (`APIRouter(prefix=...)`,
  `include_router(..., prefix=...)`, a mount). Keep it only for a prefix the code does not
  declare, such as a proxy or `root_path`. Leaving it set is harmless now, but each
  affected route reports `API_PREFIX_ALREADY_RESOLVED`.
- **Codes that do not make an analysis incomplete**: advisory `SQL_NOT_PARSED`,
  `SQL_UNSUPPORTED_STATEMENT` (it used to), `IMPORT_CONFIG_PARTIAL`,
  `API_PREFIX_ALREADY_RESOLVED`, `GITIGNORE_UNAVAILABLE`, `SQL_DIALECT_NOT_POSTGRES` and `DATA_FILE_SKIPPED` (an
  oversized non-source file, which used to be `FILE_SKIPPED`); and warnings about the
  target that was fully read: `SQL_PLPGSQL_OUTSIDE_BLOCK`, `SQL_UNKNOWN_COLUMN`,
  `SQL_INJECTION_RISK` and `API_METHOD_MISMATCH`. `ANALYSIS_PASS_FAILED` does make it
  incomplete.
  - An analysis that was incomplete only because of RLS, policy or trigger DDL is now
    complete.
  - Do not gate CI on these codes as if they were scan failures.
  - `<tool>/could-not-scan` findings do make it incomplete.
  - Link diagnostics (`UNRESOLVED_LOCAL_IMPORT`, `UNRESOLVED_ROUTER_MOUNT`,
    `ROUTER_MOUNT_CYCLE`) located in test code no longer do.
- **Scan coverage**: `respect_gitignore` defaults to on, so untracked git-ignored files
  (backups, build output) drop out of the graph and of the Python checks' findings. Set it
  to `false` to scan them.
- **Caches**: `SCANNER_REVISION` went from 2 to 8, so every `.impact-tracer/index.json`
  is rebuilt on the first run. Expect a slower first scan, and graph diffs in committed
  outputs, from the new node and edge kinds.
- **Report baselines**: new rules (`security/sql-string-interpolation`,
  `stack/api-method-mismatch`, `<tool>/could-not-scan`), the new `stack` tool run in
  `analyze`, the stricter deployment rules and the `undeployed` exposure can change findings and their
  priority. Review them, then update the baseline with `repolens report --update-baseline`.
  Fingerprints of existing findings are unchanged.
- **Docs build**: a `"!repolens.api"` entry added to `[docs.python] modules` only to get
  past a missing FastAPI can be removed.
- **Vendored copies**: replace the whole directory, then record it in `VENDORED.json`
  (see `docs/installation.md`).

## [0.3.0] - 2026-09-13

Merged as #1 (`bc0a10a`), from `e285bf6` (implementation), `d255c02` (tests) and
`eb015d3` (documentation and API contracts). The previous version is 0.2.0 (`f73033c`).

### Added
- Tree-sitter JavaScript/TypeScript extraction (`repolens/core/javascript.py`, optional
  `stack` extra), with a degraded-parser diagnostic and a regex fallback when it is
  absent.
- Static FastAPI router linkage (`repolens/impact/fastapi.py`) and import-bound call
  resolution (`repolens/impact/resolution.py`).
- PostgreSQL parsing through SQLGlot (`repolens/impact/postgres.py`): CTE-aware table
  references with read/write/DDL detail on `TOUCHES_STORE` edges.
- Bounded, BOM-tolerant source reads (`repolens/impact/source.py`), `max_file_bytes` and
  `max_files` limits, and symlink/path checks.
- `repolens analyze` (`repolens/analysis.py`): one analysis shared by the CLI and the API,
  with an explicit `complete` flag, Markdown/JSON/Mermaid/SARIF output and `--check`.
- An authenticated loopback API (`repolens serve`, `repolens/api/`, optional `api` extra),
  with generated OpenAPI and Postman contracts in `docs/api/` (`repolens api export`).
- Explicit trusted extractor plugins from the `repolens.extractors` entry-point group
  (`repolens/impact/plugins.py`, `docs/plugins.md`).
- SARIF import with producer-failure visibility (`repolens/report/sarif.py`).
- An audit report with per-capability confidence ratings
  (`docs/audit/2026-09-12-professional-foundation.md`).
- Tests for stack linkage, the API contracts and SARIF import (184 tests at merge).

### Changed
- Evidence origin is kept separate from resolution on every edge. Name-only matches are
  `probable`, never `exact`, and store edges keep the `TOUCHES_STORE` kind.
- Hardened migration admission (default and custom roots), node limits, query bounds,
  malformed-artifact completeness and repository-policy handling. An API scan request
  may set only `max_file_bytes` and `max_files`, capped by the API, applied on top of
  the repository's `repolens.toml` policy.
- `[impact]` configuration validation. Artifact paths must be relative and inside the
  repository.
- The function lens uses Tree-sitter for frontend files when it is installed.

### Documentation
- `README.md`, `docs/impact.md`, `docs/installation.md` and `docs/roadmap.md` were
  rewritten around the audited scope.
- The rewrite removed sections that other repositories cite. They are restored verbatim
  in [`docs/history/roadmap-0.2.md`](docs/history/roadmap-0.2.md) and
  [`docs/history/installation-0.2.md`](docs/history/installation-0.2.md):
  - roadmap §1 "Fixed", §2 "Still open", §3 "Extracting repolens into its own
    repository" and §4 "A robust product: what to add";
  - installation "Making it a separate repository", "Baselines", "Merge hooks for
    generated artefacts", "Upgrading", "Removing it" and "Troubleshooting".

## [0.2.0]

Initial public commit (`f73033c`). It includes FeatureTrace markers and maps, the
function lens, owners/capability index, the change-impact tracer, the built-in
security/performance/migration checks, docstring coverage and code-reference builds,
generated-artefact hooks, validation gates, the unified findings report and `repolens init`.

[Unreleased]: https://github.com/gagneet/repository-lens/compare/bc0a10a...HEAD
[0.3.0]: https://github.com/gagneet/repository-lens/compare/f73033c...bc0a10a
[0.2.0]: https://github.com/gagneet/repository-lens/commit/f73033c

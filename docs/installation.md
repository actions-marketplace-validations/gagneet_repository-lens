# Installation and CI

Repository Lens is a Python package that analyzes one local checkout. It does not
clone, install or execute the checkout being analyzed.

## Requirements and optional extras

| Extra | Provides | Use it for |
|---|---|---|
| *(none)* | Python 3.11+ standard-library core | existing FeatureTrace, lens, owners and lower-level commands |
| `stack` | Tree-sitter JavaScript/TypeScript grammars and SQLGlot | focused JS/TS/Next.js/PostgreSQL analysis |
| `api` | FastAPI and Uvicorn | local authenticated API, Swagger UI and ReDoc |
| `test` | HTTPX and PyYAML | API tests and the full test suite |
| `yaml` | PyYAML | owners/capability files |
| `docs` | pdoc | HTML Python documentation |

Install from this checkout:

```bash
python -m pip install -e '.[stack,api]'
```

For development and tests:

```bash
python -m pip install -e '.[stack,api,test,yaml,docs]'
```

The package has no required runtime dependency. If `stack` is absent, `impact` reports a
degraded JavaScript parser; `analyze` exits with an actionable dependency message rather
than claiming full coverage.

## First run

From the repository to inspect:

```bash
repolens analyze --out .repolens/analysis
```

Use `repolens --root /path/to/checkout analyze` when the command is launched elsewhere.
The report writes JSON, Markdown, Mermaid and SARIF under the chosen output directory.

Start the local API only when you need an interactive client:

```bash
export REPOLENS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
repolens --root /path/to/checkout serve
```

The service listens on `127.0.0.1` and retains only the latest scan in memory. See
[`api/README.md`](api/README.md) for Swagger/OpenAPI and Postman usage.

## Bootstrap a target repository

`init` detects common source/test/migration directories and writes a starter
`repolens.toml`:

```bash
repolens --root /path/to/checkout init --dry-run
repolens --root /path/to/checkout init --ci github
```

Review the generated paths and rules before committing them. Repository configuration is
data, not target application code, and artifact paths must remain inside the checkout.

## CI

Run the deterministic test suite and focused analysis in CI:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: '3.11'
- run: python -m pip install -e '.[stack,api,test]'
- run: python -m unittest discover -s tests -q
- run: repolens analyze --check --out .repolens/analysis
```

Treat `complete=false`, parser failures, file limits and unreadable files as review
signals. A clean report is not proof of runtime safety. Pin the package version or commit
in production CI and regenerate `docs/api/*` whenever the API changes:

```bash
repolens api export --out docs/api
git diff --exit-code -- docs/api
```

The existing `action.yml` is an optional composite action for the lower-level impact
report. It does not provide remote-repository access or a hosted service.

## Upgrading and troubleshooting

- Check `repolens --version` and installed parser versions with `python -m pip show
  tree-sitter tree-sitter-javascript tree-sitter-typescript sqlglot`. Parser versions
  contribute to the graph's configuration fingerprint.
- Delete a stale `.impact-tracer/index.json` only when you want to force a rebuild;
  content/config fingerprints normally invalidate it automatically.
- Increase `max_file_bytes` or `max_files` deliberately, understanding that larger
  values consume more memory/time. The API imposes tighter request bounds.
- If Tree-sitter or SQLGlot is missing, install `.[stack]` in the same environment that
  runs `repolens`.
- SARIF producer files are imported as evidence only. External property files and
  unsuccessful producer runs remain incomplete and cannot be baselined.

## Security posture

Run local analysis with reviewer-level permissions, not production credentials. The
scanner uses bounded UTF-8 reads, rejects source symlinks and artifact paths that escape
the root, never invokes target code, and keeps plugin loading explicit. Plugins are
trusted in-process Python and are not a sandbox; hosted provider checkouts require a
separate isolated worker design and are not part of this release.

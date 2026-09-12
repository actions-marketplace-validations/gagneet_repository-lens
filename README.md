# repolens — Code Visibility & Traceability for Python Repositories

A comprehensive, zero-configuration code-understanding toolkit for Python repositories. **repolens** provides feature traceability, per-function insights, capability indexing, change-impact analysis, and automated code quality reporting—all configured through a single `repolens.toml` file at your repository root.

## 🎯 What repolens Does

| Command | Purpose |
|---------|---------|
| `featuretrace map` | Visualize features as Mermaid flowcharts showing data flow from UI to database |
| `featuretrace audit` | Validate `@featuretrace` markers and maintain traceability quality |
| `lens` | Build a function index: who calls it, what calls it, what breaks if it changes |
| `lens similar` | Search the function index by behavior to avoid reimplementing existing features |
| `owners` | Maintain a capability index to ensure each concept has one clear owner |
| `impact` | Standalone change-impact tracer: scan, query, and doctor the impact graph |
| `artefacts regenerate` | Rebuild derived/generated files after a merge |
| `artefacts install-hooks` | Register merge drivers and post-merge hooks for generated files |
| `artefacts verify` | Ensure `.gitattributes` and regeneration rules stay in sync |
| `gates` | Verify every validation script is reachable and can fail the build |
| `docs coverage` | Track docstring coverage for public Python and TypeScript symbols |
| `docs build` | Generate HTML API docs via pdoc (Python) and TypeDoc (TypeScript) |
| `report` | Run all tools in one pass and produce a single prioritized findings list (Markdown, JSON, SARIF) |
| `init` | Bootstrap repolens in a new repository: detect structure, write config, set up CI |
| `rules` | Browse and display portable, repository-agnostic rules documents |

## ⚡ Quick Start

### Installation

```bash
# From PyPI
pip install repolens

# Or from source (editable install)
pip install -e .
```

### Basic Usage

```bash
# Initialize in your repository (detects Python/TypeScript structure automatically)
repolens init

# Build the function index for your Python codebase
repolens lens

# Audit FeatureTrace markers
repolens featuretrace audit

# Check documentation coverage
repolens docs coverage

# Run all checks and generate a report
repolens report

# Generate full HTML API documentation
repolens docs build --strict
```

### Running on Another Repository

```bash
repolens --root /path/to/repo featuretrace map
repolens --root /path/to/repo report --check --fail-on P1
```

## 📦 Core Features

### 1. **FeatureTrace Markers** (`repolens/featuretrace/`)
- Declare which feature a file belongs to with `@featuretrace:<tag>` markers
- Specify layers: frontend, router, service, domain, worker, cron, model, test, etc.
- Map data flow: where data enters, flows through, and exits the system
- Track related files, feature toggles, database tables, and test coverage
- Render as interactive Mermaid flowcharts, mindmaps, and structured JSON

**Example marker:**
```python
# @featuretrace:user-login — Handle user authentication flow
# Layer: router
# Data flow: request → auth_service → user_model (authentication)
# Related: backend/auth.py
#          backend/models/user.py
# Tests: tests/auth_test.py
```

### 2. **Function Lens** (`repolens/lens/`)
- Index every function across configured source directories
- For each function, discover:
  - Purpose and docstring
  - Direct callers and callees (name-based, upper bound)
  - Routes, guards, and data stores it interacts with
  - Tests that reference it by name
  - FeatureTrace tags and capability ownership
- Search similar functions by behavior to reduce duplication
- Call edges are name-based (never type-resolved) for conservative accuracy

### 3. **Static Analysis & Security Scanning** (`repolens/scan/`)
- **Security checks:** BOLA/IDOR candidates, object-level authorization gaps
- **Performance checks:** SELECT queries without LIMIT, N+1 query patterns
- **Database migrations:** Alembic migration validation (NULL without defaults, RLS, security_invoker, index locks)
- **Python AST-based:** Import-free, file-only parsing—no code execution
- Every finding includes:
  - **Severity:** How bad if true (CRITICAL, HIGH, MEDIUM, LOW)
  - **Confidence:** How likely it's real (HIGH, MEDIUM, LOW)
  - **Exposure:** unauthenticated, authenticated, internal, unreachable
  - **Priority:** Severity × Confidence for sorting

### 4. **Impact Tracing** (`repolens/impact/`)
Standalone, read-only change-impact graph:
- **Scan:** Build a dependency graph from your repository
- **Query:** Find what changes when you modify a file/function
- **Doctor:** Identify structural issues in the dependency graph
```bash
repolens impact scan          # Build the graph
repolens impact query X       # What depends on X?
repolens impact doctor        # Structural health check
```

### 5. **Capability Index** (`repolens/owners/`)
- YAML-based registry of who owns what concept
- Ensure each capability has one clear owner
- Integrate with the function index to detect gaps
- Optionally show impact across owned capabilities
```bash
repolens owners --impact      # Show impact of each owner's changes
repolens owners --check       # Validate index completeness
```

### 6. **Documentation** (`repolens/docs/`)
- **Coverage:** Track docstring coverage per file and language
  - Python: modules, classes, functions, methods (not starting with `_`)
  - TypeScript/JavaScript: top-level exports
- **Build:** Generate HTML API docs from pdoc (Python) + TypeDoc (TypeScript)
- **Ratchet mode:** Prevent regression—fail CI if coverage declines

```bash
repolens docs coverage --missing backend/api     # Show all undocumented symbols
repolens docs coverage --check                   # Fail if regression
repolens docs build --strict                     # Strict pdoc + TypeDoc
```

### 7. **Generated Artifacts Management** (`repolens/artefacts/`)
- Register a custom merge driver for generated files
- Automatically regenerate artifacts after merges
- Verify `.gitattributes` stays in sync with regeneration rules
- Prevent manual edits to generated files

```bash
repolens artefacts install-hooks       # Set up post-merge hooks
repolens artefacts regenerate          # Rebuild artifacts now
repolens artefacts verify              # Check consistency
```

### 8. **Validation Gates** (`repolens/gates/`)
- Ensure every validation script is reachable from the build
- Check that every audit (ratchet) can actually fail
- Build a dependency graph of validation → execution

### 9. **Unified Reporting** (`repolens/report/`)
- Run all tools in one pass
- Combine findings from security, performance, migrations, docstrings, coverage
- Output in Markdown, JSON, or SARIF format
- Support for baselines and ratchets (CI-safe incremental checks)

```bash
repolens report                           # Generate .repolens/report/report.md
repolens report --check --fail-on P1      # Fail on new P1 findings
repolens report --update-baseline         # Accept today's findings as baseline
```

## 🔧 Configuration

Every command reads `repolens.toml` at your repository root. No repository-specific facts are hardcoded in the package.

**Example repolens.toml:**
```toml
[project]
name = "my-app"
python_root = "src"
typescript_root = "frontend"
tests_dir = "tests"

[featuretrace]
auto_discover = true
layer_validation = true

[lens]
search_roots = ["src", "lib"]

[owners]
registry_file = "OWNERS.yaml"  # Optional: PyYAML required

[docs]
coverage_check = true
build_pdoc = true
build_typedoc = false

[artefacts]
rules = [
  { pattern = "**/*.generated.py", regenerate = "scripts/codegen.py" }
]

[report]
require = ["ruff", "bandit"]
fail_on = ["P0", "P1"]
```

Run `repolens init` to auto-detect your structure and create a starter config.

## 📋 Configuration Details

### repolens.toml Structure
- **[project]:** Project metadata and source directories
- **[featuretrace]:** FeatureTrace marker rules
- **[lens]:** Function index settings
- **[owners]:** Capability index path (optional, requires PyYAML)
- **[docs]:** Documentation coverage and build settings
- **[artefacts]:** Generated file management
- **[report]:** Report generation and CI integration
- **[scan]:** Security and performance scan configuration

## 🚀 Python Support

- **Python 3.11+** (uses `tomllib` from the standard library)
- **Core dependencies:** None (zero by default)
- **Optional dependencies:**
  - `PyYAML` — for owners/capability index (`pip install repolens[yaml]`)
  - `pdoc>=14` — for docs build (`pip install repolens[docs]`)
  - `TypeScript/Node.js + npx` — for TypeDoc (fetched on first use)

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/

# Run specific test module
python -m pytest tests/test_lens.py -v

# Run with coverage
python -m pytest --cov=repolens tests/
```

## 📚 Documentation

- **[docs/installation.md](docs/installation.md)** — How to install repolens in another repository, CI setup, upgrades, troubleshooting
- **[docs/impact.md](docs/impact.md)** — Detailed guide to the impact tracer
- **[docs/roadmap.md](docs/roadmap.md)** — Known issues, open tasks, future work (C#, TypeScript security, etc.)
- **[repolens/rules/](repolens/rules/)** — Repository-agnostic, portable rules documents

## 🏗️ Architecture

```
repolens/
├── cli.py                 # Command dispatcher
├── config.py              # repolens.toml loading and validation
├── featuretrace/          # Feature mapping and marker audit
├── lens/                  # Function indexing and similarity search
├── impact/                # Change-impact graph scanner and query
├── scan/                  # Security and performance detectors
│   ├── security.py        # BOLA/IDOR, auth checks
│   ├── performance.py     # Query limits, N+1 detection
│   ├── migrations.py      # Alembic migration validation
│   ├── python_ast.py      # AST parsing utilities
│   └── wiring.py          # Call graph construction
├── owners/                # Capability index management
├── docs/                  # Documentation coverage and building
├── artefacts/             # Generated file management
├── gates/                 # Validation reachability
├── report/                # Unified findings report
├── core/                  # Shared utilities
│   ├── console.py         # Terminal output
│   ├── files.py           # File operations
│   ├── findings.py        # Finding model and priority
│   ├── git.py             # Git operations
│   └── ratchet.py         # Baseline and ratcheting
├── rules/                 # Portable rules (Markdown)
└── templates/             # Configuration templates
```

## 🛠️ CLI Examples

### FeatureTrace
```bash
# Generate Mermaid flowcharts for all features
repolens featuretrace map

# Audit marker quality and generate a report
repolens featuretrace audit --check

# Show staleness gates (if any markers are outdated)
repolens featuretrace audit --check --verbose
```

### Function Lens
```bash
# Build the function index
repolens lens

# Look up one function and see who calls it
repolens lens --lookup authenticate_user

# Find similar functions by behavior
repolens lens similar --query "check authorization"
```

### Impact Tracing
```bash
# Build the impact graph
repolens impact scan

# Find everything that depends on models/user.py
repolens impact query models/user.py

# Health check the graph
repolens impact doctor
```

### Documentation
```bash
# Show coverage by file
repolens docs coverage

# Show all undocumented public symbols in a path
repolens docs coverage --missing src/api

# Generate strict HTML docs (fail if coverage < 100%)
repolens docs build --strict
```

### Full Report
```bash
# Quick report (default tools)
repolens report

# Include slow tools (impact, external scanners)
repolens report --with impact,semgrep

# Fail CI on any new P1 or P0 findings
repolens report --check --fail-on P1

# Accept current findings as baseline
repolens report --update-baseline
```

## 📊 Report Outputs

The `repolens report` command generates three files in `.repolens/report/`:
- **report.md** — Human-readable Markdown with findings by category
- **report.json** — Structured JSON for programmatic consumption
- **report.sarif** — SARIF format for GitHub Code Scanning integration

Each finding includes:
- Tool name
- Category (security, performance, documentation, etc.)
- Severity, confidence, and exposure
- File, line, and column
- Message and remediation guidance

## 🎓 Use Cases

### 1. **Maintain Feature Traceability**
Use FeatureTrace markers to document how features flow through your codebase, then generate visual maps for architecture reviews and onboarding.

### 2. **Reduce Code Duplication**
Use `lens similar` to find existing implementations before writing new code, ensuring consistent patterns across the codebase.

### 3. **Understand Function Impact**
Run `lens --lookup` to see all callers, callees, related tests, and owning capability of a function before refactoring.

### 4. **Predict Change Impact**
Use the impact tracer to understand what breaks when you change a file—ideal for review and testing strategy.

### 5. **Enforce Ownership**
Use the capability index to ensure each concept has a clear owner and to prevent architectural drift.

### 6. **Maintain Documentation Quality**
Use `docs coverage --check` as a ratchet in CI to prevent undocumented APIs from being committed.

### 7. **Catch Security Issues Early**
Run `report --check` in CI to fail on new BOLA/IDOR candidates and other security findings.

### 8. **Manage Generated Files**
Use artefacts hooks to ensure generated files are always up-to-date, reducing merge conflicts.

## 🔗 Integration

### GitHub Actions
```yaml
name: repolens
on: [push, pull_request]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      - run: pip install repolens
      - run: repolens report --check --fail-on P1
```

See `action.yml` for a pre-built GitHub Action.

## 📝 License

MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 StrataOS contributors.

## 🤝 Contributing

Contributions welcome! Please ensure:
1. All tests pass: `pytest tests/`
2. Code is documented: `repolens docs coverage --check`
3. No new findings: `repolens report --check`

## 📖 Further Reading

- **[Installation Guide](docs/installation.md)** — Set up in new repositories
- **[Impact Tracer Docs](docs/impact.md)** — Deep dive into change-impact analysis
- **[Roadmap](docs/roadmap.md)** — Known issues and future work
- **[Rules Documents](repolens/rules/)** — Portable, repository-agnostic guidance

<!--
Historical document, restored verbatim except that identifiers of the repository the
toolkit was extracted from are generalised. Do not otherwise edit the body below this comment.

Source: docs/installation.md as it stood from the initial 0.2.0 commit f73033c through d255c02
(unchanged in between), and the text downstream tickets cite from the vendored copy's
`docs/installation.md`. It was replaced by the 0.3.0 rewrite
in eb015d3 ("docs: publish audited scope roadmap and API client contracts").
Relative links inside it point at the 0.2 layout and may no longer resolve.
-->

# Installing repolens

How to put repolens into a repository, keep its gates honest, and take it out again. The
last section is the procedure for moving repolens into a repository of its own.

- [Requirements](#requirements)
- [Install](#install)
- [Set up a repository: `repolens init`](#set-up-a-repository-repolens-init)
- [Baselines](#baselines)
- [CI](#ci)
- [Merge hooks for generated artefacts](#merge-hooks-for-generated-artefacts)
- [Day to day](#day-to-day)
- [Upgrading](#upgrading)
- [Removing it](#removing-it)
- [Troubleshooting](#troubleshooting)
- [Making it a separate repository](#making-it-a-separate-repository)

## Requirements

| need | for | notes |
|---|---|---|
| Python 3.11+ | everything | the config reader is `tomllib`, in the standard library from 3.11 |
| git | artefacts, hooks, the FeatureTrace path check, lens churn | every git call is a list argv, never a shell |
| PyYAML (`repolens[yaml]`) | `owners`, and the lens's owner column | the capability index is YAML. Without it, `owners` exits with `PyYAML is not installed: pip install PyYAML (or pip install 'repolens[yaml]')` |
| pdoc (`repolens[docs]`) | `docs build`, Python half | pdoc **imports** the modules it documents, so their own dependencies must be installed where the docs are built |
| Node and `npx` | `docs build`, TypeScript half | TypeDoc is fetched at a pinned version on first use |
| ruff, bandit | `report` | pinned, see [Baselines](#baselines). Missing ones are reported as SKIPPED, never as zero findings |
| semgrep, impact | `report --with semgrep,impact` | slow or networked, so not default |

`repolens report --list-tools` prints every tool and whether it runs by default.

The package itself has **no required dependencies**. Everything above is optional, and
each command says which one it is missing.

## Install

Pick one. All of them give the same `repolens` command.

**From a checkout, with no install.** Used by the repository repolens came from:

```bash
python3 tools/repolens/bin/repolens <command>
```

The launcher puts its own checkout first on `sys.path`, so an older installed repolens
cannot shadow it.

**Editable, from a checkout:**

```bash
python -m pip install -e 'tools/repolens[yaml,docs]'
repolens <command>
```

**From git, pinned to a commit**, before a release exists:

```bash
python -m pip install 'repolens[yaml,docs] @ git+https://github.com/<org>/<repo>@<commit-sha>#subdirectory=tools/repolens'
```

Pin a commit SHA, never a branch. A branch moves, and the baselines are only comparable
with the version that made them.

**From PyPI**, once published ([GAP-TOOL-006](#making-it-a-separate-repository)):

```bash
python -m pip install 'repolens[yaml,docs]==X.Y.Z'
```

Do not vendor a copy into another repository. A copy drifts, and nothing tells you.

## Set up a repository: `repolens init`

```bash
repolens init --dry-run                                # print the plan, write nothing
repolens init --ci github --agents-file AGENTS.md      # write it
```

`init` walks the tree and writes:

| file | what |
|---|---|
| `repolens.toml` | the profile, built from what it found: Python and TS/JS roots, the tests directory, a tsconfig, importable packages, migrations directories, C# projects |
| `docs/repolens/*.md` | the portable rules (`--rules-dir` to move them, `--no-rules` to skip) |
| an empty capability index | the YAML registry `owners` reads. Skipped with `--no-rules`, like the rules |
| `.gitignore` lines | the build output only. The baselines under `.repolens/` must stay committable |
| `.github/workflows/repolens.yml` | with `--ci github`, which then needs `--install-spec`: repolens is not published to PyPI, so name the source pinned (a git URL at a commit, or a wheel you host). There is no default, because a bare `repolens` would install whatever holds that name on PyPI |
| a rules block in the agents file | with `--agents-file`, only between its `repolens:rules` markers |

It never overwrites a file without `--force`, and a second run changes nothing.

**Read the profile before committing it.** Detection is a starting point. The parts that
need a person:
- `[featuretrace.audit] scope_values`. A multi-tenant codebase lists its scope
  qualifiers here, and every marker must then state one.
- `[lens] guard_calls`: the calls that establish a trust boundary.
- `[scan.security.public_routes]`: each route that is public by design, with the reason.
  A reason names what authorises the request instead of a session.
- `[scan.migrations]`: written only if a migrations directory was found. Name the live
  history explicitly, so a stale copy elsewhere is never read as it.
- `[[report.commands]]`: the repository's own checks. Confirm each one can exit non-zero
  before relying on it.

## Baselines

Two files make `--check` meaningful. Commit both:

| file | ratchet |
|---|---|
| `.repolens/report_baseline.json` | how many of each finding fingerprint are known, and the size of each count-type finding |
| `.repolens/docstring_baseline.json` | undocumented public symbols per file |

A `--check` with no baseline has nothing to compare against. It either refuses or passes
by construction, so a missing baseline is never a clean result.

**Build them with pinned scanners, in a clean tree.** A newer ruff or bandit adds rules,
and their findings would read as new. A local virtualenv or `node_modules` inside the
tree adds files the CI checkout does not have. So:

```bash
git worktree add --detach ../rl-baseline HEAD      # a tree with no venv, no node_modules
cd ../rl-baseline
python -m venv /tmp/rl && /tmp/rl/bin/pip install -r tools/repolens/requirements-ci.txt
/tmp/rl/bin/python tools/repolens/bin/repolens report --update-baseline
/tmp/rl/bin/python tools/repolens/bin/repolens report --check --require ruff,bandit   # must pass
/tmp/rl/bin/python tools/repolens/bin/repolens docs coverage --update-baseline
```

Copy the two files back and commit them. **Never rebuild a baseline in CI.** A CI job
that accepts today's findings can only pass.

**Merging a baseline is not a text merge.** Both files are ratchets. On a conflict, take
the **lower** count for each key, then re-run `--check`.

## CI

Every gate carries `if: ${{ !cancelled() }}`, so one push shows every failure, not only
the first. The workflow `init --ci github` writes runs three gates:

1. `repolens report --check --require ruff,bandit`;
2. `repolens docs coverage --check`;
3. `repolens docs build`, **without** `--strict`. A new repository may not have Node, or
   the dependencies of the modules it documents, so a half that cannot build is reported
   as skipped instead of failing. Add `--strict` once both halves build.

The workflow in the repository repolens came from (`.github/workflows/repolens.yml`) runs
four gates. It adds the package's own unit tests, because repolens is checked out there,
and it builds the docs with `--strict`.

What fails it:
- a NEW finding at medium or high confidence, at `[report] fail_on` or worse (P1 by
  default);
- a tool that crashed (ERROR);
- a `--require`d tool that did not run;
- a file that gained an undocumented public symbol;
- a code reference that does not build: with `--strict`, a skipped half too.

Low-confidence findings never fail it. They are leads, and a gate that fails on guesses
gets deleted.

**SARIF.** The report writes `report.sarif`. Upload it to code scanning only where code
scanning is available: on a private GitHub repository that needs Advanced Security.
Otherwise upload it as an artefact, and put `report.md` in the job summary.

**Never run repolens under `pull_request_target` on a fork's checkout.**
`[[report.commands]]` are argv from the profile, and a fork's pull request controls the
profile. Use `pull_request`, which is the only trigger the `init` template writes.

## Merge hooks for generated artefacts

A committed generated file is derived from the tree. A three-way text merge of one is
always wrong: the right result is what the generator produces from the merged tree. So,
once per clone:

```bash
repolens artefacts install-hooks
```

This does two things:
- It registers a merge driver, `generated` by default, with
  `git config merge.generated.name` and `merge.generated.driver`. The driver keeps one
  side and raises no conflict.
- It writes `post-merge` and `post-rewrite` hooks into the directory
  `git rev-parse --git-path hooks` names. The hooks regenerate the artefacts from the
  completed tree.

`.gitattributes` names the files (`path merge=generated`), and `[[artefacts.rules]]` in
`repolens.toml` names how to regenerate each. `repolens artefacts verify` fails when the
two lists disagree.

Git config and hooks are not versioned, so each clone runs the installer. A clone that
does not falls back to an ordinary conflict, which is the safe way to fail. A merge made
by a hosting service's merge button runs no hooks; there, the CI `--check` of each
generator is the only protection.

## Day to day

```bash
repolens lens --lookup <function>          # before editing a function you did not write
repolens lens similar --like "..."         # before writing a helper: does it exist already?
repolens owners --impact <concept|path>    # what moves with this concept
repolens report --only migrations          # a migration, before it merges
repolens report                            # everything; writes .repolens/report/
repolens artefacts regenerate --all        # after a merge the hooks did not see
```

## Upgrading

1. Bump the pin: `--install-spec`, the requirements file, or the git SHA.
2. Look for a new rule or a scanner pin change since your pin. Either adds findings that
   are not regressions. There is no changelog yet; GAP-TOOL-006 adds one. Until then,
   read `git log` for `tools/repolens/` between the two pins, and `docs/roadmap.md`.
3. Rebuild the baselines as in [Baselines](#baselines), in the **same** pull request as
   the bump, and say why in its description.

A baseline written before count sizes were recorded still loads. The report then treats a
count-type finding as it did before: a new number reads as new. Rebuild it once to get
the count-aware comparison, where only a count that rose is new.

## Removing it

```bash
python -m pip uninstall repolens
git config --unset merge.generated.name
git config --unset merge.generated.driver
```

Then:
- Delete the `post-merge` and `post-rewrite` hooks, after reading them. They may hold
  other lines if something else also installs hooks there.
- Delete the `merge=generated` lines from `.gitattributes`.
- Delete the workflow, `repolens.toml` and `.repolens/`.
- Delete the rules block between the markers in the agents file.

## Troubleshooting

| symptom | cause | fix |
|---|---|---|
| `owners` exits: `PyYAML is not installed: pip install PyYAML (or pip install 'repolens[yaml]')` | PyYAML is not installed | install either |
| a tool shows SKIPPED | it is not installed, or its inputs do not exist (for example no `[scan] python_roots` on disk) | install it, or fix the path. Add it to `--require` if a skip must fail CI |
| a tool shows ERROR | it crashed, or exited with a code that is neither clean nor "found something" | run it by hand. `--check` fails on an ERROR by design |
| `--check` exits 2 about the baseline | the baseline is not valid JSON | restore it from git. An unreadable baseline is never read as empty |
| `--check` fails right after an upgrade | the new version or scanner reports more | re-baseline in the upgrade's pull request |
| `lens` prints "the cached index is older than the tree; rebuilding it." | a file changed since the index was built | nothing: the answer comes from the current tree |
| `docs build --strict` fails on an import | pdoc imports each documented module | install that module's dependencies where the docs are built, or narrow `[docs.python] modules` |
| a FeatureTrace path reads as missing for a file that exists | the path check asks git | `git add` the file first |
| `repolens: skipped <path>: <reason>` on stderr | a file could not be read, usually because it was deleted mid-run | nothing: the file is skipped and named |

## Making it a separate repository

### What is already true

- Every repository fact is in `repolens.toml`. The package imports nothing from the
  repository it lives in.
- A grep of the package for that repository's vocabulary finds three kinds of hit:
  - comments that cite an incident there as the reason for a rule, in `impact/query.py`
    and `impact/scanner.py`;
  - one SQL remedy that names that repository's RLS session-variable idiom, which
    should become generic advice;
  - that repository's tenant key in the default list of identity parameters.
- The coupling that matters is to frameworks. The security and performance scans
  understand FastAPI, MongoDB (Motor) and PostgreSQL (asyncpg, SQLAlchemy, Alembic).
  A Flask, Django, Express or Next.js codebase gets FeatureTrace, the lens, owners,
  gates, artefacts, docs and the migrations checks, and **no** route-security findings.

### Decisions only the owner can make

Creating a repository and publishing a package are outward-facing. Until each of these
has an answer, none of the steps below should run:

1. the organisation and repository name;
2. public or private;
3. the license. `pyproject.toml` says MIT, which nobody has decided;
4. whether to publish to PyPI, and under what name. Check that `repolens` is free.

### 1. Split it out, keeping history

```bash
git clone --no-local <this-repository> repolens-split && cd repolens-split
git filter-repo --path tools/repolens/ --path-rename tools/repolens/:
```

The package, `tests/`, `docs/`, the rules, the templates and `bin/` move together. The
new root holds `pyproject.toml`, `README.md`, `repolens/`, `tests/`, `docs/`, `bin/`.

### 2. `pyproject.toml`

- Keep `dependencies = []` and the `yaml`/`docs` extras.
- Single-source the version. It is written in two places today, `pyproject.toml` and
  `repolens/__init__.py`, and they must not drift:
  ```toml
  [project]
  dynamic = ["version"]

  [tool.setuptools.dynamic]
  version = { attr = "repolens.__version__" }
  ```
- Add `[project.urls]` (source, issues, changelog) and classifiers (Python 3.11–3.13,
  OS independent once the Windows run is green).
- Keep `[tool.setuptools.package-data]`: `init` and `rules` read the templates and rules
  documents from the installed wheel.
- `action.yml` at the root today runs only the impact tracer. Move it to
  `impact/action.yml`, and make the root action the report (step 4).

### 3. Publish with trusted publishing

No API token is stored. PyPI trusts this repository's workflow through OIDC; configure
the publisher on PyPI first.

```yaml
# .github/workflows/release.yml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with: { python-version: "3.12" }
      - run: python -m pip install build && python -m build
      - uses: actions/upload-artifact@v7
        with: { name: dist, path: dist/ }
  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: pypi            # a protected environment: releases need an approval
    permissions:
      id-token: write            # the OIDC token; nothing else
    steps:
      - uses: actions/download-artifact@v7
        with: { name: dist, path: dist/ }
      - uses: pypa/gh-action-pypi-publish@release/v1
```

This is a template for the new repository, not a file that exists. `checkout`,
`setup-python` and `upload-artifact` at `@v7` are what this repository's own workflows
use. `download-artifact` and `pypa/gh-action-pypi-publish` are used nowhere here yet, so
check their current versions before copying this.

Release rules:
- Semantic versions, with a CHANGELOG entry per release.
- A new rule, or a scanner pin change, is a minor release whose note says
  **re-baseline**.
- Pin the scanners the release was tested with in the release notes, so users can pin
  the same.

### 4. The GitHub Action

```yaml
# action.yml
name: repolens
description: The repolens findings report and docstring ratchet, gated on the pull request.
inputs:
  version:   { description: "repolens version to install (pin it)", required: true }
  scanners:  { description: "requirements file pinning ruff/bandit/pdoc", required: false, default: "" }
  require:   { description: "tools that must run", required: false, default: "ruff,bandit" }
runs:
  using: composite
  steps:
    - shell: bash
      env:
        REPOLENS_VERSION: ${{ inputs.version }}
        REPOLENS_SCANNERS: ${{ inputs.scanners }}
      run: |
        python -m pip install "repolens[yaml,docs]==${REPOLENS_VERSION}"
        if [ -n "$REPOLENS_SCANNERS" ]; then python -m pip install -r "$REPOLENS_SCANNERS"; fi
    - shell: bash
      env:
        REPOLENS_REQUIRE: ${{ inputs.require }}
      run: repolens report --check --require "$REPOLENS_REQUIRE"
    - shell: bash
      if: ${{ !cancelled() }}
      run: repolens docs coverage --check
    - shell: bash
      if: ${{ always() }}
      run: |
        if [ -f .repolens/report/report.md ]; then
          head -c 900000 .repolens/report/report.md >> "$GITHUB_STEP_SUMMARY"
        fi
```

Inputs reach the shell through `env:`, never as `${{ }}` inside `run:`. Interpolating an
input into a script is how a workflow gets injected.

Once the action exists, `repolens init --ci github` can write a short job that uses it.
Today it writes the full job from `templates/github-workflow.yml`.

### 5. The package's own CI matrix

```yaml
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python: ["3.11", "3.12", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with: { python-version: "${{ matrix.python }}" }
      - run: python -m pip install -e ".[yaml,docs]"
      - run: python -m unittest discover -s tests
```

**Windows has never been run.** Paths are POSIX where they are compared (`rel()`,
FeatureTrace's `rel_path`), and the hooks are written with LF endings. Both are tested on
Linux only. Do not claim Windows support until this matrix is green.

### 6. Plugin entry points (proposed)

So that a framework adapter or a house detector is a package, not a fork:

```toml
# in the plugin's pyproject.toml
[project.entry-points."repolens.frameworks"]
flask = "repolens_flask:adapter"

[project.entry-points."repolens.detectors"]
house-rules = "acme_repolens:detectors"
```

```python
from importlib.metadata import entry_points
adapters = {ep.name: ep.load() for ep in entry_points(group="repolens.frameworks")}
```

An adapter yields routes, their auth and their object-id parameters; the existing BOLA
and unauthenticated-mutation rules consume it unchanged. This is not built yet
(GAP-TOOL-008).

### 7. What stays in the original repository

- `repolens.toml` and `.repolens/*_baseline.json`.
- The workflow. It changes from `python tools/repolens/bin/repolens` to a pinned
  `pip install repolens==X.Y.Z`, or to the action.
- The repository's own script shims. CI, deploy preflight, the git hooks and the tests
  call them by name.
- The repository's test suites that assert its policy, not the package's (validation gate
  reachability, generated-artefact merges, canonical owners, the FeatureTrace ratchet).
  They keep running against the installed version.
- Then delete `tools/repolens/`, in the same pull request that switches the workflow.

### 8. Hardening checklist before it runs in anyone else's CI

In another repository, a pull request can change the profile, the baselines and the
source tree. Each item below is tracked in GAP-TOOL-007.

- [ ] Every configured path (a baseline, `out_dir`, `map_dir`, the docs output) resolves
      inside the repository root, symlinks included, or repolens refuses.
- [ ] `[artefacts] hook_command` reaches a shell. `artefacts install-hooks` writes it
      verbatim into the bash `post-merge` and `post-rewrite` hooks, and quotes only the
      interpreter it puts in for `{python}`. Parse it as an argv and quote every token.
      Then add a test that feeds `$(...)`, backticks and `;` through it and through
      `[[report.commands]]`, and asserts they stay literal. Every other subprocess the
      package starts already takes a list argv, with no `shell=True`.
- [ ] Finding text is escaped in `report.md` and the job summary. It carries source
      snippets. SARIF `message.text` stays plain text.
- [ ] TypeDoc comes from the host project's lockfile when present. `npx --yes typedoc@X`
      downloads code at run time.
- [ ] A test that the workflow `init --ci github` writes triggers on `pull_request`, never
      `pull_request_target`. The template does that today, but nothing tests it.

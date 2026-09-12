"""`repolens init`: set repolens up in a repository that has never used it.

    repolens init                          write whatever is missing; never overwrite
    repolens init --dry-run                print the plan and write nothing
    repolens init --ci github              also write .github/workflows/repolens.yml
    repolens init --agents-file AGENTS.md  add (or refresh) the rules block in an agent
                                           instructions file (CLAUDE.md, AGENTS.md, ...)
    repolens init --force                  overwrite the files init owns

What it writes:

  repolens.toml                  a profile built from what the tree contains: which top-level
                                 directories hold Python, which hold TypeScript/JavaScript
                                 (preferring `<dir>/src`), the tests directory, a tsconfig,
                                 and importable packages for pdoc
  <rules-dir>/*.md               the portable rules documents (default docs/repolens/)
  <rules-dir>/canonical_owners.yaml   an empty capability index, with the entry format
  .gitignore                     the build output under .repolens/ (baselines stay committed)
  the agents file, --ci          only when asked

Detection is a starting point, not a verdict: read the profile before committing it. An
existing file is never overwritten without --force, and the agents file is only ever
edited between its `repolens:rules` markers.

C# is detected and reported, not analysed: repolens has no C# parser yet. The profile
then carries commented `[[report.commands]]` for the .NET toolchain's own analysers, which
the report can run today.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from . import rules
from .config import CONFIG_NAME, Config
from .core.files import SkipRule

#: Scanner versions the generated CI workflow pins. A baseline is only comparable with
#: the scanner versions that produced it.
SCANNER_PINS = {"ruff": "0.16.7", "bandit": "1.9.4", "pdoc": "16.0.0"}

GITIGNORE_LINES = (
    "# repolens build output. Baselines and the digests in .repolens/ ARE committed.",
    ".repolens/report/",
    ".repolens/docs/",
    ".repolens/function_lens.json",
    ".impact-tracer/",
)

_SKIP = [".git", "node_modules", "venv", ".venv", "env", "__pycache__", "site-packages", "dist",
         "build", "coverage", ".next", ".nuxt", ".tox", ".mypy_cache", ".pytest_cache", "bin",
         "obj", "vendor", "third_party", "packages/.cache"]
_LANGUAGE = {".py": "python", ".ts": "javascript", ".tsx": "javascript", ".js": "javascript",
             ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".cs": "csharp"}
_TEST_DIRS = ("tests", "test", "__tests__", "spec", "specs")
_MIGRATION_DIRS = (("alembic", "versions"), ("migrations", "versions"))
_NOT_SOURCE = frozenset({*_TEST_DIRS, "docs", "doc", "examples", "example", "public", "static",
                         "assets", "fixtures"})
MAX_FILES = 200_000
_BLOCK = re.compile(r"<!-- repolens:rules:start -->.*?<!-- repolens:rules:end -->\n?", re.S)


@dataclass
class Detected:
    """What the tree contains, as far as a walk of file names can tell."""
    counts: Counter = field(default_factory=Counter)
    python_roots: list[str] = field(default_factory=list)
    javascript_roots: list[str] = field(default_factory=list)
    tests_dir: str = "tests"
    tsconfig: str = ""
    ts_entry_points: list[str] = field(default_factory=list)
    pdoc_modules: list[str] = field(default_factory=list)
    pdoc_path: list[str] = field(default_factory=list)
    csharp_projects: list[str] = field(default_factory=list)
    migration_roots: list[str] = field(default_factory=list)
    truncated: bool = False

    def summary(self) -> str:
        parts = [f"{n} {lang}" for lang, n in sorted(self.counts.items())] or ["no source files"]
        if self.migration_roots:
            parts.append(f"migrations in {', '.join(self.migration_roots)}")
        return ", ".join(parts) + (" (walk truncated)" if self.truncated else "")


def detect(root: Path) -> Detected:
    """Walk the tree once and derive a starting profile from what it holds."""
    found = Detected()
    skip = SkipRule(_SKIP)
    per_top: dict[str, Counter] = defaultdict(Counter)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        # A migrations directory inside a test tree is a fixture, often a broken one on
        # purpose; configuring it as a root would report its planted defects.
        if (tuple(rel_dir.parts[-2:]) in _MIGRATION_DIRS
                and not set(rel_dir.parts) & {*_TEST_DIRS, "fixtures", "testdata"}):
            found.migration_roots.append(rel_dir.as_posix())
        dirnames[:] = sorted(d for d in dirnames
                             if not d.startswith(".") and not skip.matches((*rel_dir.parts, d)))
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_FILES:
                found.truncated = True
                break
            if name.endswith(".csproj"):
                found.csharp_projects.append((rel_dir / name).as_posix())
            language = _LANGUAGE.get(Path(name).suffix.lower())
            if language is None or name.endswith(".d.ts"):
                continue
            found.counts[language] += 1
            per_top[rel_dir.parts[0] if rel_dir.parts else "."][language] += 1
        if found.truncated:
            break

    def roots_for(language: str) -> list[str]:
        tops = sorted(t for t, c in per_top.items() if c[language] and t != "." and t not in _NOT_SOURCE)
        if not tops and per_top["."][language]:
            return ["."]
        return tops

    found.python_roots = roots_for("python")
    found.javascript_roots = [f"{t}/src" if t != "." and (root / t / "src").is_dir() else t
                              for t in roots_for("javascript")]
    found.tests_dir = next((d for d in _TEST_DIRS if (root / d).is_dir()), "tests")

    for js_root in found.javascript_roots:
        base = Path(js_root).parent if js_root.endswith("/src") else Path(js_root)
        tsconfig = root / base / "tsconfig.json"
        if tsconfig.is_file():
            found.tsconfig = tsconfig.relative_to(root).as_posix()
            lib = root / js_root / "lib"
            found.ts_entry_points = [(lib if lib.is_dir() else root / js_root).relative_to(root).as_posix()]
            break

    for py_root in found.python_roots:
        base = root / py_root
        if (base / "__init__.py").is_file() and py_root != ".":
            found.pdoc_modules.append(Path(py_root).name)
            parent = Path(py_root).parent.as_posix()
            if parent not in found.pdoc_path:
                found.pdoc_path.append(parent)
            continue
        packages = sorted(p.name for p in base.iterdir()
                          if p.is_dir() and (p / "__init__.py").is_file() and p.name not in _NOT_SOURCE)
        if packages:
            found.pdoc_modules.extend(packages[:5])
            if py_root not in found.pdoc_path:
                found.pdoc_path.append(py_root)
    found.pdoc_modules = found.pdoc_modules[:8]
    return found


def _template(name: str) -> str:
    return (resources.files(__package__) / "templates" / name).read_text(encoding="utf-8")


def _fill(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace(f"@@{key}@@", value)
    return text


def _csharp_block(d: Detected) -> str:
    if not (d.counts["csharp"] or d.csharp_projects):
        return ""
    target = next(iter(d.csharp_projects), "<solution.sln>")
    return (
        f"\n# C# detected ({d.counts['csharp']} .cs files, {len(d.csharp_projects)} projects). repolens\n"
        "# does not parse C# yet, so nothing above covers it. The report can run the .NET\n"
        "# toolchain's own analysers as commands; confirm each one exits non-zero on a\n"
        "# finding first (`dotnet list package --vulnerable` has historically exited 0 either way).\n"
        "# [[report.commands]]\n"
        '# name = "dotnet-format"\n'
        f'# run = ["dotnet", "format", "{target}", "--verify-no-changes"]\n'
        '# category = "hygiene"\n'
        "# [[report.commands]]\n"
        '# name = "dotnet-build-analyzers"\n'
        f'# run = ["dotnet", "build", "{target}", "-warnaserror", "-p:EnableNETAnalyzers=true", "-p:AnalysisLevel=latest"]\n'
        '# severity = "medium"\n'
        '# category = "correctness"\n'
    )


def _migrations_block(d: Detected) -> str:
    if not d.migration_roots:
        return ""
    return (
        "\n# Database migrations, checked before they run: revision width, NOT NULL without a\n"
        "# default, row-level security with no FORCE, views without security_invoker, and\n"
        "# CREATE INDEX without CONCURRENTLY on a table the migration did not create.\n"
        "[scan.migrations]\n"
        f"roots = {json.dumps(d.migration_roots)}\n"
        "# revision_max_length = 32   # the version table's column width\n"
        "# require_rls = true         # every table created in rls_schemas must be row-secured\n"
        "# rls_schemas = []\n"
    )


def profile_text(root: Path, d: Detected, registry: str) -> str:
    """The repolens.toml init writes for this tree."""
    as_list = json.dumps  # a JSON array of strings is a valid TOML array
    return _fill(_template("repolens.toml"), {
        "NAME": root.name,
        "DETECTED": d.summary(),
        "SCAN_DIRS": as_list(sorted({*d.python_roots, *d.javascript_roots, d.tests_dir}
                                    - {""}) or ["."]),
        "PYTHON_ROOTS": as_list(d.python_roots),
        "JS_ROOTS": as_list(d.javascript_roots),
        "TESTS_DIR": d.tests_dir,
        "REGISTRY": registry,
        "PDOC_MODULES": as_list(d.pdoc_modules),
        "PDOC_PATH": as_list(d.pdoc_path),
        "TS_ENTRY": as_list(d.ts_entry_points),
        "TSCONFIG": d.tsconfig,
        "CSHARP": _csharp_block(d),
        "MIGRATIONS": _migrations_block(d),
    })


def _default_branch(root: Path) -> str:
    out = subprocess.run(["git", "-C", str(root), "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
                         capture_output=True, text=True)
    return out.stdout.strip().split("/", 1)[-1] if out.returncode == 0 and out.stdout.strip() else "main"


@dataclass
class Action:
    """One file init would touch, and what it would do to it."""
    path: Path
    verb: str          # write | skip | append | update | unchanged
    content: str = ""
    note: str = ""


def plan(root: Path, args: argparse.Namespace) -> tuple[list[Action], Detected]:
    d = detect(root)
    rules_dir = args.rules_dir.strip("/")
    registry = f"{rules_dir}/canonical_owners.yaml"
    wanted: list[tuple[Path, str]] = [(root / CONFIG_NAME, profile_text(root, d, registry))]
    if not args.no_rules:
        for name, body in rules.documents().items():
            wanted.append((root / rules_dir / name, body))
        wanted.append((root / registry, _fill(_template("canonical_owners.yaml"), {"RULES_DIR": rules_dir})))
    if args.ci == "github":
        pins = " ".join(f'"{tool}=={version}"' for tool, version in SCANNER_PINS.items())
        wanted.append((root / ".github" / "workflows" / "repolens.yml", _fill(
            _template("github-workflow.yml"),
            {"DEFAULT_BRANCH": _default_branch(root), "INSTALL_SPEC": args.install_spec,
             "SCANNER_PINS": pins})))

    actions: list[Action] = []
    for path, content in wanted:
        if not path.exists():
            actions.append(Action(path, "write", content))
        elif args.force and path.read_text(encoding="utf-8", errors="replace") != content:
            actions.append(Action(path, "write", content, "overwriting (--force)"))
        else:
            actions.append(Action(path, "skip", note="exists; --force to overwrite"))

    gitignore = root / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8").splitlines() if gitignore.is_file() else []
    missing = [ln for ln in GITIGNORE_LINES if ln.startswith("#") is False and ln not in existing]
    if missing:
        block = [GITIGNORE_LINES[0], *missing]
        actions.append(Action(gitignore, "append", "\n".join(block) + "\n", f"+{len(missing)} lines"))
    else:
        actions.append(Action(gitignore, "unchanged"))

    if args.agents_file:
        agents = root / args.agents_file
        block = _fill(_template("agents-block.md"), {"RULES_DIR": rules_dir})
        current = agents.read_text(encoding="utf-8") if agents.is_file() else ""
        if _BLOCK.search(current):
            updated = _BLOCK.sub(lambda _: block, current, count=1)
            actions.append(Action(agents, "unchanged" if updated == current else "update", updated,
                                  "rules block between its markers"))
        else:
            sep = "" if not current or current.endswith("\n\n") else ("\n" if current.endswith("\n") else "\n\n")
            actions.append(Action(agents, "update" if current else "write", current + sep + block,
                                  "rules block appended"))
    return actions, d


def apply(actions: list[Action]) -> None:
    for action in actions:
        if action.verb in ("write", "update"):
            action.path.parent.mkdir(parents=True, exist_ok=True)
            action.path.write_text(action.content, encoding="utf-8", newline="\n")
        elif action.verb == "append":
            current = action.path.read_text(encoding="utf-8") if action.path.is_file() else ""
            sep = "" if not current or current.endswith("\n") else "\n"
            action.path.write_text(current + sep + ("\n" if current else "") + action.content,
                                   encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None, *, config: Config | None = None, prog: str | None = None) -> int:
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="print the plan; write nothing")
    ap.add_argument("--force", action="store_true", help="overwrite files init owns")
    ap.add_argument("--rules-dir", default="docs/repolens", help="where the rules documents go")
    ap.add_argument("--no-rules", action="store_true", help="do not copy the rules documents")
    ap.add_argument("--agents-file", help="agent instructions file to carry the rules block")
    ap.add_argument("--ci", choices=["github"], help="also write a CI workflow")
    ap.add_argument("--install-spec",
                    help="what the CI workflow pip-installs; required with --ci github. A git URL "
                         "pinned to a commit, e.g. 'repolens[yaml,docs] @ "
                         "git+https://github.com/<org>/<repo>@<sha>#subdirectory=tools/repolens'")
    args = ap.parse_args(argv)
    if args.ci == "github" and not args.install_spec:
        # A bare `repolens` resolves on PyPI, where this project does not publish: CI would
        # install whatever package holds that name there, if any, with the repo's token.
        ap.error("--ci github needs --install-spec: repolens is not published to PyPI, so "
                 "name the source, pinned (a git URL at a commit, or a wheel you host)")

    root = (config.root if config is not None else Path.cwd()).resolve()
    actions, detected = plan(root, args)
    print(f"repolens init: {root}")
    print(f"  detected: {detected.summary()}")
    print(f"  python roots: {detected.python_roots or 'none'}   "
          f"javascript roots: {detected.javascript_roots or 'none'}")
    if detected.counts["csharp"] or detected.csharp_projects:
        print("  C#: detected but not analysed (no C# parser yet); see the commented "
              "[[report.commands]] in repolens.toml")
    print()
    for action in actions:
        rel = action.path.relative_to(root).as_posix()
        verb = f"would {action.verb}" if args.dry_run and action.verb not in ("skip", "unchanged") else action.verb
        print(f"  {verb:<14} {rel}" + (f"  ({action.note})" if action.note else ""))
    if args.dry_run:
        return 0
    apply(actions)
    print("\nNext:")
    print(f"  1. Read {CONFIG_NAME}: detection is a starting point, not a verdict.")
    print("  2. Accept today's state, then commit the baselines it writes under .repolens/:")
    print("       repolens report --update-baseline")
    print("       repolens docs coverage --update-baseline")
    print("       repolens featuretrace audit --update-baseline")
    print("  3. Committing generated artefacts? Configure [artefacts] and run "
          "`repolens artefacts install-hooks` once per clone.")
    return 0

"""Which build of repolens produced an output.

The version string cannot tell two working trees apart. A field evaluation compared an
`impact doctor` run and an `analyze` run that disagreed only because the tool's code had
changed between them. Outputs carry this stamp so a result can be matched to the code,
optional extras and configuration that wrote it.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import shutil
import subprocess
from functools import lru_cache
from importlib import metadata as package_metadata
from pathlib import Path

from . import __version__
from .core.git import git_env, is_modified, run_git  # noqa: F401 - git_env is re-exported

_PACKAGE = Path(__file__).resolve().parent
#: Optional imports that change results: module name -> distribution name.
_EXTRAS = {"tree_sitter": "tree-sitter", "sqlglot": "sqlglot", "fastapi": "fastapi", "pdoc": "pdoc"}
#: What the package ships; an editor's swap file or a stray local file must not change the hash.
_SOURCE_SUFFIXES = frozenset({".py", ".md", ".toml", ".json", ".yml", ".yaml", ".txt", ".cfg", ".ini", ".html",
                              ".css", ".js", ".sh", ".j2", ".tmpl", ".typed"})


def _source_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted(_PACKAGE.rglob("*")):
        if (not path.is_file() or "__pycache__" in path.parts or path.name.startswith(".")
                or path.suffix not in _SOURCE_SUFFIXES):
            continue
        digest.update(path.relative_to(_PACKAGE).as_posix().encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _git(*args: str) -> str | None:
    """Output of a git command in the checkout holding this package, or None."""
    checkout = _PACKAGE.parent
    if not (checkout / ".git").exists() or shutil.which("git") is None:
        return None
    try:
        return run_git(checkout, *args, check=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def tool_build() -> dict:
    """Version, git commit and dirty flag (None outside a checkout), a hash of the
    installed package sources, and the optional extras with their versions.

    Computed once per process and returned as a copy. Entry points call it at start-up,
    so a long-running server stamps the code it loaded, not a later checkout."""
    return copy.deepcopy(_tool_build())


@lru_cache(maxsize=1)
def _tool_build() -> dict:
    commit = _git("rev-parse", "HEAD") or None
    # Not `git status`: it runs clean filters. None when git cannot tell, never "clean".
    dirty = is_modified(_PACKAGE.parent, _PACKAGE.name) if commit else None
    extras: dict[str, str | None] = {}
    for module, distribution in _EXTRAS.items():
        if importlib.util.find_spec(module) is None:
            extras[distribution] = None
            continue
        try:
            extras[distribution] = package_metadata.version(distribution)
        except package_metadata.PackageNotFoundError:
            extras[distribution] = "installed"
    return {"version": __version__, "commit": commit, "dirty": dirty,
            "source_sha256": _source_sha256(), "extras": extras}


def describe_build(build: dict | None = None) -> str:
    """One line: `repolens 0.3.0 bc0a10a3f1e2+dirty source 7f095c20791e extras sqlglot,tree-sitter`."""
    build = build or tool_build()
    commit = (build.get("commit") or "")[:12] or "no-git"
    dirty = "+dirty" if build.get("dirty") else ""
    extras = ",".join(sorted(name for name, version in build.get("extras", {}).items() if version)) or "none"
    return f"repolens {build['version']} {commit}{dirty} source {build['source_sha256'][:12]} extras {extras}"

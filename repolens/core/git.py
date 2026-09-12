"""The committed tree as an oracle.

Existence is decided against what git tracks, never against the working tree. A check
that asks `Path.exists()` gives a different answer on a machine that has run a
generator (whose output is gitignored) than in CI, which never has — so it passes
locally and fails in CI on the identical commit. The committed tree is the same
everywhere, so it is the only oracle that gives one answer.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable


def tracked_paths(root: Path) -> frozenset[str]:
    """Every tracked path, repo-relative. Empty when git is unavailable."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, text=True, check=True, timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(p for p in out.split("\0") if p)


def ignored(root: Path, candidates: Iterable[str]) -> set[str]:
    """The subset of `candidates` that `.gitignore` excludes — one subprocess for all."""
    batch = tuple(candidates)
    if not batch:
        return set()
    try:
        # -z both ways: without it git C-quotes a path holding a non-ASCII character
        # (core.quotePath), and the quoted form matches nothing the caller passed in.
        proc = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-z", "--stdin"],
            input="\0".join(batch), capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    # exit 0 = some ignored, 1 = none ignored, >1 = error. 1 is not a failure here.
    if proc.returncode > 1:
        return set()
    return {p for p in proc.stdout.split("\0") if p}

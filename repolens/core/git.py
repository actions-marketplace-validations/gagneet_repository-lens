"""The committed tree as an oracle.

Existence is decided against what git tracks, never against the working tree. A check
that asks `Path.exists()` gives a different answer on a machine that has run a
generator (whose output is gitignored) than in CI, which never has — so it passes
locally and fails in CI on the identical commit. The committed tree is the same
everywhere, so it is the only oracle that gives one answer.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

#: Settings that let a repository's own config run a command during a read-only query.
#: `status` (clean/smudge filters, fsmonitor) is never used on a target: `diff-index` and
#: `diff-files` answer "is it modified" without running filters.
_SAFE_CONFIG = ("-c", "core.fsmonitor=", "-c", "core.untrackedCache=false")


def git_env() -> dict[str, str]:
    """The environment for running git on a directory we name with `-C`.

    Every inherited `GIT_*` variable is dropped: hooks, merge drivers and wrapper scripts
    set `GIT_DIR`/`GIT_INDEX_FILE`, which `-C` does not override and which would point git
    at a different repository."""
    return {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
            "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}


def run_git(root: Path | str, *args: str, input: str | bytes | None = None, check: bool = False,
            timeout: float = 120, text: bool = True, errors: str = "surrogateescape") -> subprocess.CompletedProcess:
    """git in `root` with config that could run a command overridden, a clean environment and
    a timeout. Raises OSError/SubprocessError like `subprocess.run`."""
    return subprocess.run(["git", *_SAFE_CONFIG, "-C", str(root), *args], input=input, capture_output=True,
                          text=text, check=check, timeout=timeout, env=git_env(),
                          **({"encoding": "utf-8", "errors": errors} if text else {}))


def is_modified(root: Path | str, *paths: str) -> bool | None:
    """Whether tracked files under `paths` differ from HEAD; None when git cannot tell.

    `git status` would run the repository's clean filters on every stat-changed file."""
    try:
        results = [run_git(root, "diff-index", "--quiet", "HEAD", "--", *paths, timeout=60),
                   run_git(root, "diff-files", "--quiet", "--", *paths, timeout=60)]
    except (OSError, subprocess.SubprocessError):
        return None
    if any(result.returncode not in (0, 1) for result in results):
        return None
    return any(result.returncode == 1 for result in results)


def tracked_paths(root: Path) -> frozenset[str]:
    """Every tracked path, repo-relative. Empty when git is unavailable."""
    try:
        out = run_git(root, "ls-files", "-z", check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(p for p in out.split("\0") if p)


def untracked_ignored(root: Path) -> tuple[frozenset[str], str]:
    """Untracked files and directories git ignores under `root`, relative to it, and why
    that list is unavailable ("" when it was read or `root` is not in a git checkout).

    A gitignored backup is not source. Tracked files are never listed. `root` may be a
    subdirectory of the checkout. Directories are listed once (`--directory`), so a caller
    tests a path and its parents. On any failure nothing is treated as ignored."""
    checkout = next((parent for parent in (root, *root.parents) if (parent / ".git").exists()), None)
    if checkout is None:
        return frozenset(), ""
    if shutil.which("git") is None:
        return frozenset(), "git is not installed"

    def git(*args: str) -> bytes:
        return run_git(root, *args, check=True, timeout=120, text=False).stdout
    try:
        top = Path(os.fsdecode(git("rev-parse", "--show-toplevel").strip())).resolve()
        if top != checkout.resolve():
            # An empty or broken `.git` falls through to an outer repository's rules.
            return frozenset(), "the nearest .git is not a usable repository"
        output = git("ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
    except subprocess.CalledProcessError as exc:
        return frozenset(), f"git exited with status {exc.returncode} (not a usable repository, or one git refuses to read)"
    except (OSError, subprocess.SubprocessError) as exc:
        return frozenset(), f"git failed: {type(exc).__name__}"
    listed = frozenset(entry.decode("utf-8", "surrogateescape").rstrip("/") for entry in output.split(b"\0") if entry)
    if "" in listed or "." in listed:
        return frozenset(), "the scan root itself is ignored by git"
    return listed, ""


def under_ignored(rel: str, listed: frozenset[str]) -> bool:
    """Whether repo-relative `rel` is, or lies inside, a path `untracked_ignored` listed."""
    parts = rel.split("/")
    return any("/".join(parts[:i]) in listed for i in range(1, len(parts) + 1))


def ignored(root: Path, candidates: Iterable[str]) -> set[str]:
    """The subset of `candidates` that `.gitignore` excludes — one subprocess for all."""
    batch = tuple(candidates)
    if not batch:
        return set()
    try:
        # -z both ways: without it git C-quotes a path holding a non-ASCII character
        # (core.quotePath), and the quoted form matches nothing the caller passed in.
        proc = run_git(root, "check-ignore", "-z", "--stdin", input="\0".join(batch), timeout=60)
    except (OSError, subprocess.SubprocessError):
        return set()
    # exit 0 = some ignored, 1 = none ignored, >1 = error. 1 is not a failure here.
    if proc.returncode > 1:
        return set()
    return {p for p in proc.stdout.split("\0") if p}

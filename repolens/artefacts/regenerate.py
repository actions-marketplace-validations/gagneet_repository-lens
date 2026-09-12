"""Regenerate committed derived artefacts from the CURRENT tree.

Used by the `post-merge` / `post-rewrite` hooks, and runnable by hand.

WHY THIS IS A POST-MERGE STEP AND *NOT* A MERGE DRIVER
======================================================
A merge driver was tried first and is WRONG in a way that produces no error, which is
worse than the conflict it set out to remove. Measured, not assumed:

    two branches each changed a different @featuretrace marker and regenerated;
    the merge auto-resolved with no conflict;
    the resulting artefact did NOT equal a fresh regeneration of the merged tree,
    and was missing one branch's marker entirely.

The reason is structural: **git invokes a merge driver DURING the merge, one path at a
time, while the working tree is still half-applied.** A generator that scans the tree at
that moment sees some of one branch's source and none of the other's. It cannot see the
merged tree, because the merged tree does not exist yet. No amount of care inside the
driver fixes that.

So the split is:

  merge driver   resolve WITHOUT conflict and WITHOUT pretending to be correct — it just
                 keeps one side, because the content is about to be replaced anyway.
  this module    run AFTER the merge, when the tree is complete, and produce the artefact
                 that is correct by construction.
  the CI gate    the backstop. A merge performed by GitHub's own merge button runs NO
                 client-side hooks at all, so `--check` failing with "regenerate" is the
                 only thing standing between a server-side merge and a stale artefact.

Determinism is a prerequisite for all of it: a generator that stamps a wall clock into a
committed file makes every regeneration a conflict.

Which files are generated, and by which command, is `[artefacts] rules` in repolens.toml.

USAGE
    repolens artefacts regenerate --changed-since 'HEAD@{1}'
    repolens artefacts regenerate --paths docs/architecture/function_lens_digest.json
    repolens artefacts regenerate --all
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import PurePosixPath

from ..config import Config
from ..core.files import SkipRule
from ..core.git import tracked_paths
from ..featuretrace.model import MARKER_PREFIXES, MARKER_RE
from .settings import ArtefactSettings, from_config

# The FeatureTrace generator exits 1 with this line for a tag carrying no markers.
NO_MARKERS = re.compile(r"No @featuretrace:\S+ markers found")

#: Bytes of a changed file read for its marker lines; markers sit at the top.
HEAD_BYTES = 4000


class Regenerator:
    def __init__(self, settings: ArtefactSettings):
        self.settings = settings
        self._ft_skip = SkipRule(settings.featuretrace.skip_parts)

    # ── which generator owns a path ─────────────────────────────────────────────
    def argv_for(self, path: str) -> list[str] | None:
        """The regeneration command for `path`, or None when no rule owns it.

        Ordered, first match wins. A path that matches nothing is NOT regenerated: an
        artefact this module does not understand is one it must not claim to have fixed.
        """
        for rule in self.settings.rules:
            argv = rule.argv(path)
            if argv is not None:
                return argv
        return None

    def _runs_first(self, command: list[str]) -> bool:
        return any(name in command[0] for name in self.settings.run_first)

    def generators_for(self, paths: list[str]) -> list[list[str]]:
        """The DEDUPLICATED generator commands needed to refresh `paths`.

        Deduplicated because one generator writes several artefacts: the function lens
        emits both the digest and the HTML, and a FeatureTrace run emits four files per
        tag. Running it once per changed file would multiply a multi-minute scan for no
        gain.

        ORDERED so every `run_first` command happens FIRST. A FeatureTrace run with
        `--format all` writes all four of a tag's files whichever one triggered it —
        including any a dedicated generator owns. Left in path order the winner depended
        on `git ls-files` ordering, which is not a decision anybody made. Running the
        explicit owners last makes the result deterministic and correct by construction.
        """
        first: list[list[str]] = []
        rest: list[list[str]] = []
        for path in paths:
            argv = self.argv_for(path.replace("\\", "/"))
            if argv is None:
                continue
            bucket = first if self._runs_first(argv) else rest
            if argv not in bucket:
                bucket.append(argv)
        return first + rest

    def tracked_generated_paths(self) -> list[str]:
        """Every tracked file a rule knows how to regenerate."""
        return [p for p in sorted(tracked_paths(self.settings.root)) if self.argv_for(p) is not None]

    # ── how to run it ───────────────────────────────────────────────────────────
    def is_slow(self, command: list[str]) -> bool:
        return any(any(slow in part for part in command) for slow in self.settings.slow)

    def needs_venv(self, command: list[str]) -> bool:
        return any(any(name in part for part in command) for name in self.settings.needs_venv)

    def has_venv(self) -> bool:
        venv = self.settings.venv_python
        return venv is not None and venv.exists()

    def interpreter_for(self, command: list[str]) -> str:
        """The configured venv interpreter whenever it exists, else the current one.

        Preferred even for generators that do not strictly need it: a generator that
        degrades without the application's dependencies (computing fewer fields and
        carrying the previous run's forward) produces a different artefact than CI.
        """
        if self.has_venv():
            return str(self.settings.venv_python)
        return sys.executable

    def is_stale(self, command: list[str], interpreter: str) -> bool | None:
        """Whether `command`'s artefact actually needs regenerating.

        True = stale, False = current, None = could not tell (no --check, timeout, crash).
        None must be treated as stale by the caller: a check that cannot run is not
        evidence of freshness, and the whole point of the warning is the case where CI
        would fail.

        A NAG THAT FIRES EVERY TIME IS A NAG NOBODY READS. The slow generators answer
        "am I stale?" far faster than "regenerate me" (the lens: ~4 minutes to build, 6s
        to check). On a plain fast-forward pull whose commits carried their own
        regenerated copies, the hook used to print "run it before pushing" anyway.
        """
        try:
            result = subprocess.run(
                [interpreter, *command, "--check"], cwd=self.settings.root, capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                timeout=self.settings.check_timeout_seconds,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        if result.returncode == 0:
            return False
        # Non-zero is "stale" only if the generator understood --check at all. An
        # argparse rejection also exits non-zero, and reading that as staleness would
        # restore the unconditional nag silently.
        if "unrecognized arguments" in (result.stderr or ""):
            return None
        return True

    # ── which artefacts a change invalidates ────────────────────────────────────
    def is_scanned_by_featuretrace(self, path: str) -> bool:
        """Whether the FeatureTrace generator would even look at this file.

        A marker outside its scan roots yields ZERO nodes and a doomed exit 1, so a tag
        read from such a file has no map to refresh.
        """
        ft = self.settings.featuretrace
        roots = [d.strip("/") for d in ft.scan_dirs]
        if not any(d in ("", ".") or path.startswith(d + "/") for d in roots):
            return False
        if self._ft_skip.matches(tuple(path.split("/"))):
            return False
        return PurePosixPath(path).suffix in ft.extensions

    @staticmethod
    def declared_tags(text: str) -> set[str]:
        """The tags this text DECLARES — marker lines only, never a mention of one.

        FeatureTrace's own grammar, deliberately: it counts only a line whose first
        non-space characters open a marker, so a `Related:` cross-reference, a test
        fixture or prose carrying the literal string is not a declaration and has no map
        to regenerate. Read without that rule, a file that merely POINTED at
        `@featuretrace:notices` queued a generator for a tag nothing declares, which
        exits 1, and every merge touching it reported "1 generator(s) failed".
        """
        tags: set[str] = set()
        for line in text.splitlines():
            stripped = line.lstrip()
            if not stripped.startswith(MARKER_PREFIXES):
                continue
            match = MARKER_RE.search(stripped)
            if match:
                tags.add(match.group(1))
        return tags

    def featuretrace_map_for(self, tag: str) -> str:
        return f"{self.settings.featuretrace.map_dir_rel}/{tag}_flow.md"

    def _head_at(self, ref: str, path: str) -> str:
        """The top of `path` as it was at `ref`, or "" if it did not exist there."""
        out = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=self.settings.root,
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
        return out.stdout[:HEAD_BYTES] if out.returncode == 0 else ""

    def affected_paths(self, changed: list[str], since: str | None = None) -> list[str]:
        """Map changed SOURCE files to the artefacts they invalidate.

        Deliberately narrower than "everything". An earlier version returned every known
        artefact whenever anything changed, so the post-merge hook regenerated all 200+
        FeatureTrace maps AND the function lens on every merge — it ran for over eight
        minutes and had to be killed. A hook that slow gets uninstalled, and an
        uninstalled hook protects nothing.

        A FeatureTrace map is invalidated only by a change to a file carrying its tag, so
        the tags are read out of the changed files themselves. `invalidated_by_any_source`
        names artefacts that index the whole tree, which is exactly why they are slow.

        With `since`, the tags a file carried BEFORE the change count too. Deleting a
        marked file, or removing its marker, changes that tag's map; reading only the new
        content found no tag and left the map naming a file that no longer exists.
        """
        root = self.settings.root
        paths: list[str] = []
        tags: set[str] = set()
        source_touched = False

        for path in changed:
            if self.argv_for(path) is not None:
                continue  # a regenerated artefact is an OUTPUT, never a reason to regenerate
            if not path.endswith(self.settings.source_suffixes):
                continue
            source_touched = True
            if not self.is_scanned_by_featuretrace(path):
                continue  # the generator cannot see it, so it has no map to refresh
            if since:
                tags.update(self.declared_tags(self._head_at(since, path)))
            full = root / path
            if not full.exists():
                continue  # deleted on this side: only its old tags (above) apply
            try:
                head = full.read_text(encoding="utf-8", errors="replace")[:HEAD_BYTES]
            except OSError:
                continue
            tags.update(self.declared_tags(head))

        paths.extend(self.featuretrace_map_for(tag) for tag in sorted(tags))
        if source_touched:
            paths.extend(self.settings.invalidated_by_any_source)
        return paths

    def changed_since(self, ref: str) -> list[str]:
        # -z: git C-quotes a non-ASCII path in line mode ("docs/caf\303\251.md"), which
        # then matches no rule and no file, so its artefact was silently never refreshed.
        out = subprocess.run(
            ["git", "diff", "--name-only", "-z", ref, "HEAD"], cwd=self.settings.root,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if out.returncode != 0:
            # A hook must never break the operation it runs after. Report and do nothing
            # rather than guess: the CI gate still catches a stale artefact.
            print(f"regenerate_artifacts: could not diff against {ref!r}; nothing regenerated",
                  file=sys.stderr)
            return []
        return self.affected_paths([p for p in out.stdout.split("\0") if p], since=ref)

    def orphan_hint(self, command: list[str]) -> str:
        """The command that removes a tag's maps once no source file declares it."""
        return f"git rm {self.settings.featuretrace.map_dir_rel}/{command[1]}_*"

    # ── the run ─────────────────────────────────────────────────────────────────
    def run(self, argv: list[str] | None, prog: str | None = None) -> int:
        ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
        group = ap.add_mutually_exclusive_group(required=True)
        group.add_argument("--paths", nargs="+", help="regenerate the artefacts for these paths")
        group.add_argument("--changed-since", metavar="REF",
                           help="regenerate what changed between REF and HEAD invalidates")
        group.add_argument("--all", action="store_true", help="regenerate every known artefact")
        ap.add_argument("--include-slow", action="store_true",
                        help="also run the generators classified slow")
        ap.add_argument("--quiet", action="store_true")
        args = ap.parse_args(argv)

        if args.paths:
            paths = args.paths
        elif args.all:
            paths = self.tracked_generated_paths()
        else:
            paths = self.changed_since(args.changed_since)

        commands = self.generators_for(paths)
        if not self.has_venv():
            blocked = [c for c in commands if self.needs_venv(c)]
            commands = [c for c in commands if not self.needs_venv(c)]
            venv = self.settings.venv_python
            for command in blocked:
                # A generator that CANNOT run is skipped and reported, never failed: a
                # phantom failure and a real one read identically in a failure count.
                print(f"regenerate_artifacts: SKIPPED (needs venv) {' '.join(command)}")
                where = self.settings.rel(venv) if venv else "(no venv_python configured)"
                print(f"  no interpreter at {where}; run it yourself once the venv exists:")
                print(f"    {where} {command[0]}")

        if not args.include_slow:
            deferred = [c for c in commands if self.is_slow(c)]
            commands = [c for c in commands if not self.is_slow(c)]
            for command in deferred:
                stale = self.is_stale(command, self.interpreter_for(command))
                if stale is False:
                    if not args.quiet:
                        print(f"regenerate_artifacts: current, not run {' '.join(command)}")
                    continue
                hedge = "" if stale else " (could not check — treating as stale)"
                print(f"regenerate_artifacts: SKIPPED (slow){hedge} {' '.join(command)}")
                print("  run it before pushing, or CI will fail on a stale artefact:")
                print(f"    python3 {command[0]}")
        if not commands:
            if not args.quiet:
                print("regenerate_artifacts: nothing to regenerate")
            return 0

        failed = 0
        orphaned = 0
        for command in commands:
            if not args.quiet:
                print(f"regenerate_artifacts: running {' '.join(command)}")
            result = subprocess.run(
                [self.interpreter_for(command), *command], cwd=self.settings.root,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            if result.returncode != 0:
                # A TAG WITH NO MARKERS IS NOT A BROKEN GENERATOR — it is an artefact
                # whose source markers are gone, and calling it "FAILED" makes a phantom
                # read exactly like a real breakage. Named separately, with the one
                # action that resolves it.
                if NO_MARKERS.search(result.stderr or ""):
                    print(f"regenerate_artifacts: ORPHANED {' '.join(command)}")
                    print("  no source file carries that tag any more. Either restore the "
                          "marker, or delete the stale artefact:")
                    print(f"    {self.orphan_hint(command)}")
                    orphaned += 1
                    continue
                # Reported, never fatal to the caller: this runs from a post-merge hook,
                # and a hook that aborts leaves a developer mid-merge with no obvious way
                # out. The CI gate is what turns a missed regeneration into a failure.
                print(f"regenerate_artifacts: {' '.join(command)} FAILED", file=sys.stderr)
                print(result.stderr[-1500:], file=sys.stderr)
                failed += 1

        if orphaned:
            print(f"regenerate_artifacts: {orphaned} artefact(s) have no markers left "
                  f"(see ORPHANED above). Nothing is broken; the stale files need removing.")
        if failed:
            print(f"regenerate_artifacts: {failed} generator(s) failed - the committed "
                  f"artefacts may be stale. Re-run them by hand before pushing.",
                  file=sys.stderr)
        return 0


def main(argv: list[str] | None = None, *, config: Config | None = None,
         settings: ArtefactSettings | None = None, prog: str | None = None) -> int:
    return Regenerator(settings or from_config(config)).run(argv, prog)


if __name__ == "__main__":
    raise SystemExit(main())

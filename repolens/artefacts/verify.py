"""`.gitattributes` and the regeneration rules must name the same committed files.

They are two lists of one fact, kept in two places, and each half fails differently:

  routed to the driver, no rule   the merge keeps one side and nothing regenerates it,
                                  so the artefact stays silently stale after every merge.
  a rule, not routed to the driver  a parallel branch produces an ordinary text conflict
                                  on a derived file — or worse, a clean text merge that
                                  describes neither branch and still passes as valid.

Asks git itself (`git check-attr`), so glob semantics are git's, not a reimplementation.
Exits 1 when the lists disagree.
"""
from __future__ import annotations

import argparse
import subprocess

from ..config import Config
from ..core.git import tracked_paths
from .regenerate import Regenerator
from .settings import ArtefactSettings, from_config


def routed_to_driver(settings: ArtefactSettings, paths: list[str]) -> set[str]:
    """The subset of `paths` whose `merge` attribute is the configured driver."""
    if not paths:
        return set()
    # -z: NUL-separated in and out, so a non-ASCII path comes back as itself rather than
    # C-quoted, and `path NUL attribute NUL value` needs no ": " splitting.
    out = subprocess.run(
        ["git", "-C", str(settings.root), "check-attr", "-z", "--stdin", "merge"],
        input="\0".join(paths), capture_output=True, text=True, check=True,
    ).stdout
    fields = out.split("\0")
    routed = set()
    for i in range(0, len(fields) - 2, 3):
        path, _attribute, value = fields[i:i + 3]
        if value == settings.driver:
            routed.add(path)
    return routed


def disagreements(settings: ArtefactSettings) -> tuple[list[str], list[str]]:
    """(routed but unowned, owned but unrouted), both sorted."""
    regen = Regenerator(settings)
    tracked = sorted(tracked_paths(settings.root))
    owned = {p for p in tracked if regen.argv_for(p) is not None}
    routed = routed_to_driver(settings, tracked)
    return sorted(routed - owned), sorted(owned - routed)


def main(argv: list[str] | None = None, *, config: Config | None = None,
         settings: ArtefactSettings | None = None, prog: str | None = None) -> int:
    argparse.ArgumentParser(prog=prog, description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter).parse_args(argv)
    settings = settings or from_config(config)
    unowned, unrouted = disagreements(settings)
    for path in unowned:
        print(f"merge={settings.driver} but no regeneration rule owns it: {path}")
    for path in unrouted:
        print(f"a rule regenerates it but it is not merge={settings.driver}: {path}")
    if unowned or unrouted:
        print(f"\n{len(unowned) + len(unrouted)} disagreement(s) between .gitattributes and "
              "[artefacts] rules.")
        return 1
    print("artefacts: .gitattributes and the regeneration rules agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

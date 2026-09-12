"""The portable rules documents, shipped with the package.

Each document states one rule for a codebase that more than one person (or agent)
changes: the rule, why the obvious alternative fails, how to apply it, and the repolens
command that enforces it. None assumes anything about a particular repository.

    repolens rules                 list them
    repolens rules show NAME       print one
    repolens init                  copies them into a repository (default docs/repolens/)
"""
from __future__ import annotations

import argparse
from importlib import resources

from ..config import Config

INDEX = "README"


def names() -> list[str]:
    """Rule names, in the order the index lists them (the index itself excluded)."""
    found = sorted(p.name[:-3] for p in resources.files(__package__).iterdir()
                   if p.name.endswith(".md") and p.name != f"{INDEX}.md")
    return found


def text(name: str) -> str:
    """The Markdown source of one rule, or of the index (`README`)."""
    path = resources.files(__package__) / f"{name}.md"
    if not path.is_file():
        raise KeyError(name)
    return path.read_text(encoding="utf-8")


def documents() -> dict[str, str]:
    """Every document, index included: file name -> Markdown."""
    return {f"{name}.md": text(name) for name in [INDEX, *names()]}


def main(argv: list[str] | None = None, *, config: Config | None = None, prog: str | None = None) -> int:
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="action")
    show = sub.add_parser("show", help="print one rule")
    show.add_argument("name", help="a rule name, or README for the index")
    args = ap.parse_args(argv)
    if args.action == "show":
        try:
            print(text(args.name.removesuffix(".md")), end="")
        except KeyError:
            print(f"no rule {args.name!r}; one of: {', '.join(names())}")
            return 2
        return 0
    for name in names():
        first = next((ln for ln in text(name).splitlines() if ln.startswith("# ")), f"# {name}")
        print(f"  {name:<24} {first[2:]}")
    return 0

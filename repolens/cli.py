"""The `repolens` command line: `repolens [--root DIR] <group> <command> [args]`."""
from __future__ import annotations

import importlib
import sys

from . import __version__
from .config import load_config
from .core.console import utf8_console

#: "<group> <command>" -> module exposing `main(argv, *, config, prog)`.
COMMANDS: dict[str, tuple[str, str]] = {
    "featuretrace map": ("repolens.featuretrace.maps", "generate FeatureTrace maps; --check gates staleness"),
    "featuretrace audit": ("repolens.featuretrace.audit", "audit marker quality; --check is the ratchet"),
    "featuretrace propose": ("repolens.featuretrace.propose", "draft markers, JSDoc and stable Function Lens ids; --apply writes the reviewed patch"),
    "lens": ("repolens.lens.build", "build the function index; --lookup NAME; --check gates staleness"),
    "lens similar": ("repolens.lens.similar", "search the index by behaviour before writing a helper"),
    "owners": ("repolens.owners.registry", "check the capability index; --impact; --check"),
    "impact": ("repolens.impact.cli", "scan | query | doctor: read-only change-impact explorer"),
    "artefacts regenerate": ("repolens.artefacts.regenerate", "rebuild derived artefacts after a merge"),
    "artefacts install-hooks": ("repolens.artefacts.hooks", "register the merge driver and post-merge hooks"),
    "artefacts verify": ("repolens.artefacts.verify", ".gitattributes and the rules must agree"),
    "gates": ("repolens.gates.reachability", "every validation script is run by something, and can fail"),
    "docs coverage": ("repolens.docs.coverage", "docstring coverage of public symbols; --check is a ratchet"),
    "docs build": ("repolens.docs.build", "code-reference HTML: pdoc (Python) and TypeDoc (TypeScript)"),
    "docs generate": ("repolens.docs.generate", "OpenAPI, schema, architecture, debugging and feature maps from the evidence graph"),
    "report": ("repolens.report.runner", "run every tool: one prioritised findings report (md, json, sarif)"),
    "analyze": ("repolens.analysis", "static stack analysis: JSON, Mermaid, Markdown and SARIF"),
    "serve": ("repolens.api.cli", "serve a configured local repository with Swagger and a bearer token"),
    "api export": ("repolens.api.export", "generate OpenAPI and Postman contracts from the API"),
    "init": ("repolens.bootstrap", "set up a repository: repolens.toml, rules documents, CI workflow"),
    "rules": ("repolens.rules", "list or print the portable rules documents (`rules show NAME`)"),
}


def usage() -> str:
    """The top-level help text listing every command in `COMMANDS`."""
    width = max(len(name) for name in COMMANDS)
    rows = "\n".join(f"  {name:<{width}}  {desc}" for name, (_, desc) in COMMANDS.items())
    return (
        "usage: repolens [--root DIR] <command> [args]\n\n"
        f"commands:\n{rows}\n\n"
        "Settings are read from repolens.toml at the repository root."
    )


def main(argv: list[str] | None = None) -> int:
    """Dispatch to the command module's `main` and return its exit code.

    Two-word command names are tried before one-word names. Returns 2 for an unknown
    command.
    """
    utf8_console()
    args = list(sys.argv[1:] if argv is None else argv)
    root = None
    if len(args) >= 2 and args[0] == "--root":
        root, args = args[1], args[2:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(usage())
        return 0
    if args[0] == "--version":
        print(__version__)
        return 0
    for width in (2, 1):
        name = " ".join(args[:width])
        if len(args) >= width and name in COMMANDS:
            module = importlib.import_module(COMMANDS[name][0])
            return module.main(args[width:], config=load_config(root), prog=f"repolens {name}")
    print(f"repolens: unknown command {' '.join(args[:2])!r}\n\n{usage()}", file=sys.stderr)
    return 2

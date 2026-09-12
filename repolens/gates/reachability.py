"""Every validation script is run by something, and every audit can fail.

A check dies in one of three ways, and none of them raises:

  absent     nothing runs it. A script no workflow, deploy step, Makefile, test or
             config names is dead code wearing a gate's clothes.
  defanged   it runs, and can never exit non-zero: no --check/--strict/--exit-code
             flag and no `return 1`. That is a report, and a report is not a gate.
  blind      its subject list is a literal and the new file is not on it. Not
             detectable here; see the ratchets.

Reachability is a TEXT search of the configured execution surfaces with whole-line
comments stripped — prose that names a script (a README, CLAUDE.md, a task file) is
deliberately not a surface, because being named in three documents and executed by
nothing is exactly the state this rejects. A trailing comment on a command line is not
stripped; that can only make a script look MORE reachable, and the job here is the
zero-reference case. repolens.toml is a surface only through the commands it runs (see
`executed_by_config`), never through a script merely named in it.

Every exemption carries a reason in words and is a debt marker, not an escape hatch.
An exemption that no longer applies is reported as stale (fatal under --strict).

Configured by `[gates]` in repolens.toml.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config, load_config, merge

DEFAULTS: dict[str, Any] = {
    # Globs (repo-relative) of scripts that must be reachable from a surface.
    "scripts": [],
    # Globs of scripts that must also be able to FAIL; usually the audits, not generators.
    "must_fail": [],
    # Globs of files whose contents can cause a script to run.
    "surfaces": [".github/workflows/*.yml", ".github/workflows/*.yaml", "Makefile",
                 "repolens.toml"],
    "gate_flags": ["--check", "--strict", "--exit-code"],
    # script file name -> the reason it is exempt, in words.
    "exempt_unreachable": {},
    "exempt_non_gating": {},
}

_COMMENT = re.compile(r"^\s*#")
_FAILING_RETURN = re.compile(r"^\s*return 1\b", re.MULTILINE)


def _glob(root: Path, patterns: list[str]) -> list[Path]:
    found: set[Path] = set()
    for pattern in patterns:
        found.update(p for p in root.glob(pattern) if p.is_file())
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def non_comment_text(path: Path) -> str:
    """File contents with whole-line `#` comments removed."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(line for line in lines if not _COMMENT.match(line))


#: A surface line that runs the report: `repolens report`, `bin/repolens report --check`.
#: Whitespace, not a slash, separates the words, so `.repolens/report/` does not match.
_RUNS_REPORT = re.compile(r"\brepolens(?:\s+--root\s+\S+)?\s+report\b")


def executed_by_config(cfg: Config, report_is_run: bool = False) -> str:
    """The commands repolens.toml RUNS. Only these count when the profile is a surface.

    The `[[artefacts.rules]]` generators always count: the post-merge hook executes them.
    `[[report.commands]]` count only when some OTHER surface runs `repolens report` —
    a CI step, say — because until something does, they are names, not executions.
    Labels, remedies, the `slow` list and exemption lists never count: a name that runs
    nothing is exactly what this check exists to reject."""
    commands = list(cfg.section("artefacts").get("rules", []))
    if report_is_run:
        commands += list(cfg.section("report").get("commands", []))
    return "\n".join(" ".join(str(part) for part in c.get("run", [])) for c in commands)


@dataclass
class GateSettings:
    root: Path
    scripts: list[Path]
    must_fail: list[Path]
    surfaces: list[Path]
    gate_flags: tuple[str, ...]
    exempt_unreachable: dict[str, str]
    exempt_non_gating: dict[str, str]
    config_path: Path | None = None
    config_commands: str = ""
    _texts: dict[Path, str] = field(default_factory=dict, repr=False)

    def surface_text(self, surface: Path) -> str:
        if surface not in self._texts:
            if self.config_path is not None and surface == self.config_path:
                self._texts[surface] = self.config_commands
            else:
                self._texts[surface] = non_comment_text(surface)
        return self._texts[surface]


def from_config(cfg: Config | None = None) -> GateSettings:
    cfg = cfg if cfg is not None else load_config()
    section = merge(DEFAULTS, cfg.section("gates"))
    root = cfg.root
    surfaces = _glob(root, section["surfaces"])
    report_is_run = any(_RUNS_REPORT.search(non_comment_text(p))
                        for p in surfaces if cfg.path is None or p != cfg.path)
    return GateSettings(
        root=root,
        scripts=_glob(root, section["scripts"]),
        must_fail=_glob(root, section["must_fail"]),
        surfaces=surfaces,
        gate_flags=tuple(section["gate_flags"]),
        exempt_unreachable=dict(section["exempt_unreachable"]),
        exempt_non_gating=dict(section["exempt_non_gating"]),
        config_path=cfg.path,
        config_commands=executed_by_config(cfg, report_is_run),
    )


def referenced_by(settings: GateSettings, script: Path) -> list[str]:
    """The surfaces that name `script`, comments stripped. Empty = executed by nothing."""
    return [
        s.relative_to(settings.root).as_posix()
        for s in settings.surfaces
        if s != script and script.name in settings.surface_text(s)
    ]


def can_fail(settings: GateSettings, script: Path) -> bool:
    """Whether `script` has any way to exit non-zero: a gate flag, or a `return 1`."""
    try:
        src = script.read_text(encoding="utf-8", errors="replace")
    except OSError:  # deleted since the walk: it cannot fail anything
        return False
    has_flag = any(f'"{flag}"' in src or f"'{flag}'" in src for flag in settings.gate_flags)
    return has_flag or _FAILING_RETURN.search(src) is not None


@dataclass
class Findings:
    unreachable: list[str] = field(default_factory=list)
    non_gating: list[str] = field(default_factory=list)
    stale_exemptions: list[str] = field(default_factory=list)


def evaluate(settings: GateSettings) -> Findings:
    found = Findings()
    names = {p.name for p in settings.scripts}
    for script in settings.scripts:
        reached = bool(referenced_by(settings, script))
        exempt = script.name in settings.exempt_unreachable
        if not reached and not exempt:
            found.unreachable.append(script.name)
        elif reached and exempt:
            found.stale_exemptions.append(
                f"{script.name}: exempt_unreachable, but {referenced_by(settings, script)[0]} runs it")
    for script in settings.must_fail:
        fails = can_fail(settings, script)
        exempt = script.name in settings.exempt_non_gating
        if not fails and not exempt:
            found.non_gating.append(script.name)
        elif fails and exempt:
            found.stale_exemptions.append(f"{script.name}: exempt_non_gating, but it can fail")
    gating_names = {p.name for p in settings.must_fail}
    for name in sorted(settings.exempt_unreachable):
        if name not in names:
            found.stale_exemptions.append(f"{name}: exempt_unreachable, but no such script")
    for name in sorted(settings.exempt_non_gating):
        if name not in gating_names:
            found.stale_exemptions.append(
                f"{name}: exempt_non_gating, but it is not one of the must_fail scripts")
    return found


def main(argv: list[str] | None = None, *, config: Config | None = None,
         settings: GateSettings | None = None, prog: str | None = None) -> int:
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on an unreachable or non-gating script")
    ap.add_argument("--strict", action="store_true",
                    help="also exit 1 on a stale exemption")
    args = ap.parse_args(argv)
    settings = settings or from_config(config)
    found = evaluate(settings)

    print(f"gates: {len(settings.scripts)} scripts, {len(settings.surfaces)} surfaces")
    for name in found.unreachable:
        print(f"  UNREACHABLE  {name} is executed by nothing. Wire it into a surface, or "
              "exempt it with a reason.")
    for name in found.non_gating:
        print(f"  NON-GATING   {name} can never exit non-zero: give it a --check mode, or "
              "exempt it as a pure generator.")
    for line in found.stale_exemptions:
        print(f"  STALE        {line}")
    if not (found.unreachable or found.non_gating or found.stale_exemptions):
        print("  every script is reachable and every audit can fail.")

    if (args.check or args.strict) and (found.unreachable or found.non_gating):
        return 1
    if args.strict and found.stale_exemptions:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

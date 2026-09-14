"""Artefact settings: generic defaults, overridden by `[artefacts]` in repolens.toml."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import Config, load_config, merge
from ..featuretrace.settings import FTSettings
from ..featuretrace.settings import from_config as featuretrace_settings

DEFAULTS: dict[str, Any] = {
    # Ordered, first match wins: [{pattern = '<regex>', run = [argv...]}]. A `{name}` in
    # `run` is filled from the pattern's named group, so one rule covers a family of
    # files whose generator takes an argument (a FeatureTrace tag, say).
    "rules": [],
    # Generator names whose commands run BEFORE every other command. For a generator
    # that writes files another generator owns, so the owner writes last and wins.
    "run_first": [],
    # Generators too slow for a hook. They are reported (after asking --check whether
    # they are even stale) instead of run, unless --include-slow is passed.
    "slow": [],
    # Generators that cannot run without `venv_python`; skipped and reported without it.
    "needs_venv": [],
    # Preferred interpreter for every generator, when it exists.
    "venv_python": "",
    # A changed file with one of these suffixes is SOURCE, and invalidates
    # `invalidated_by_any_source`; FeatureTrace maps are invalidated by tag instead.
    "source_suffixes": [".py", ".ts", ".tsx", ".js", ".jsx"],
    "invalidated_by_any_source": [],
    "check_timeout_seconds": 90,
    # The merge driver name .gitattributes uses (`merge=<driver>`).
    "driver": "generated",
    # How a person runs the regenerator, and what the installed hooks run. `{python}`
    # is filled with the interpreter found at install time.
    "command": "repolens artefacts regenerate",
    "hook_command": "repolens artefacts regenerate",
}


@dataclass(frozen=True)
class Rule:
    """One `[artefacts] rules` entry: a path regex and the generator argv that rebuilds it."""
    pattern: re.Pattern[str]
    run: tuple[str, ...]

    def argv(self, path: str) -> list[str] | None:
        """The generator argv for `path` with `{name}` filled from named groups; None if unmatched."""
        match = self.pattern.match(path)
        if not match:
            return None
        groups = {k: v for k, v in match.groupdict().items() if v is not None}
        return [_fill(part, groups) for part in self.run]


_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _fill(part: str, groups: dict[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: groups.get(m.group(1), m.group(0)), part)


@dataclass
class ArtefactSettings:
    """Resolved `[artefacts]` settings, plus the FeatureTrace settings used to map tags."""
    root: Path
    rules: tuple[Rule, ...]
    run_first: tuple[str, ...]
    slow: tuple[str, ...]
    needs_venv: tuple[str, ...]
    venv_python: Path | None
    source_suffixes: tuple[str, ...]
    invalidated_by_any_source: tuple[str, ...]
    check_timeout_seconds: int
    driver: str
    command: str
    hook_command: str
    featuretrace: FTSettings

    def rel(self, path: Path) -> str:
        """`path` relative to the root with forward slashes, or as-is when outside it."""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()


def from_config(cfg: Config | None = None) -> ArtefactSettings:
    """Build `ArtefactSettings` from `[artefacts]` merged over `DEFAULTS`; loads config if none given."""
    cfg = cfg if cfg is not None else load_config()
    section = merge(DEFAULTS, cfg.section("artefacts"))
    venv = section["venv_python"]
    return ArtefactSettings(
        root=cfg.root,
        rules=tuple(Rule(re.compile(r["pattern"]), tuple(r["run"])) for r in section["rules"]),
        run_first=tuple(section["run_first"]),
        slow=tuple(section["slow"]),
        needs_venv=tuple(section["needs_venv"]),
        venv_python=(cfg.root / venv) if venv else None,
        source_suffixes=tuple(section["source_suffixes"]),
        invalidated_by_any_source=tuple(section["invalidated_by_any_source"]),
        check_timeout_seconds=int(section["check_timeout_seconds"]),
        driver=section["driver"],
        command=section["command"],
        hook_command=section["hook_command"],
        featuretrace=featuretrace_settings(cfg),
    )

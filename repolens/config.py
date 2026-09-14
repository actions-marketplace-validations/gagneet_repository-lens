"""Load a repository's repolens profile.

Everything specific to one repository — which directories to scan, what the layers are
called, where generated artefacts live, which strings a report prints — lives in
`repolens.toml` at the repository root. Each subpackage owns its own defaults and reads
its section through `Config.section`, so a repository with no profile still gets a
working, if plain, setup.
"""
from __future__ import annotations

import copy
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONFIG_NAME = "repolens.toml"


def find_root(start: Path | str | None = None) -> Path:
    """The nearest directory holding `repolens.toml`, else the git root, else `start`."""
    here = Path(start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / CONFIG_NAME).is_file():
            return candidate
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    return here


def merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge `override` onto `base`. Tables merge; lists and scalars replace."""
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


@dataclass
class Config:
    """A parsed profile: the repository root, the TOML data, and the file it came from (if any)."""
    root: Path
    data: dict[str, Any]
    path: Path | None = None

    def section(self, *names: str) -> dict[str, Any]:
        """The nested table at `names` (e.g. `section("scan", "migrations")`), or {} if absent or not a table."""
        node: Any = self.data
        for name in names:
            node = node.get(name, {}) if isinstance(node, dict) else {}
        return node if isinstance(node, dict) else {}


def load_config(root: Path | str | None = None) -> Config:
    """Read the profile. With `root`, use it as-is; without, search upward from the cwd."""
    base = Path(root).resolve() if root is not None else find_root()
    path = base / CONFIG_NAME
    data: dict[str, Any] = {}
    if path.is_file():
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    return Config(root=base, data=data, path=path if path.is_file() else None)

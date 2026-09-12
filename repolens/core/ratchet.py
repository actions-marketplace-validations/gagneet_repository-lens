"""The per-file count ratchet.

A standard usually outlives its enforcement, so turning on a strict gate would fail
every change on debt its author did not create — and a gate that fails for reasons you
cannot fix is a gate that gets deleted. A ratchet asks the only fair question, "did THIS
change make it worse?", and lets the number fall as files are touched.

Two behaviours are deliberate and both are argued about:

* An un-baselined IMPROVEMENT also fails. A baseline that drifts above the real number
  quietly re-licenses every finding it was meant to hold; making the win fail loudly is
  what locks it in, and the fix is one command.
* A MISSING baseline fails in check mode and writes nothing. A check that creates its
  own baseline passes by construction, so deleting the file would silently disarm it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .files import rel


@dataclass
class Ratchet:
    label: str
    baseline_path: Path
    root: Path
    comment: str
    update_command: str
    unit: str = "issue"
    subject: str = "findings"
    regress_reason: str = "went backwards"
    new_file_note: str = "new files must be clean"
    failure_help: tuple[str, ...] = ()
    total_key: str = "total_issues"
    files_key: str = "files"
    extra: dict[str, Any] = field(default_factory=dict)

    def load(self) -> dict[str, int] | None:
        if not self.baseline_path.exists():
            return None
        try:
            data = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        return data.get(self.files_key, data) if isinstance(data, dict) else None

    def write(self, counts: dict[str, int]) -> None:
        payload = {
            "_comment": self.comment,
            self.total_key: sum(counts.values()),
            self.files_key: counts,
            **self.extra,
        }
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(
            json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8",
        )

    def run(self, counts: dict[str, int], update: bool) -> int:
        counts = dict(sorted(counts.items()))
        baseline = self.load()
        where = rel(self.baseline_path, self.root)

        if update:
            self.write(counts)
            action = "written" if baseline is None else "updated"
            print(f"\n{self.label} baseline {action}: "
                  f"{len(counts)} file(s), {sum(counts.values())} {self.unit}(s)")
            print(f"  {where}")
            return 0

        if baseline is None:
            print(f"\n{self.label} ratchet FAILED - no readable baseline at {where}.")
            print("A check that writes its own baseline passes by construction, so this")
            print(f"fails instead. Create it with `{self.update_command}` and commit it.")
            return 1

        regressions: list[str] = []
        improvements: list[str] = []
        for path, live in counts.items():
            was = baseline.get(path)
            if was is None:
                regressions.append(
                    f"  NEW FILE  {path}: {live} {self.unit}(s) - {self.new_file_note}")
            elif live > was:
                regressions.append(f"  INCREASED {path}: {was} -> {live}")
        for path, was in baseline.items():
            live = counts.get(path, 0)
            if live < was:
                improvements.append(f"  improved  {path}: {was} -> {live}")

        if regressions:
            print(f"\n{self.label} ratchet FAILED - {self.regress_reason}:")
            for line in regressions:
                print(line)
            if self.failure_help:
                print("\n" + "\n".join(self.failure_help))
            return 1

        if improvements:
            print(f"\n{self.label} improvements since baseline:")
            for line in improvements:
                print(line)
            print(f"\n{self.label} ratchet: {self.subject} improved but the baseline is stale.")
            print(f"Run `{self.update_command}` and commit")
            print(f"{where} to lock these wins in.")
            return 1

        print(f"\n{self.label} ratchet OK - {sum(counts.values())} {self.unit}(s) "
              f"across {len(counts)} file(s) (never increasing)")
        return 0

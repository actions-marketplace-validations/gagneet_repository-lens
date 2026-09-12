"""One findings model for every repolens tool, and the formats a reader or CI consumes.

Each tool reports in its own words; the report runner converts them to `Finding`s so a
reader gets ONE list, ordered by what to fix first, instead of eleven outputs in eleven
shapes. Three properties are kept apart on purpose, because collapsing them is how a
report stops being believed:

  severity    how bad it is IF real     critical | high | medium | low | info
  confidence  how likely it is real     high | medium | low
  exposure    who can reach it          unauthenticated | authenticated | internal |
                                        unreachable (dead code: nothing imports it) | ""

`priority` (P0-P3) is derived from all three and is the sort key. A heuristic detector
reports low confidence rather than a lower severity: a missing object-level check is as
bad as it ever was; what is uncertain is whether this one is missing.

The fingerprint deliberately excludes the line number, so a finding survives unrelated
edits above it and a baseline does not churn on every commit. Excluding the line also
means two hits of one rule in one file usually share a fingerprint — ruff and bandit say
the same words for every hit — so the baseline records HOW MANY of each fingerprint are
known, not merely that one is. A set would let the second SQL injection in a file hide
behind the first. Repeats are numbered in sort order (`occurrence`); when a file gains a
repeat, the count is exact and the one flagged new is the one that sorts last.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
PRIORITIES = ("P0", "P1", "P2", "P3")

_SEVERITY_WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 0.5}
_CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.7, "low": 0.4}
_EXPOSURE_WEIGHT = {"unauthenticated": 1.5, "authenticated": 1.0, "internal": 0.5,
                    "unreachable": 0.1, "": 1.0}
#: Lower bound of each priority's score band.
_PRIORITY_FLOOR = (("P0", 9.0), ("P1", 5.0), ("P2", 2.5), ("P3", 0.0))
#: GitHub code scanning reads `security-severity` (0-10) to label a security result.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

_DIGITS = re.compile(r"\d+")
#: A number in a message that can rise or fall as a COUNT: not a piece of a decimal
#: ("0.41s"), not a duration ("12 s", "300ms"), not a denominator ("3 of 148", "3/148").
#: Those move from run to run without the finding getting worse.
_MAGNITUDE = re.compile(r"(?<![\d.])(?<!of )(?<!/)\d+(?!\.?\d)"
                        r"(?!\s*(?:ms|s|secs?|seconds?|mins?|minutes?)\b)")
#: Baselines older than this recorded magnitudes with `_DIGITS`, so theirs cannot be
#: compared number by number with today's; they are ignored until the next rebuild.
_MAGNITUDE_FORMAT = 3


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    message: str
    file: str = ""
    line: int = 0
    confidence: str = "medium"
    category: str = "correctness"
    exposure: str = ""
    remedy: str = ""
    evidence: str = ""
    # True when a number in the message IS the finding: a ratchet's "FAIL: 3 new reads"
    # going to "FAIL: 4" is a new violation, and going to "FAIL: 2" is not. The numbers
    # stay out of the fingerprint and are compared on their own (`magnitudes`), so an
    # improvement keeps the finding's identity instead of reading as a new finding.
    counts_matter: bool = False
    # Filled by the report runner when a baseline exists.
    new: bool | None = None
    # 0 for the first finding with this fingerprint in sort order, 1 for the next, ...
    occurrence: int = 0

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r} from {self.tool}/{self.rule}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"unknown confidence {self.confidence!r} from {self.tool}/{self.rule}")

    @property
    def score(self) -> float:
        return round(_SEVERITY_WEIGHT[self.severity] * _CONFIDENCE_WEIGHT[self.confidence]
                     * _EXPOSURE_WEIGHT.get(self.exposure, 1.0), 2)

    @property
    def priority(self) -> str:
        return next(name for name, floor in _PRIORITY_FLOOR if self.score >= floor)

    @property
    def fingerprint(self) -> str:
        # Digits are normalised out of the message: counts and line references inside a
        # message change without the finding changing. When the count IS the finding
        # (`counts_matter`) it is compared separately, through `magnitudes`.
        stable = "|".join((self.tool, self.rule, self.file, _DIGITS.sub("#", self.message)))
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]

    @property
    def magnitudes(self) -> list[int]:
        """The numbers in the message when they are the finding (`counts_matter`), else []."""
        return [int(n) for n in _MAGNITUDE.findall(self.message)] if self.counts_matter else []

    @property
    def location(self) -> str:
        if not self.file:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    def to_dict(self) -> dict:
        data = asdict(self)
        data.update(priority=self.priority, score=self.score, fingerprint=self.fingerprint,
                    location=self.location)
        return data


def sort_key(finding: Finding) -> tuple:
    return (PRIORITIES.index(finding.priority), -finding.score, finding.category,
            finding.rule, finding.file, finding.line)


@dataclass
class ToolRun:
    """What one tool contributed: findings, or the reason it could not run."""
    tool: str
    findings: list[Finding] = field(default_factory=list)
    skipped: str = ""       # non-empty = did not run, and why (never a silent zero)
    error: str = ""         # non-empty = crashed; its findings are incomplete
    seconds: float = 0.0


# ── baseline ─────────────────────────────────────────────────────────────────────
class BaselineError(ValueError):
    """A baseline file exists and cannot be used. Never read as "no baseline" (which
    makes --check refuse for the wrong reason) or as an empty one (which makes every
    finding new)."""


def load_baseline(path: Path) -> dict[str, int] | None:
    """Fingerprint -> how many occurrences are known; None when there is no file.

    Reads formats 2 and 3 (`{"fingerprints": {fp: count}}`) and format 1, a list, in
    which each listed fingerprint counts once."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"{path}: not readable JSON ({exc})") from None
    raw = data.get("fingerprints") if isinstance(data, dict) else None
    if isinstance(raw, list) and all(isinstance(fp, str) for fp in raw):
        return dict(Counter(raw))
    if isinstance(raw, dict) and all(isinstance(k, str) and isinstance(v, int) and v >= 0
                                     for k, v in raw.items()):
        return dict(raw)
    raise BaselineError(f'{path}: expected {{"fingerprints": {{"<fingerprint>": <count>}}}}')


def load_magnitudes(path: Path) -> dict[str, list[list[int]]]:
    """Fingerprint -> the numbers each known occurrence of a `counts_matter` finding
    carried, in occurrence order. {} when the baseline has none, or recorded them before
    format 3 counted durations and decimals as numbers: comparing those against today's
    would report a finding as new because the old list was longer."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}  # load_baseline has already refused this file, with the reason
    if not isinstance(data, dict) or not isinstance(data.get("format"), int) \
            or data["format"] < _MAGNITUDE_FORMAT:
        return {}
    raw = data.get("magnitudes")
    if not isinstance(raw, dict):
        return {}
    return {fp: [list(m) for m in seen] for fp, seen in raw.items()
            if isinstance(seen, list) and all(isinstance(m, list) and all(isinstance(n, int) for n in m)
                                              for m in seen)}


def write_baseline(path: Path, findings: Iterable[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(findings, key=sort_key)  # the order `number_occurrences` uses
    counts = dict(sorted(Counter(f.fingerprint for f in ordered).items()))
    magnitudes: dict[str, list[list[int]]] = {}
    for f in ordered:
        if f.counts_matter:
            magnitudes.setdefault(f.fingerprint, []).append(f.magnitudes)
    data: dict = {"format": _MAGNITUDE_FORMAT, "fingerprints": counts}
    if magnitudes:
        data["magnitudes"] = dict(sorted(magnitudes.items()))
    path.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")


def number_occurrences(findings: Iterable[Finding]) -> None:
    """Number repeated fingerprints in sort order, so the numbering is deterministic."""
    seen: Counter[str] = Counter()
    for finding in sorted(findings, key=sort_key):
        finding.occurrence = seen[finding.fingerprint]
        seen[finding.fingerprint] += 1


def mark_new(findings: list[Finding], baseline: dict[str, int] | None,
             magnitudes: dict[str, list[list[int]]] | None = None) -> None:
    """A finding is new when its fingerprint occurs more often than the baseline allows,
    or, for a `counts_matter` finding, when a number it carries has RISEN since the
    baseline. A number that fell is an improvement, not a new finding."""
    number_occurrences(findings)
    known = magnitudes or {}
    for finding in findings:
        if baseline is None:
            finding.new = None
            continue
        finding.new = finding.occurrence >= baseline.get(finding.fingerprint, 0)
        before = known.get(finding.fingerprint, [])
        if not finding.new and finding.counts_matter and finding.occurrence < len(before):
            was, now = before[finding.occurrence], finding.magnitudes
            # A different SHAPE of message cannot be compared number by number.
            finding.new = len(was) != len(now) or any(n > w for n, w in zip(now, was))


# ── formats ──────────────────────────────────────────────────────────────────────
def to_json(runs: list[ToolRun], meta: dict) -> str:
    findings = sorted((f for r in runs for f in r.findings), key=sort_key)
    return json.dumps({
        "meta": meta,
        "tools": [{"tool": r.tool, "findings": len(r.findings), "skipped": r.skipped,
                   "error": r.error, "seconds": round(r.seconds, 1)} for r in runs],
        "summary": summary(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=1, sort_keys=False) + "\n"


def summary(findings: list[Finding]) -> dict:
    return {
        "total": len(findings),
        "by_priority": {p: sum(f.priority == p for f in findings) for p in PRIORITIES},
        "by_category": dict(sorted(Counter(f.category for f in findings).items())),
        "new": sum(1 for f in findings if f.new),
    }


def to_sarif(runs: list[ToolRun], tool_version: str) -> str:
    """SARIF 2.1.0, one run per tool, so GitHub code scanning can file each separately.

    A tool that did not run (skipped or crashed) is a run with `executionSuccessful:
    false` and NO `results` key. SARIF 2.1.0 (§3.14.23) reads an absent `results` as "the
    tool could not produce results" and an empty array as "it looked and found nothing";
    writing `[]` for a crash would tell a consumer every earlier alert was fixed.
    """
    sarif_runs = []
    for run in runs:
        driver = {"name": f"repolens/{run.tool}", "version": tool_version,
                  "informationUri": "https://github.com/"}
        if run.skipped or run.error:
            sarif_runs.append({"tool": {"driver": driver}, "invocations": [{
                "executionSuccessful": False,
                "toolExecutionNotifications": [{"level": "error" if run.error else "note",
                                                "message": {"text": run.error or run.skipped}}],
            }]})
            continue
        rules: dict[str, dict] = {}
        worst: dict[str, str] = {}
        results = []
        # Repeats share a fingerprint; the ordinal keeps GitHub from merging N alerts into one.
        ordinal: Counter[str] = Counter()
        for f in sorted(run.findings, key=sort_key):
            rule = rules.setdefault(f.rule, {
                "id": f.rule,
                "shortDescription": {"text": f.rule},
                "help": {"text": f.remedy or f.rule},
                "properties": {"tags": [f.category], "precision": f.confidence},
            })
            if f.category == "security":
                # A rule carries ONE severity: its worst result's, not the last written.
                if _SEVERITY_WEIGHT[f.severity] > _SEVERITY_WEIGHT.get(worst.get(f.rule, "info"), 0) \
                        or f.rule not in worst:
                    worst[f.rule] = f.severity
                rule["properties"]["security-severity"] = _SECURITY_SEVERITY[worst[f.rule]]
            result = {
                "ruleId": f.rule,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.message + (f"\nRemedy: {f.remedy}" if f.remedy else "")},
                "partialFingerprints": {"repolens/v1": f"{f.fingerprint}:{ordinal[f.fingerprint]}"},
                "properties": {"severity": f.severity, "confidence": f.confidence,
                               "priority": f.priority, "category": f.category,
                               "exposure": f.exposure},
            }
            ordinal[f.fingerprint] += 1
            if f.file:
                location = {"artifactLocation": {"uri": f.file}}
                if f.line > 0:
                    location["region"] = {"startLine": f.line}
                result["locations"] = [{"physicalLocation": location}]
            results.append(result)
        sarif_runs.append({
            "tool": {"driver": {**driver, "rules": list(rules.values())}},
            "invocations": [{"executionSuccessful": True}],
            "results": results,
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": sarif_runs,
    }, indent=1) + "\n"


def _cell(text: str, width: int = 160) -> str:
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= width else text[: width - 1] + "…"


def to_markdown(runs: list[ToolRun], meta: dict, per_rule_cap: int = 15) -> str:
    findings = sorted((f for r in runs for f in r.findings), key=sort_key)
    s = summary(findings)
    lines = [f"# {meta.get('title', 'repolens report')}", ""]
    lines.append(f"Tree `{meta.get('commit', '?')}` · {s['total']} findings"
                 + (f" · **{s['new']} new** against the baseline" if meta.get("baseline") else
                    " · no baseline (every finding is unclassified)"))
    lines += ["", "Priority blends severity (how bad if real), confidence (how likely real) "
              "and exposure (who can reach it). Heuristic detectors say LOW confidence rather "
              "than a lower severity — triage them, do not trust them.", ""]

    lines += ["## Summary", "", "| priority | " + " | ".join(sorted(s["by_category"])) + " | total |",
              "|---|" + "---|" * (len(s["by_category"]) + 1)]
    for p in PRIORITIES:
        row = [sum(1 for f in findings if f.priority == p and f.category == c) for c in sorted(s["by_category"])]
        lines.append(f"| **{p}** | " + " | ".join(str(n) for n in row) + f" | {s['by_priority'][p]} |")

    lines += ["", "## Tools", "", "| tool | findings | status | seconds |", "|---|---|---|---|"]
    for run in runs:
        status = ("SKIPPED — " + run.skipped) if run.skipped else ("ERROR — " + run.error) if run.error else "ran"
        lines.append(f"| {run.tool} | {len(run.findings)} | {_cell(status, 120)} | {run.seconds:.1f} |")

    for p in PRIORITIES:
        group = [f for f in findings if f.priority == p]
        if not group:
            continue
        lines += ["", f"## {p} — {len(group)} finding(s)", ""]
        by_rule: dict[str, list[Finding]] = {}
        for f in group:
            by_rule.setdefault(f.rule, []).append(f)
        for rule, items in sorted(by_rule.items(), key=lambda kv: (-max(f.score for f in kv[1]), kv[0])):
            first = items[0]
            lines += [f"### `{rule}` · {first.category} · {first.severity}/{first.confidence}"
                      f" · {len(items)}", ""]
            if first.remedy:
                lines += [f"**Fix:** {first.remedy}", ""]
            lines += ["| | location | finding |", "|---|---|---|"]
            for f in items[:per_rule_cap]:
                flag = "🆕" if f.new else ""
                lines.append(f"| {flag} | `{_cell(f.location, 90)}` | {_cell(f.message)} |")
            if len(items) > per_rule_cap:
                lines.append(f"| | | … {len(items) - per_rule_cap} more in the JSON report |")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"

"""Validate the capability index against the source tree, and publish it.

    repolens owners              # report, and write the artefacts
    repolens owners --check      # CI: new/stale violations or stale artefacts fail
    repolens owners --format json
    repolens owners --impact <concept | owner path | consumer path>
"""
from __future__ import annotations

import warnings
import argparse
import ast
import hashlib
import json
import re
import sys
from functools import cached_property
from pathlib import Path

from ..config import Config, load_config
from ..core.console import utf8_console
from ..core.files import iter_files
from .settings import OwnerSettings, from_config

_LANGUAGES = {"python", "javascript"}

#: The three linkage fields are OPTIONAL, deliberately: requiring every existing
#: concept to be mapped before any could be would mean none ever was. A field that is
#: PRESENT is validated strictly — a consumer path that does not exist is a linkage
#: claim that is already false.
_LINKAGE_FIELDS = ("consumers", "featuretrace_tags", "metric_id")


def _detect_pattern(entry: dict) -> str | None:
    detect = entry.get("detect")
    if detect is None:
        return None
    if isinstance(detect, str):
        return detect
    if isinstance(detect, dict) and detect.get("kind", "regex") == "regex":
        return detect.get("pattern")
    return None


def _language(entry: dict) -> str:
    return entry.get("language") or "python"


def _docstring_lines(tree: ast.AST) -> set[int]:
    """Line numbers occupied by docstrings.

    Prose that quotes a banned pattern in order to warn against it is not an instance
    of it. Without this, the module documenting why a pattern must not be
    re-implemented is reported as a re-implementation, and the fix a reader reaches
    for is to delete the warning.
    """
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            lines.update(range(first.lineno, getattr(first, "end_lineno", first.lineno) + 1))
    return lines


def _javascript_symbol_from_line(line: str) -> str | None:
    patterns = (
        r"\bexport\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\b",
        r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\b",
        r"\bexport\s+(?:default\s+)?class\s+([A-Za-z_$][\w$]*)\b",
        r"\bclass\s+([A-Za-z_$][\w$]*)\b",
        r"\bexport\s+const\s+([A-Za-z_$][\w$]*)\b",
        r"\bexport\s+let\s+([A-Za-z_$][\w$]*)\b",
    )
    for pattern in patterns:
        m = re.search(pattern, line)
        if m:
            return m.group(1)
    return None


class OwnerRegistry:
    """One scan of one tree. Sources and parse trees are cached for the life of the
    instance: the tree does not change within a run, and a test module scans it once
    per concept."""

    def __init__(self, settings: OwnerSettings):
        self.s = settings
        self._sources: dict[Path, str] = {}
        self._trees: dict[Path, ast.AST | None] = {}
        self._py_lines: dict[Path, tuple[tuple[int, str], ...]] = {}
        self._js_lines: dict[Path, tuple[tuple[int, str], ...]] = {}

    def load_registry(self) -> dict:
        """Read the YAML registry, exiting with an actionable message if it cannot be used.

        Raises `SystemExit` when PyYAML is missing or the document is not a mapping
        with a `concepts` key.
        """
        try:
            import yaml
        except ImportError:
            # One line the user can act on, not a traceback. The report runner turns this
            # into a SKIPPED tool; `repolens owners` exits 1 with it.
            raise SystemExit(f"{self.s.registry} is YAML and PyYAML is not installed: "
                             "pip install PyYAML (or pip install 'repolens[yaml]')") from None

        data = yaml.safe_load(self.s.registry.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "concepts" not in data:
            raise SystemExit(f"{self.s.registry} must be a mapping with a 'concepts' key")
        return data

    # ── Files ────────────────────────────────────────────────────────────────

    # SORTED, and that is the gate working rather than a tidy-up. `rglob` yields in
    # filesystem order, which differs between platforms; violation lists are emitted
    # in scan order, so an unsorted walk renders byte-different artefacts from an
    # identical tree and `--check` passes on one machine and fails on another.
    # Sorted on the POSIX string, as the original script did, rather than on `Path`:
    # the two orders differ where a name sorts against a separator ("a-b/x" vs "a/x"),
    # and the violation lists this feeds are committed.
    @cached_property
    def python_files(self) -> tuple[Path, ...]:
        """Python files under `python_roots`, minus skipped parts, in POSIX-string order."""
        found = iter_files(self.s.root, self.s.python_roots, [".py"], self.s.skip_parts)
        return tuple(sorted(found, key=lambda p: p.as_posix()))

    @cached_property
    def javascript_files(self) -> tuple[Path, ...]:
        """JS/TS files under `javascript_roots`, minus skipped parts, in POSIX-string order."""
        found = iter_files(self.s.root, self.s.javascript_roots,
                           self.s.javascript_extensions, self.s.skip_parts)
        return tuple(sorted(found, key=lambda p: p.as_posix()))

    def source_files(self, language: str) -> tuple[Path, ...]:
        """The scanned files for `language`; `ValueError` for an unsupported language."""
        if language == "python":
            return self.python_files
        if language == "javascript":
            return self.javascript_files
        raise ValueError(f"unsupported canonical owner language: {language}")

    def _source(self, path: Path) -> str:
        if path not in self._sources:
            try:
                self._sources[path] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:  # deleted or unreadable since the walk: it holds nothing now
                self._sources[path] = ""
        return self._sources[path]

    def _tree(self, path: Path):
        """Parsed once per file per run. None for a file that does not parse — a syntax
        error is not this check's business to report."""
        if path not in self._trees:
            try:
                with warnings.catch_warnings():  # target code's own SyntaxWarnings are not ours to print
                    warnings.simplefilter("ignore")
                    self._trees[path] = ast.parse(self._source(path))
            except (SyntaxError, ValueError, RecursionError):
                self._trees[path] = None
        return self._trees[path]

    def _code_lines(self, path: Path) -> tuple[tuple[int, str], ...]:
        """Source lines that are actually CODE — no whole-line comments, no docstrings."""
        if path not in self._py_lines:
            tree = self._tree(path)
            skip = _docstring_lines(tree) if tree is not None else set()
            self._py_lines[path] = tuple(
                (lineno, raw) for lineno, raw in enumerate(self._source(path).splitlines(), start=1)
                if lineno not in skip and not raw.lstrip().startswith("#")
            )
        return self._py_lines[path]

    def _javascript_code_lines(self, path: Path) -> tuple[tuple[int, str], ...]:
        """Source lines excluding whole-line and block comments.

        Deliberately not a JavaScript parser: cheap and deterministic, behind a
        function boundary that can be upgraded to a real TypeScript AST later. It DOES
        know about string literals: `accept="image/*"` is not the start of a comment, and
        treating it as one hid every following line up to the next `*/` from every
        detector (45 lines of one live file). A `'`/`"` string ends at the line end; a
        template literal may span lines. A regex literal containing `/*` or `//` is still
        misread, and is rare enough to leave.
        """
        if path in self._js_lines:
            return self._js_lines[path]
        out = []
        in_block = False
        in_template = False
        for lineno, line in enumerate(self._source(path).splitlines(), start=1):
            cleaned: list[str] = []
            quote = "`" if in_template else ""
            i, width = 0, len(line)
            while i < width:
                if in_block:
                    end = line.find("*/", i)
                    if end == -1:
                        break
                    in_block = False
                    i = end + 2
                    continue
                ch = line[i]
                if quote:
                    cleaned.append(ch)
                    if ch == "\\" and i + 1 < width:
                        cleaned.append(line[i + 1])
                        i += 2
                        continue
                    if ch == quote:
                        quote = ""
                    i += 1
                    continue
                if ch in "'\"`":
                    quote = ch
                    cleaned.append(ch)
                    i += 1
                    continue
                if line.startswith("//", i):
                    break
                if line.startswith("/*", i):
                    in_block = True
                    i += 2
                    continue
                cleaned.append(ch)
                i += 1
            in_template = quote == "`"
            text = "".join(cleaned)
            if text.strip():
                out.append((lineno, text))
        self._js_lines[path] = tuple(out)
        return self._js_lines[path]

    # ── Delegation and symbols ───────────────────────────────────────────────

    def _delegates_python(self, path: Path, symbol: str, owner_symbols_: list[str]) -> bool:
        """True if `symbol`'s body calls one of the owner's symbols.

        A thin wrapper that forwards to the canonical implementation is the OPPOSITE of
        a second implementation. Flagging it would push people toward inlining the call
        to silence the check, so delegation is recognised, not punished.
        """
        if not owner_symbols_:
            return False
        tree = self._tree(path)
        if tree is None:
            return False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and sub.id in owner_symbols_:
                        return True
                    if isinstance(sub, ast.Attribute) and sub.attr in owner_symbols_:
                        return True
        return False

    def _delegates_javascript(self, path: Path, symbol: str, owner_symbols_: list[str]) -> bool:
        if not owner_symbols_:
            return False
        lines = self._javascript_code_lines(path)
        start = None
        for idx, (_, line) in enumerate(lines):
            if _javascript_symbol_from_line(line) == symbol:
                start = idx
                break
        if start is None:
            return False
        body = "\n".join(line for _, line in lines[start:start + 80])
        return any(re.search(rf"\b{re.escape(owner)}\b", body) for owner in owner_symbols_)

    def delegates(self, language: str, path: Path, symbol: str, owner_symbols_: list[str]) -> bool:
        """True if `symbol` in `path` references an owner symbol, i.e. forwards to it.

        False for an unsupported language. JavaScript is checked textually over the
        first 80 code lines from the symbol's declaration.
        """
        if language == "python":
            return self._delegates_python(path, symbol, owner_symbols_)
        if language == "javascript":
            return self._delegates_javascript(path, symbol, owner_symbols_)
        return False

    def _symbol_at_python(self, path: Path, lineno: int) -> str | None:
        """Name the def/class a hit falls inside, so a violation is reported as
        `module.py:symbol` — stable across edits, unlike a line number."""
        tree = self._tree(path)
        if tree is None:
            return None
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                end = getattr(node, "end_lineno", node.lineno)
                if node.lineno <= lineno <= end:
                    if best is None or node.lineno > best.lineno:
                        best = node
        return best.name if best else None

    def _symbol_at_javascript(self, path: Path, lineno: int) -> str | None:
        best = None
        for current_lineno, line in self._javascript_code_lines(path):
            if current_lineno > lineno:
                break
            symbol = _javascript_symbol_from_line(line)
            if symbol:
                best = symbol
        return best

    def symbol_at(self, language: str, path: Path, lineno: int) -> str | None:
        """Name of the symbol enclosing (Python) or last declared before (JS) `lineno`.

        None when there is none, the file does not parse, or the language is unsupported.
        """
        if language == "python":
            return self._symbol_at_python(path, lineno)
        if language == "javascript":
            return self._symbol_at_javascript(path, lineno)
        return None

    # ── Scanning ─────────────────────────────────────────────────────────────

    def _scan_source_lines(self, entry: dict, owner_defined: list[str],
                           paths: tuple[Path, ...], code_lines) -> list[dict]:
        """Every second implementation of one concept, excluding its allowlist. A hit
        inside a symbol that CALLS the canonical implementation is dropped."""
        detect = _detect_pattern(entry)
        if not detect:
            # Deliberately undetectable: a null detector is a recorded verdict that no
            # cheap pattern separates the correct use from the incorrect one.
            return []
        pattern = re.compile(detect.strip(), re.VERBOSE if "\n" in detect else 0)
        allow = {a.strip() for a in entry.get("allow") or []}
        canonical = entry.get("symbols") or owner_defined
        language = _language(entry)
        hits: list[dict] = []
        for path in paths:
            # POSIX, never `str()`: the YAML is the interface and it is written with
            # forward slashes, so on Windows `str()` matched no allowlist entry.
            rel = self.s.rel(path)
            if rel in allow:
                continue
            for lineno, line in code_lines(path):
                m = pattern.search(line)
                if not m:
                    continue
                symbol = self.symbol_at(language, path, lineno) or "<module>"
                if symbol != "<module>" and self.delegates(language, path, symbol, canonical):
                    continue
                hits.append({
                    "file": rel, "line": lineno, "symbol": symbol,
                    "key": f"{rel}:{symbol}", "match": m.group(0).strip()[:80],
                })
        return hits

    def scan(self, entry: dict, owner_defined: list[str]) -> list[dict]:
        """Detector hits for one concept across the files of its language.

        Each hit is a dict with `file`, `line`, `symbol`, `key` and `match`. Empty for
        an unsupported language or a concept with no detector.
        """
        language = _language(entry)
        if language == "python":
            return self._scan_source_lines(entry, owner_defined, self.python_files, self._code_lines)
        if language == "javascript":
            return self._scan_source_lines(entry, owner_defined, self.javascript_files,
                                           self._javascript_code_lines)
        return []

    def owner_symbols(self, entry: dict) -> tuple[bool, list[str]]:
        """(owner module exists, symbols it actually defines at top level)."""
        owner = self.s.root / entry["owner"]
        if not owner.exists():
            return False, []
        language = _language(entry)
        if language == "python":
            tree = self._tree(owner)
            if tree is None:
                return True, []
            names: list[str] = []
            for n in tree.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.append(n.name)
                # Module-level CONSTANTS count: several concepts are owned BY a value —
                # a canonical vocabulary or role set — not by a function.
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    names.append(n.target.id)
                elif isinstance(n, ast.Assign):
                    names.extend(t.id for t in n.targets if isinstance(t, ast.Name))
            return True, names
        if language == "javascript":
            symbols = []
            for _, line in self._javascript_code_lines(owner):
                symbol = _javascript_symbol_from_line(line)
                if symbol:
                    symbols.append(symbol)
            return True, symbols
        return True, []

    # ── Schema ───────────────────────────────────────────────────────────────

    def validate_schema(self, data: dict) -> list[str]:
        """Structural problems in the loaded registry, one message per problem; empty if valid."""
        out = []
        concepts = data.get("concepts")
        if not isinstance(concepts, list):
            return ["registry must contain a list named concepts"]
        seen = set()
        for idx, entry in enumerate(concepts):
            name = entry.get("concept")
            label = name or f"entry #{idx + 1}"
            if not name:
                out.append(f"{label}: missing concept")
            elif name in seen:
                out.append(f"{label}: duplicate concept")
            seen.add(name)
            language = _language(entry)
            if language not in _LANGUAGES:
                out.append(f"{label}: unsupported language {language!r}")
            for field in ("owner", "symbols", "rule", "why", "allow", "known_violations", "tests"):
                if field not in entry:
                    out.append(f"{label}: missing {field}")
            if "detect" not in entry:
                out.append(f"{label}: missing detect (use null only after recording why)")
            detect = entry.get("detect")
            if isinstance(detect, dict) and detect.get("kind", "regex") != "regex":
                out.append(f"{label}: unsupported detect kind {detect.get('kind')!r}")
            if detect is not None and not _detect_pattern(entry):
                out.append(f"{label}: detect must be a regex string or a {{kind, pattern}} object")
            out.extend(self._validate_linkage(entry, label))
        return out

    def _validate_linkage(self, entry: dict, label: str) -> list[str]:
        """Shape-check `consumers:`, `featuretrace_tags:` and `metric_id:`.

        These answer the question no reachability artefact can: *who else publishes
        this concept, and must move with it?*
        """
        problems: list[str] = []

        consumers = entry.get("consumers")
        if consumers is not None:
            if not isinstance(consumers, list):
                problems.append(f"{label}: consumers must be a list")
            else:
                for pos, consumer in enumerate(consumers, start=1):
                    where = f"{label}: consumers[{pos}]"
                    if not isinstance(consumer, dict):
                        problems.append(f"{where} must be a mapping with path and surface")
                        continue
                    path = consumer.get("path")
                    if not path:
                        problems.append(f"{where} missing path")
                    elif not (self.s.root / path).exists():
                        # A wrong edge is worse than a missing one: it is read as coverage.
                        problems.append(f"{where} path does not exist: {path}")
                    if not consumer.get("surface"):
                        problems.append(
                            f"{where} missing surface — name what a USER sees, not the "
                            f"module; that is what makes the impact list readable"
                        )

        tags = entry.get("featuretrace_tags")
        if tags is not None and (
            not isinstance(tags, list) or not all(isinstance(t, str) and t for t in tags)
        ):
            problems.append(f"{label}: featuretrace_tags must be a list of tag strings")

        metric_id = entry.get("metric_id")
        if metric_id is not None:
            if not isinstance(metric_id, str):
                problems.append(f"{label}: metric_id must be a string")
            elif not self.s.metric_registry:
                problems.append(f"{label}: metric_id {metric_id!r} given, but no [owners] "
                                f"metric_registry is configured to check it against")
            elif metric_id not in self.known_metric_ids:
                problems.append(f"{label}: metric_id {metric_id!r} is in no MetricDefinition "
                                f"in {self.s.metric_registry}")
        return problems

    @cached_property
    def known_metric_ids(self) -> frozenset[str]:
        """Every metric id declared in the configured metric registry.

        Read by pattern rather than imported, so this gate needs no installed
        application dependencies to validate a string.
        """
        path = self.s.root / self.s.metric_registry if self.s.metric_registry else None
        if path is None or not path.exists():
            return frozenset()
        return frozenset(re.findall(self.s.metric_id_pattern, path.read_text(encoding="utf-8")))

    # ── Evaluation ───────────────────────────────────────────────────────────

    def evaluate(self, data: dict) -> dict:
        """Check every concept against the tree and return the content-stamped report.

        Per concept: whether the owner exists, which declared symbols it no longer
        defines, and found/new/resolved violations compared with `known_violations`.
        """
        results = []
        for entry in data["concepts"]:
            exists, defined = self.owner_symbols(entry)
            missing = [x for x in entry.get("symbols") or [] if x not in defined]
            hits = self.scan(entry, defined)
            # Deduped by key: one symbol re-implementing a concept is ONE violation,
            # however many of its lines match.
            found = sorted({h["key"] for h in hits})
            known = sorted(entry.get("known_violations") or [])
            results.append({
                "concept": entry["concept"],
                "language": _language(entry),
                "owner": entry["owner"],
                "owner_exists": exists,
                "symbols": entry.get("symbols") or [],
                "missing_symbols": missing,
                "rule": " ".join((entry.get("rule") or "").split()),
                "why": " ".join((entry.get("why") or "").split()),
                "tests": entry.get("tests") or [],
                "detectable": bool(_detect_pattern(entry)),
                "known_violations": known,
                "found_violations": found,
                "new_violations": [k for k in found if k not in known],
                "resolved_violations": [k for k in known if k not in found],
                "detail": hits,
                # Absent on entries that predate the field, so the artefacts must render
                # "not mapped" rather than "no consumers" — different states.
                "consumers": entry.get("consumers"),
                "featuretrace_tags": entry.get("featuretrace_tags"),
                "metric_id": entry.get("metric_id"),
            })
        return _stamped({
            "registry": self.s.rel(self.s.registry),
            "version": data.get("version", 1),
            "debt_ceiling": data.get("debt_ceiling") or {},
            "concepts": results,
            "known_violations_by_language": {
                language: sum(len(c["known_violations"]) for c in results if c["language"] == language)
                for language in sorted({c["language"] for c in results})
            },
        })

    def problems(self, report: dict, schema_problems: list[str] | None = None) -> list[str]:
        """Messages for everything that fails `--check` in an evaluated report.

        Missing owners or symbols, named tests that do not exist, new violations and
        fixed violations still listed as known, after any `schema_problems` given.
        """
        registry = self.s.rel(self.s.registry)
        out = list(schema_problems or [])
        for c in report["concepts"]:
            if not c["owner_exists"]:
                out.append(f"[{c['concept']}] owner module does not exist: {c['owner']}")
            for x in c["missing_symbols"]:
                out.append(
                    f"[{c['concept']}] {c['owner']} no longer defines {x!r} — callers will "
                    f"roll their own again, which is how this comes back"
                )
            for t in c["tests"]:
                if not (self.s.root / t).exists():
                    out.append(
                        f"[{c['concept']}] names a test that does not exist: {t}. An entry "
                        f"whose enforcement has been deleted is worse than no entry."
                    )
            for v in c["new_violations"]:
                out.append(
                    f"[{c['concept']}] SECOND IMPLEMENTATION: {v}\n"
                    f"      Rule: {c['rule']}\n"
                    f"      Use {c['owner']} instead. Do not add it to known_violations."
                )
            for v in c["resolved_violations"]:
                out.append(
                    f"[{c['concept']}] {v} is fixed but still listed in known_violations — "
                    f"remove it from {registry} so the ratchet holds"
                )
        return out

    def rendered(self, report: dict) -> list[tuple[Path, str]]:
        """(path, body) for every configured artefact."""
        out = [(self.s.out_json, render_json(report))]
        if self.s.out_html:
            out.append((self.s.out_html, render_html(report, self.s)))
        if self.s.out_mindmap:
            out.append((self.s.out_mindmap, render_mindmap(report, self.s)))
        return out


def _stamped(report: dict) -> dict:
    """Add a CONTENT hash, deliberately in place of a wall clock.

    The artefacts are committed. A clock made every regeneration dirty the tree and
    made every two branches conflict on a line carrying no information. The hash says
    the one useful thing a timestamp stood in for — WHICH TREE is this? — and is
    computed over the report EXCLUDING itself, so re-hashing a written artefact
    reproduces it.
    """
    payload = json.dumps(report, sort_keys=True, ensure_ascii=False)
    return {**report, "content_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest()}


# ── Rendering ────────────────────────────────────────────────────────────────

def render_text(report: dict) -> str:
    """Console summary of a report: per-concept state, debt, new and stale violations."""
    lines = ["", "=" * 92, "CANONICAL OWNER REGISTRY — one concept, one owner", "=" * 92]
    for c in report["concepts"]:
        debt = len(c["known_violations"])
        state = "CLEAN" if not debt and not c["new_violations"] else f"{debt} known"
        if c["new_violations"]:
            state = f"FAIL +{len(c['new_violations'])} new"
        lines.append(f"\n  {c['concept']:<32} {state} [{c['language']}]")
        lines.append(f"    owner   {c['owner']}")
        if c["symbols"]:
            lines.append(f"    symbols {', '.join(c['symbols'])}")
        lines.append(f"    rule    {c['rule'][:200]}")
        for v in c["known_violations"]:
            lines.append(f"      debt  {v}")
        for v in c["new_violations"]:
            lines.append(f"      NEW   {v}   <-- fails the build")
        for v in c["resolved_violations"]:
            lines.append(f"      STALE {v}   <-- fixed; delete from the registry")
    total_debt = sum(len(c["known_violations"]) for c in report["concepts"])
    by_language = ", ".join(
        f"{language}: {count}"
        for language, count in report.get("known_violations_by_language", {}).items()
    )
    lines += ["", "-" * 92,
              f"  {len(report['concepts'])} concepts   {total_debt} recorded violations "
              f"(this number may only go down)",
              f"  by language: {by_language}", "-" * 92, ""]
    return "\n".join(lines)


def render_json(report: dict) -> str:
    """The report as indented JSON, the body of the `out_json` artefact."""
    return json.dumps(report, indent=2)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(report: dict, s: OwnerSettings) -> str:
    """Standalone HTML page for the `out_html` artefact, one card per concept."""
    rows = []
    for c in report["concepts"]:
        debt = "".join(f"<li><code>{_esc(v)}</code></li>" for v in c["known_violations"])
        badge = ("clean" if not c["known_violations"] else "debt")
        if c["new_violations"]:
            badge = "fail"
        rows.append(f"""
    <article class="concept {badge}" data-language="{_esc(c['language'])}">
      <h3>{_esc(c['concept'])} <span>{_esc(c['language'])}</span></h3>
      <p class="rule">{_esc(c['rule'])}</p>
      <dl>
        <dt>Owner</dt><dd><code>{_esc(c['owner'])}</code></dd>
        <dt>Symbols</dt><dd>{', '.join(f'<code>{_esc(x)}</code>' for x in c['symbols']) or '<em>n/a</em>'}</dd>
        <dt>Enforced by</dt><dd>{', '.join(f'<code>{_esc(t)}</code>' for t in c['tests'])}</dd>
      </dl>
      <details><summary>Why one owner</summary><p>{_esc(c['why'])}</p></details>
      {f'<details><summary>Recorded debt ({len(c["known_violations"])})</summary><ul>{debt}</ul></details>' if debt else '<p class="ok">No second implementation.</p>'}
    </article>""")
    total_debt = sum(len(c["known_violations"]) for c in report["concepts"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(s.title)}</title>
<style>
 :root{{--ink:#2F4F4F;--accent:#E07A5F;--sand:#F2CC8F;--bg:#fbfaf8;--line:#e6e1d8}}
 body{{margin:0;padding:2.5rem 1.5rem;background:var(--bg);color:#23302f;
   font:16px/1.65 Inter,system-ui,sans-serif;max-width:66rem;margin-inline:auto}}
 h1{{font-family:Manrope,sans-serif;color:var(--ink);margin:0 0 .3rem;font-size:1.9rem}}
 .sub{{color:#6b7876;margin:0 0 2rem}}
 .lede{{border-left:3px solid var(--accent);padding:.2rem 0 .2rem 1rem;margin:0 0 2rem;color:#41514f}}
 .concept{{background:#fff;border:1px solid var(--line);border-radius:12px;
   padding:1.1rem 1.3rem;margin:0 0 1rem;box-shadow:0 1px 2px rgba(0,0,0,.04)}}
 .concept h3{{margin:0 0 .4rem;font-family:Manrope,sans-serif;color:var(--ink);font-size:1.1rem}}
 .concept h3 span{{display:inline-block;margin-left:.35rem;padding:.05rem .35rem;border-radius:4px;
   background:#edf2f1;color:#4c5b59;font:700 .68rem/1.3 Inter,system-ui,sans-serif;text-transform:uppercase}}
 .concept.clean{{border-left:4px solid #4d8b6f}} .concept.debt{{border-left:4px solid var(--sand)}}
 .concept.fail{{border-left:4px solid var(--accent)}}
 .rule{{margin:.2rem 0 .8rem;color:#41514f}}
 dl{{display:grid;grid-template-columns:8rem 1fr;gap:.25rem .8rem;margin:.6rem 0;font-size:.92rem}}
 dt{{color:#6b7876}} dd{{margin:0}}
 code{{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.86em;
   background:#f3f1ec;padding:.1rem .35rem;border-radius:4px}}
 details{{margin-top:.5rem;font-size:.92rem}} summary{{cursor:pointer;color:var(--ink)}}
 details p,details ul{{margin:.5rem 0 0;color:#41514f}} .ok{{color:#4d8b6f;font-size:.9rem;margin:.5rem 0 0}}
 footer{{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--line);
   color:#8a9694;font-size:.85rem}}
 @media(max-width:620px){{dl{{grid-template-columns:1fr}}}}
</style></head><body>
<h1>Canonical Owner Registry</h1>
<p class="sub">One concept, one owner — {len(report['concepts'])} concepts, {total_debt} recorded violations.</p>
<p class="lede">A call graph answers <em>what calls what</em>. It cannot answer
<em>does this concept already have an owner?</em> — a re-implementation creates no edge
to the original, so every map renders it as healthy new code. This consolidated
index closes that gap across backend Python and frontend TypeScript/JavaScript:
a second implementation fails the build.</p>
<section class="lede">
  <strong>How to add an entry:</strong> name the concept, pick one owner module,
  list the symbols callers use, write a reviewer-applicable rule, cite the
  incident/risk, add a precise detector, and record exact existing debt only.
</section>
{''.join(rows)}
<footer>Content <code>{_esc(report.get('content_sha256', '')[:12] or 'unknown')}</code> from <code>{_esc(report['registry'])}</code>
 by <code>{_esc(s.generator_label)}</code>. Do not edit by hand.</footer>
</body></html>
"""


def render_mindmap(report: dict, s: OwnerSettings) -> str:
    """Markdown with a Mermaid mindmap of concepts, owners and debt, for `out_mindmap`."""
    lines = ["# Canonical owners — capability index", "",
             f"> Generated by `{s.generator_label}`. Do not edit.",
             "", "```mermaid", "mindmap", "  root((one concept<br/>one owner))"]
    for c in report["concepts"]:
        lines.append(f"    {c['concept']}")
        lines.append(f"      {c['language']}: {Path(c['owner']).name}")
        for x in c["symbols"][:4]:
            lines.append(f"        {x}")
        if c["known_violations"]:
            lines.append(f"      debt: {len(c['known_violations'])}")
    lines += ["```", ""]
    return "\n".join(lines)


# ── Impact ───────────────────────────────────────────────────────────────────

def report_impact(data: dict, subject: str) -> int:
    """Answer "I am about to change this — what moves with it?".

    A re-implementation creates no call edge and a FeatureTrace `Related:` only links
    files inside one tag, so no graph can list the surfaces that publish a shared
    concept. `consumers:` is a DECLARED edge for that reason.

    Accepts a concept name or a repo-relative path; a path matches whether it is the
    OWNER of a concept or one of its consumers. Advisory: it prints what to review and
    decides nothing. The failure being prevented is *nobody looked*.
    """
    concepts = data["concepts"]
    subject_norm = subject.strip().rstrip("/")

    as_concept = [c for c in concepts if c.get("concept") == subject_norm]
    as_owner = [c for c in concepts if c.get("owner") == subject_norm]
    as_consumer = [
        c for c in concepts
        if any((con or {}).get("path") == subject_norm for con in (c.get("consumers") or []))
    ]

    matched = as_concept or (as_owner + as_consumer)
    if not matched:
        print(f"\n  No registered concept matches {subject!r}.")
        print("  That is not the same as 'no impact': the index is REACTIVE, and an")
        print("  unregistered concept has no entry until somebody writes one. If what")
        print("  you are changing will be reused, add an entry in the same PR.\n")
        print("  Concepts:  " + ", ".join(sorted(c["concept"] for c in concepts)))
        return 1

    print()
    print("=" * 92)
    print(f"IMPACT — {subject_norm}")
    print("=" * 92)

    for entry in as_concept or as_owner:
        _print_impact_entry(entry, role="you are changing the OWNER of this concept")
    for entry in as_consumer:
        if entry in (as_concept or as_owner):
            continue
        _print_impact_entry(entry, role="this file is a declared CONSUMER of this concept")

    print()
    print("  Nothing here is automatic. Read the rule, then decide per surface whether")
    print("  it must change with you. A consumer you deliberately leave alone is a fine")
    print("  answer; a consumer nobody looked at is the failure this list exists to stop.")
    print()
    return 0


def _print_impact_entry(entry: dict, *, role: str) -> None:
    consumers = entry.get("consumers")
    print()
    print(f"  concept   {entry['concept']}   [{_language(entry)}]")
    print(f"            {role}")
    print(f"  owner     {entry['owner']}")
    print(f"  symbols   {', '.join(entry.get('symbols') or []) or '(none listed)'}")
    print()
    print("  RULE      " + _wrap(entry.get("rule") or "(none)", 12))
    if entry.get("metric_id"):
        print(f"  metric    {entry['metric_id']}")
    if entry.get("featuretrace_tags"):
        print(f"  tags      {', '.join(entry['featuretrace_tags'])}")

    print()
    if consumers is None:
        # Unmapped and empty are different states: an entry written before
        # `consumers:` existed has not been checked and found to have none.
        print("  CONSUMERS not mapped — this concept predates the consumers edge.")
        print("            Absence of a list is NOT evidence of no consumers.")
    elif not consumers:
        print("  CONSUMERS none declared.")
    else:
        print(f"  CONSUMERS {len(consumers)} surface(s) publish this concept:")
        width = max(len((c or {}).get("path") or "") for c in consumers)
        for consumer in consumers:
            print(f"            {(consumer.get('path') or ''):<{width}}  {consumer.get('surface') or ''}")
    if entry.get("tests"):
        print()
        print("  TESTS     " + "\n            ".join(entry["tests"]))


def _wrap(text: str, indent: int, width: int = 78) -> str:
    words, lines, current = " ".join(text.split()).split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return ("\n" + " " * indent).join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None, *, config: Config | None = None,
         settings: OwnerSettings | None = None, prog: str | None = None) -> int:
    """Entry point for `repolens owners`; returns the process exit code.

    Exits 1 without writing anything on schema errors. Otherwise prints the report and
    either writes the artefacts or, under `--check`, fails on violations or stale
    artefacts. `--impact` prints what moves with a concept or path instead.
    """
    utf8_console()
    s = settings or from_config(config or load_config())
    reg = OwnerRegistry(s)
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="Exit non-zero on a new or stale violation. Writes nothing.")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--impact", metavar="CONCEPT|PATH",
                    help="What moves with this? Give a concept name or a repo-relative "
                         "file path; prints the owner, the rule, and every surface that "
                         "publishes the concept. Writes nothing.")
    args = ap.parse_args(argv)

    data = reg.load_registry()
    schema_issues = reg.validate_schema(data)

    if schema_issues:
        # BAIL BEFORE RENDERING ANYTHING. A schema error means the concept list could
        # not be evaluated, and every artefact would describe an EMPTY registry —
        # "0 concepts, 0 recorded violations", the most reassuring line this tool can
        # print. A non-zero exit protects CI; printing nothing else protects the person
        # reading a merged `2>&1 | tail`.
        print("\n  REFUSING TO RUN — the registry has schema errors, so no report can be",
              file=sys.stderr)
        print("  produced and nothing was written:", file=sys.stderr)
        for problem in schema_issues:
            print(f"    - {problem}", file=sys.stderr)
        print("\n  Fix the entry above and re-run.", file=sys.stderr)
        return 1

    if args.impact:
        return report_impact(data, args.impact)

    report = reg.evaluate(data)
    issues = reg.problems(report)

    if args.format == "json":
        print(render_json(report))
    else:
        print(render_text(report))

    if args.check:
        if issues:
            print("\nCANONICAL OWNER CHECK FAILED\n", file=sys.stderr)
            for p in issues:
                print(f"  - {p}", file=sys.stderr)
            return 1

        # Staleness is the second half of this gate. Comparing only policy against
        # code let a PR add a concept without regenerating, and the JSON/HTML a reader
        # consults went on describing a registry that no longer existed. Rendering is
        # deterministic, so a byte difference is real drift, never noise.
        stale = [
            s.rel(path) for path, body in reg.rendered(report)
            if not path.exists() or path.read_text(encoding="utf-8") != body
        ]
        if stale:
            print("\nCANONICAL OWNER CHECK FAILED — committed artefacts are stale\n",
                  file=sys.stderr)
            for rel in stale:
                print(f"  - {rel}", file=sys.stderr)
            print("\n  Regenerate in the same commit as the change:", file=sys.stderr)
            print(f"    {s.command}", file=sys.stderr)
            return 1

        print("  canonical owner check: OK (policy and artefacts current)")
        return 0

    for path, body in reg.rendered(report):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        print(f"  wrote {s.rel(path)}")
    if issues:
        # Violations (unlike schema errors) are real debt in a well-formed registry, so
        # the artefacts are still correct and are written. Printed last, so it is the
        # final thing on screen.
        print("\n  NOTE — issues present; `--check` would fail:", file=sys.stderr)
        for p in issues:
            print(f"    - {p}", file=sys.stderr)
    return 0

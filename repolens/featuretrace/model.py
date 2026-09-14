"""The marker grammar: finding `@featuretrace` markers and parsing their blocks."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.files import iter_files as _iter_files
from ..core.files import read_text, read_text_or_none
from .settings import UNKNOWN, FTSettings

MARKER_RE = re.compile(r"@featuretrace:([A-Za-z0-9_.-]+)")
MARKER_PREFIXES = (
    "@featuretrace:",
    "# @featuretrace:",
    "// @featuretrace:",
    "* @featuretrace:",
    "<!-- @featuretrace:",
)
#: Lines read from the marker line onward. Long reasoning belongs in the docstring
#: below the header, not inside it.
PARSE_WINDOW = 20
KNOWN_FIELDS = frozenset(["Layer", "Data flow", "Related", "Toggle", "Collection", "Table", "Tests"])
#: A `Related:` value saying no file was found (`none found (draft)`, which `featuretrace propose` writes
#: because the audit requires the field). It names no file, so it is never an edge or a tour entry.
NO_RELATED_RE = re.compile(r"^none(?: found)?\s*(?:\(draft\))?\.?$", re.IGNORECASE)
_DESCRIPTION_RE = re.compile(r"@featuretrace:[A-Za-z0-9_.-]+\s*[—–-]+\s*(.+)")
_LEADERS = ("#", "//", "*", "<!--")

__all__ = [
    "MARKER_RE", "MARKER_PREFIXES", "MarkerNode", "iter_files", "read_text",
    "parse_marker_block", "scan_all_tags", "scan_for_tag", "split_store_field",
]


@dataclass
class MarkerNode:
    """A single file carrying a `@featuretrace:<tag>` marker."""
    file_path: Path              # absolute path
    tag: str
    description: str             # text after the dash on the marker line
    layer: str                   # from Layer: ("unknown" if absent or unrecognised)
    data_flow_raw: str
    related_raw: list[str]
    toggle: Optional[str]
    collections: list[str]
    tables: list[str]
    tests: list[str]
    line_no: int
    root: Optional[Path] = field(default=None, repr=False, compare=False)

    @property
    def rel_path(self) -> str:
        """The file's path relative to the root (absolute if no root), with forward slashes."""
        # POSIX on every OS: the result is printed into committed maps and compared with
        # `Related:` paths, which are written with forward slashes.
        return (self.file_path.relative_to(self.root) if self.root else self.file_path).as_posix()

    @property
    def short_name(self) -> str:
        """The file's base name."""
        return self.file_path.name

    @property
    def node_id(self) -> str:
        """Safe Mermaid node identifier."""
        return "n_" + re.sub(r"[^A-Za-z0-9]", "_", self.rel_path)

    @property
    def data_flow_steps(self) -> list[str]:
        """Parse 'A → B → C (scope)' into ['A', 'B', 'C (scope)']."""
        if not self.data_flow_raw:
            return []
        return [s.strip() for s in self.data_flow_raw.split("→") if s.strip()]

    def to_dict(self) -> dict:
        """The node as a JSON-serialisable dict, keyed as in the committed graph JSON."""
        return {
            "file": self.rel_path,
            "tag": self.tag,
            "layer": self.layer,
            "description": self.description,
            "data_flow": self.data_flow_raw,
            "related": self.related_raw,
            "toggle": self.toggle,
            "collections": self.collections,
            "tables": self.tables,
            "tests": self.tests,
            "line_no": self.line_no,
        }


def iter_files(settings: FTSettings) -> list[Path]:
    """The files to search for markers: configured dirs and extensions, minus skipped parts."""
    return _iter_files(settings.root, settings.scan_dirs, settings.extensions, settings.skip_parts)


def strip_comment_leader(line: str) -> str:
    """Remove a leading #, //, *, <!-- (and a trailing -->) from a comment line."""
    stripped = line.strip()
    for prefix in _LEADERS:
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):].strip()
    if stripped.endswith("-->"):
        stripped = stripped[:-3].strip()
    return stripped


def extract_field(lines: list[str], field_name: str) -> Optional[str]:
    """The value of the first 'Field: value' line in a block."""
    prefix = f"{field_name}:"
    for line in lines:
        cleaned = strip_comment_leader(line)
        if cleaned.startswith(prefix):
            return cleaned[len(prefix):].strip()
    return None


def content_indent(line: str) -> int:
    """Whitespace columns between a comment leader and the text that follows it.

    `strip_comment_leader` throws this away, and indentation is what separates a
    field's continuation line from ordinary prose under the block, so it is measured
    from the raw line. 0 for a non-comment line.
    """
    stripped = line.lstrip()
    for prefix in _LEADERS:
        if stripped.startswith(prefix):
            rest = stripped[len(prefix):]
            return len(rest) - len(rest.lstrip())
    return 0


def split_store_field(value: str) -> list[str]:
    """Split ONE `Collection:`/`Table:` value into individual store identifiers.

    The one splitter for this field: the audit imports it rather than keeping a copy,
    so the check and the maps can never disagree about what a store list is.

    Splits on `,` and `;` at PAREN DEPTH ZERO only. A naive split is wrong:
    `demo_bank_transactions (read-only, FK resolution)` is a single correct token whose
    qualifier happens to contain the separator, and splitting it yields fragments like
    `FK resolution)` that name nothing. Not splitting at all is wrong the other way —
    several real stores render as one phantom node that nobody searching for any of
    them will find.
    """
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch in ",;" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def extract_multifield(lines: list[str], field_name: str) -> list[str]:
    """Every value for 'Field: value', including its continuation lines.

    A continuation must still be a comment line, must not start another field, and
    must be INDENTED past the field it continues. Without the indent rule, prose that
    merely follows a block — design notes under a `Table:` line — is collected as
    values, and the map then asserts tables that do not exist.
    """
    prefix = f"{field_name}:"
    results: list[str] = []
    collecting = False
    field_indent = 0
    for line in lines:
        cleaned = strip_comment_leader(line)
        if cleaned.startswith(prefix):
            val = cleaned[len(prefix):].strip()
            if val:
                results.append(val)
            collecting = True
            field_indent = content_indent(line)
        elif collecting:
            raw = line.strip()
            # A blank or non-comment line (a docstring delimiter, code) ends the field.
            if not raw or not (raw.startswith("#") or raw.startswith("//")):
                collecting = False
                continue
            if any(cleaned.startswith(f"{k}:") for k in KNOWN_FIELDS) or cleaned.startswith("@featuretrace:"):
                collecting = False
                continue
            # A bare comment line is the paragraph break between the block and prose.
            if not cleaned:
                collecting = False
                continue
            if content_indent(line) <= field_indent:
                collecting = False
                continue
            val = cleaned.strip()
            if val:
                results.append(val)
    return results


def parse_marker_block(settings: FTSettings, path: Path, lines: list[str],
                       marker_line_idx: int, tag: str) -> MarkerNode:
    """Parse the block starting at `marker_line_idx` (0-based)."""
    block_lines = lines[marker_line_idx: marker_line_idx + PARSE_WINDOW]

    match = _DESCRIPTION_RE.search(strip_comment_leader(lines[marker_line_idx]))
    description = match.group(1).strip() if match else ""

    # The leading word is the layer. `Layer: test (global)` is a test file — the audit
    # has always accepted it — but matching the WHOLE value rendered it as "unknown",
    # so the map and the audit disagreed about the same line.
    word = re.match(r"[a-z]+", (extract_field(block_lines, "Layer") or "").strip().lower())
    layer = word.group(0) if word and word.group(0) in settings.layers else UNKNOWN

    return MarkerNode(
        file_path=path,
        tag=tag,
        description=description,
        layer=layer,
        data_flow_raw=extract_field(block_lines, "Data flow") or "",
        related_raw=[item for item in extract_multifield(block_lines, "Related") if not NO_RELATED_RE.match(item)],
        toggle=extract_field(block_lines, "Toggle"),
        # One node per STORE, never one per source line.
        collections=[tok for raw in extract_multifield(block_lines, "Collection")
                     for tok in split_store_field(raw)],
        tables=[tok for raw in extract_multifield(block_lines, "Table")
                for tok in split_store_field(raw)],
        tests=extract_multifield(block_lines, "Tests"),
        line_no=marker_line_idx + 1,
        root=settings.root,
    )


def _markers_in(settings: FTSettings, only_tag: str | None = None):
    for path in iter_files(settings):
        text = read_text_or_none(path)
        if not text:
            continue
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            stripped = line.lstrip()
            if not stripped.startswith(MARKER_PREFIXES):
                continue
            match = MARKER_RE.search(stripped)
            if match and (only_tag is None or match.group(1) == only_tag):
                yield parse_marker_block(settings, path, lines, idx, match.group(1))


def scan_for_tag(settings: FTSettings, tag: str) -> list[MarkerNode]:
    """Every parsed marker carrying `tag`, in file order."""
    return list(_markers_in(settings, tag))


def scan_all_tags(settings: FTSettings) -> dict[str, list[MarkerNode]]:
    """Every parsed marker in the repository, grouped by tag."""
    result: dict[str, list[MarkerNode]] = {}
    for node in _markers_in(settings):
        result.setdefault(node.tag, []).append(node)
    return result

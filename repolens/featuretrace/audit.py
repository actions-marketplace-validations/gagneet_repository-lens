"""Audit FeatureTrace markers: complete, near the top of the file, and truthful.

Every marker needs `Data flow:`, `Related:`, `Layer:` and — when the repository
declares scope values — a scope qualifier. Beyond presence, three checks ask whether
what a marker says is TRUE:

* a referenced path must exist in the committed tree (or be deliberately gitignored);
* a `Collection:`/`Table:` value must be a store identifier, not prose;
* a `Related:` target that could carry a marker must carry one, or the edge the marker
  declares is silently dropped from every map.

Quality is ratcheted, not strict: `--check` fails only when a change makes it worse.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from pathlib import Path

from ..config import Config, load_config
from ..core import git
from ..core.files import read_text, read_text_or_none, rel
from ..core.ratchet import Ratchet
from .model import MARKER_PREFIXES, MARKER_RE, iter_files, split_store_field
from .settings import UNKNOWN, FTSettings, from_config

# Longest-first alternation is load-bearing: with `ts` before `tsx`, every `.tsx`
# reference truncates to a `.ts` path that does not exist.
REF_PATH_RE = re.compile(r"[A-Za-z0-9_./-]+\.(?:tsx|ts|jsx|js|py|md|yaml|yml|json|html)\b")

#: A field label at the start of a line, after any comment leader. Bounds the
#: `Related:` list, which continues over indented lines until the next label.
FIELD_LABEL_RE = re.compile(
    r"^\s*(?:[#/*]+|<!--)?\s*(Related|Data flow|Tests|Toggle|Collection|Table|Layer|Scope)\s*:",
    re.IGNORECASE,
)

#: Suffixes that CAN carry a marker. A `Related:` line naming a design note or a
#: policy file is good documentation, not a missing marker.
MARKABLE_SUFFIXES = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs"})

#: A store list: identifiers separated by `,` or `;`, each optionally qualified by a
#: parenthetical. `*` is an explicit wildcard; `a/b/c` is sibling-table shorthand.
STORE_TOKEN_RE = re.compile(r"^(\*|[A-Za-z_][A-Za-z0-9_.\-*/]*)(\s*\([^)]*\))?$")
STORE_FIELD_RE = re.compile(r"^\s*(?:[#*]|//|<!--)?\s*(Collection|Table)s?:\s*(.+?)\s*$", re.M)

#: Lines after the marker line that count as its block. A window, not a walk to the
#: first blank line: widening can only FIND fields, so it can only remove findings.
AUDIT_WINDOW = 20


def is_store_identifier_list(value: str) -> bool:
    """Whether a `Collection:`/`Table:` value is a non-empty list of store identifiers, not prose."""
    parts = split_store_field(value)
    return bool(parts) and all(STORE_TOKEN_RE.match(p) for p in parts)


class AuditContext:
    """One repository's settings plus the per-run caches the checks share."""

    def __init__(self, settings: FTSettings):
        self.settings = settings
        self.root = settings.root
        values = settings.scope_values
        self.scope_re = (
            re.compile(r"\((" + "|".join(re.escape(v) for v in values) + r")\)") if values else None
        )
        names = [name for name in settings.layers if name != UNKNOWN]
        self.layer_re = re.compile(r"Layer:\s*(" + "|".join(re.escape(n) for n in names) + r")",
                                   re.IGNORECASE)
        self._tracked: frozenset[str] | None = None
        self._tag_index: dict[str, frozenset[str]] | None = None

    def iter_files(self) -> list[Path]:
        """The files the audit scans, as selected by the FeatureTrace settings."""
        return iter_files(self.settings)

    @property
    def tracked(self) -> frozenset[str]:
        """Git-tracked repo-relative paths, fetched once per context; empty without git."""
        if self._tracked is None:
            self._tracked = git.tracked_paths(self.root)
        return self._tracked

    def ignored(self, candidates: list[str]) -> set[str]:
        """The subset of `candidates` that `.gitignore` excludes."""
        return git.ignored(self.root, candidates)

    @property
    def tag_index(self) -> dict[str, frozenset[str]]:
        """Every marked file, resolved path -> the tags it carries.

        Built by a flat regex pass rather than from `Marker` objects, because
        `Marker.issues` consults this index and building markers here would recurse.
        """
        if self._tag_index is None:
            index: dict[str, set[str]] = {}
            for path in self.iter_files():
                try:
                    text = read_text(path)
                except OSError:
                    continue
                if "@featuretrace:" not in text:
                    continue
                for line in text.splitlines():
                    stripped = line.lstrip()
                    if not stripped.startswith(MARKER_PREFIXES):
                        continue
                    for match in MARKER_RE.finditer(stripped):
                        index.setdefault(path.resolve().as_posix(), set()).add(match.group(1))
            self._tag_index = {k: frozenset(v) for k, v in index.items()}
        return self._tag_index

    def is_ref(self, token: str) -> bool:
        """Whether a path-like token is a repo-relative reference the audit should verify.

        With `ref_prefixes` configured, only tokens starting with one count; otherwise
        any token containing `/` that is not absolute does.
        """
        prefixes = self.settings.ref_prefixes
        if prefixes:
            return token.startswith(prefixes)
        return "/" in token and not token.startswith("/")

    def ref_forms(self, token: str) -> list[str]:
        """A reference may be written from the root or from any configured alt root."""
        return [token, *(f"{alt}/{token}" for alt in self.settings.ref_alt_roots)]


@lru_cache(maxsize=1)
def default_context() -> AuditContext:
    """A cached context for the current repository, used by markers built without one."""
    return AuditContext(from_config(load_config()))


@dataclass(frozen=True)
class Marker:
    """One `@featuretrace:<tag>` marker and the block of lines the audit checks with it."""
    path: Path
    line_no: int
    tag: str
    block: str
    ctx: AuditContext | None = field(default=None, compare=False, repr=False)

    @property
    def _c(self) -> AuditContext:
        return self.ctx if self.ctx is not None else default_context()

    @property
    def has_data_flow(self) -> bool:
        """Whether the block has a `Data flow:` field."""
        return "Data flow:" in self.block

    @property
    def has_related(self) -> bool:
        """Whether the block has a `Related:` field."""
        return "Related:" in self.block

    @property
    def has_scope(self) -> bool:
        """Whether the block names a configured scope qualifier; always true when none are configured."""
        scope_re = self._c.scope_re
        return True if scope_re is None else bool(scope_re.search(self.block))

    @property
    def has_layer(self) -> bool:
        """Whether the block has a `Layer:` naming a configured layer other than `unknown`."""
        return bool(self._c.layer_re.search(self.block))

    @property
    def is_near_top(self) -> bool:
        """Whether the marker sits within `near_top_lines`, or its file may carry section markers."""
        c = self._c
        try:
            relative = self.path.relative_to(c.root).as_posix()
        except ValueError:
            relative = None
        if relative in c.settings.section_marker_files:
            return True
        return self.line_no <= c.settings.near_top_lines

    @property
    def dangling_refs(self) -> list[str]:
        """Referenced paths that exist in the marker and not in the committed tree.

        A `Related:` line names files that must be opened together and a `Tests:` line
        claims proof exists; a rename, a move or a file never written leaves the marker
        asserting something false. A gitignored path is a declared generated output
        and counts as present.
        """
        c = self._c
        tracked = c.tracked
        candidates: list[str] = []
        for token in REF_PATH_RE.findall(self.block):
            if not c.is_ref(token):
                continue
            forms = c.ref_forms(token)
            if any(form in tracked for form in forms):
                continue
            if not tracked and any((c.root / form).exists() for form in forms):
                continue  # no git available: fall back to the filesystem
            candidates.append(token)
        ignored = c.ignored(candidates)
        return [t for t in candidates if t not in ignored]

    @property
    def related_refs(self) -> list[str]:
        """Paths named on the `Related:` line and its continuations — that field only.

        `Related:` is the claim about the chain ("open these together"), so only it
        carries the reciprocity obligation. `Data flow:` may name files that are not
        part of the chain.
        """
        c = self._c
        refs: list[str] = []
        inside = False
        for line in self.block.splitlines():
            label = FIELD_LABEL_RE.match(line)
            if label:
                inside = label.group(1).lower() == "related"
                if not inside:
                    continue
            elif not inside:
                continue
            refs.extend(t for t in REF_PATH_RE.findall(line) if c.is_ref(t))
        return refs

    def _resolved_related(self) -> list[tuple[str, str]]:
        """`Related:` targets that exist and could carry a marker, as (token, path)."""
        c = self._c
        out: list[tuple[str, str]] = []
        for token in self.related_refs:
            for form in c.ref_forms(token):
                candidate = c.root / form
                if candidate.suffix not in MARKABLE_SUFFIXES:
                    continue
                if candidate.exists():
                    out.append((token, candidate.resolve().as_posix()))
                    break
        return out

    @property
    def unmarked_related_refs(self) -> list[str]:
        """`Related:` targets carrying no marker at all — an edge every map drops.

        An ISSUE: deterministic, and every instance is real.
        """
        index = self._c.tag_index
        return [token for token, path in self._resolved_related() if not index.get(path)]

    @property
    def cross_tag_related_refs(self) -> list[tuple[str, str]]:
        """`Related:` targets marked under a DIFFERENT tag, as (token, their tags).

        Reported, never an issue: a chain legitimately crosses features, so failing on
        these would buy an allowlist rather than a fix. They still render as NO edge
        in a per-tag map, which is why the count is printed.
        """
        index = self._c.tag_index
        out: list[tuple[str, str]] = []
        for token, path in self._resolved_related():
            tags = index.get(path)
            if tags and self.tag not in tags:
                out.append((token, ", ".join(sorted(tags))))
        return out

    @property
    def prose_store_values(self) -> list[str]:
        """`Collection:` / `Table:` values that are not store identifiers — phantom stores."""
        return [value for _field, value in STORE_FIELD_RE.findall(self.block)
                if not is_store_identifier_list(value)]

    @cached_property
    def issues(self) -> list[str]:
        """Every problem with this marker as a readable message; empty when it is complete."""
        # One issue per bad reference or value, never one per marker: the ratchet
        # counts issues, so collapsing three into one would let two be re-added
        # after one is fixed without the count moving.
        issues: list[str] = []
        if not self.is_near_top:
            issues.append("marker not near top")
        if not self.has_data_flow:
            issues.append("missing Data flow")
        if not self.has_related:
            issues.append("missing Related")
        if not self.has_scope:
            issues.append("missing scope qualifier")
        if not self.has_layer:
            issues.append("missing Layer (needed for map generation)")
        for token in self.dangling_refs:
            issues.append(f"references a path that does not exist: {token}")
        for value in self.prose_store_values:
            trimmed = value if len(value) <= 60 else value[:57] + "..."
            issues.append(f"Collection:/Table: value is not a store identifier: {trimmed}")
        for token in self.unmarked_related_refs:
            issues.append(f"Related: target carries no @featuretrace marker: {token}")
        return issues


def markers_for(ctx: AuditContext, path: Path, text: str) -> list[Marker]:
    """Every marker in one file's text, each with its `AUDIT_WINDOW`-line block."""
    lines = text.splitlines()
    markers: list[Marker] = []
    for idx, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if not stripped.startswith(MARKER_PREFIXES):
            continue
        for match in MARKER_RE.finditer(stripped):
            block = "\n".join(lines[idx - 1: idx + AUDIT_WINDOW])
            markers.append(Marker(path=path, line_no=idx, tag=match.group(1), block=block, ctx=ctx))
    return markers


def weak_counts(ctx: AuditContext, markers: list) -> dict[str, int]:
    """{file: number of individual issues} — the unit the ratchet locks.

    Per ISSUE rather than per MARKER: a file that swapped one issue for another keeps
    its marker count, but one that gained a second issue must not slip through.
    """
    counts: dict[str, int] = {}
    for marker in markers:
        found = marker.issues
        if found:
            key = rel(marker.path, ctx.root)
            counts[key] = counts.get(key, 0) + len(found)
    return dict(sorted(counts.items()))


def ratchet_for(ctx: AuditContext, baseline_path: Path | None = None) -> Ratchet:
    """The per-file marker-issue ratchet, with failure help built from the repository's settings."""
    s = ctx.settings
    if s.scope_values:
        help_lines = [
            "Every marker needs Data flow, Related, Layer, a scope qualifier",
            "  (" + " | ".join(f"({v})" for v in s.scope_values) + "),",
        ]
    else:
        help_lines = ["Every marker needs Data flow, Related and Layer,"]
    help_lines.append(f"  and must sit within the first {s.near_top_lines} lines of the file.")
    if s.standard_doc:
        help_lines.append(f"See {s.standard_doc}")
    return Ratchet(
        label="FeatureTrace",
        baseline_path=baseline_path or s.baseline,
        root=ctx.root,
        comment=("FeatureTrace ratchet baseline. Per-file count of individual marker issues. "
                 "A file may never INCREASE; a new file must have none. Regenerate with "
                 f"{s.audit_command} --update-baseline and commit alongside the change."),
        update_command=f"{s.audit_command} --update-baseline",
        unit="issue",
        subject="markers",
        regress_reason="marker quality went backwards",
        new_file_note="new markers must be complete",
        failure_help=tuple(help_lines),
    )


def run_ratchet(ctx: AuditContext, markers: list, update: bool,
                baseline_path: Path | None = None) -> int:
    """Check the markers' issue counts against the baseline, or rewrite it when `update`."""
    return ratchet_for(ctx, baseline_path).run(weak_counts(ctx, markers), update)


def main(argv: list[str] | None = None, *, config: Config | None = None,
         context: AuditContext | None = None, baseline_path: Path | None = None,
         prog: str | None = None) -> int:
    """CLI entry point for `featuretrace audit`: print weak markers and return an exit code.

    Returns the ratchet's result under `--check`/`--update-baseline` (2 if combined with
    a tag), 1 under `--strict` when any marker is weak, otherwise 0.
    """
    ctx = context or AuditContext(from_config(config or load_config()))
    parser = argparse.ArgumentParser(prog=prog, description="Audit @featuretrace marker coverage.")
    parser.add_argument("tag", nargs="?", help="Limit audit to one feature tag.")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero when ANY weak marker is found.")
    parser.add_argument("--check", action="store_true",
                        help="Ratchet against the committed baseline: fail only on NEW issues.")
    parser.add_argument("--update-baseline", action="store_true",
                        help="Rewrite the baseline after a genuine improvement.")
    args = parser.parse_args(argv)

    files = ctx.iter_files()
    markers: list[Marker] = []
    candidate_files: list[Path] = []
    mention = (re.compile(rf"(?:@featuretrace:|featuretrace:){re.escape(args.tag)}\b")
               if args.tag else None)

    for path in files:
        text = read_text_or_none(path)
        if text is None:
            continue
        found = markers_for(ctx, path, text)
        if args.tag:
            found = [m for m in found if m.tag == args.tag]
            if (mention and mention.search(text)) or found:
                candidate_files.append(path)
        markers.extend(found)

    weak = [m for m in markers if m.issues]
    tags = sorted({m.tag for m in markers})

    print("FeatureTrace audit")
    print("==================")
    if args.tag:
        print(f"Tag: {args.tag}")
        print(f"Candidate files mentioning tag: {len(candidate_files)}")
    print(f"Scanned files: {len(files)}")
    print(f"Markers found: {len(markers)}")
    print(f"Unique tags: {len(tags)}")
    if tags and not args.tag:
        print("Tags: " + ", ".join(tags))

    if weak:
        print("\nWeak markers")
        for m in weak:
            print(f"- {rel(m.path, ctx.root)}:{m.line_no} [{m.tag}] - {', '.join(m.issues)}")
    else:
        print("\nWeak markers: none")

    cross_tag = [
        (rel(m.path, ctx.root), m.line_no, m.tag, token, their)
        for m in markers
        for token, their in m.cross_tag_related_refs
    ]
    if cross_tag:
        print(f"\nCross-tag Related: edges (reported, not ratcheted): {len(cross_tag)}")
        print("  These render as NO edge in a per-tag map. Not a defect on its own --")
        print("  a chain legitimately crosses features -- but the map is smaller than")
        hint = ctx.settings.concept_index_hint
        if hint:
            print("  the markers suggest. Concept-level linkage lives in")
            print(f"  {hint}.")
        else:
            print("  the markers suggest.")
        if args.tag:
            for path, line_no, tag, token, their in cross_tag:
                print(f"  - {path}:{line_no} [{tag}] -> {token} [{their}]")
        else:
            print("  Pass a tag argument to list them for one feature.")

    if args.tag:
        covered = sorted({m.path for m in markers})
        mentioned_without_marker = sorted(set(candidate_files) - set(covered))
        if covered:
            print("\nCovered files")
            for path in covered:
                print(f"- {rel(path, ctx.root)}")
        if mentioned_without_marker:
            print("\nMention tag but lack matching marker")
            for path in mentioned_without_marker:
                print(f"- {rel(path, ctx.root)}")

    # The ratchet is whole-repository only: with a tag, every other file reads as
    # zero and --update-baseline would rewrite the debt record as one big improvement.
    if (args.check or args.update_baseline) and not args.tag:
        return run_ratchet(ctx, markers, update=args.update_baseline, baseline_path=baseline_path)
    if (args.check or args.update_baseline) and args.tag:
        print("\n--check/--update-baseline operate on the whole repository; "
              "drop the tag argument.")
        return 2

    if weak and args.strict:
        return 1
    return 0

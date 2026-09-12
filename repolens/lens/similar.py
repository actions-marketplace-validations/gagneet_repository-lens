"""Search for an existing implementation BY BEHAVIOUR, before you write a new one.

A capability index only knows the concepts somebody has already registered, so it is
reactive by construction: an entry is written after somebody notices. The lens
reports functions sharing a NAME, but the expensive duplicates share a PURPOSE and
differ in name. This is the search you run before writing, so the notice comes first.

Every function is a bag of what it TOUCHES — the collections and tables it reads, the
functions it calls, and the words in its own name and purpose. Scoring is crude and
transparent: overlap counts, weighted, printed with the evidence. It suggests; it
never decides.

    # before writing a helper — describe what it will do
    --like "resolve the owner name for a unit"

    # ...or name the stores it will touch, which is the stronger signal
    --like "owner name" --touches user_units,users

    # what else looks like this existing function?
    --like-function backend/services/owner_service.py::get_owner_info

    # the standing report: clusters that look like re-implementations
    --clusters
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict

from ..config import Config, load_config
from ..core.console import utf8_console
from .build import load_index
from .settings import LensSettings, from_config

#: Words that carry no signal about what a function DOES. Kept short on purpose: an
#: aggressive stop-list hides the very verbs that distinguish "resolve" from "format".
_STOP = {
    "get", "set", "the", "a", "an", "for", "of", "to", "and", "or", "is", "in", "on",
    "by", "with", "from", "this", "that", "it", "as", "at", "be", "return", "returns",
    "data", "value", "values", "func", "function", "handler", "helper", "util", "utils",
}


def _tokens(text: str) -> set[str]:
    """snake_case, camelCase and prose, all reduced to the same word bag."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(text or ""))
    words = re.split(r"[^a-zA-Z0-9]+", spaced.lower())
    return {w for w in words if len(w) > 2 and w not in _STOP}


def _load(s: LensSettings) -> list[dict]:
    return list(load_index(s)["functions"].values())


def _stores(fn: dict) -> set[str]:
    return {str(x) for x in (fn.get("mongo_collections") or [])} | \
           {str(x) for x in (fn.get("postgres_tables") or [])}


def _profile(fn: dict) -> set[str]:
    """The word bag that stands for what this function is about."""
    return _tokens(fn.get("name")) | _tokens(fn.get("purpose")) | \
           {t for x in _stores(fn) for t in _tokens(x)}


def _score(fn: dict, want_words: set[str], want_stores: set[str],
           want_callees: set[str]) -> tuple[float, list[str]]:
    why: list[str] = []
    score = 0.0

    shared_stores = _stores(fn) & want_stores
    if shared_stores:
        # The strongest signal by far. Two functions reading the same collections are
        # answering questions about the same thing, whatever they are named.
        score += 3.0 * len(shared_stores)
        why.append(f"stores: {', '.join(sorted(shared_stores))}")

    shared_words = _profile(fn) & want_words
    if shared_words:
        score += 1.0 * len(shared_words)
        why.append(f"words: {', '.join(sorted(shared_words)[:6])}")

    shared_callees = {c.split("::")[-1] for c in (fn.get("callees") or [])} & want_callees
    if shared_callees:
        score += 2.0 * len(shared_callees)
        why.append(f"calls: {', '.join(sorted(shared_callees)[:4])}")

    # A function nothing calls is either new, dead, or a duplicate nobody adopted — all
    # three are worth seeing, so this nudges rather than filters.
    if score and not (fn.get("callers") or []):
        score += 0.5
        why.append("no callers")
    return score, why


def _print(fn: dict, score: float, why: list[str]) -> None:
    owner = (fn.get("canonical") or {}).get("owns")
    violates = (fn.get("canonical") or {}).get("violates")
    flag = "  ** REGISTERED OWNER **" if owner else ("  ** REGISTRY VIOLATION **" if violates else "")
    print(f"  [{score:5.1f}] {fn['key']}{flag}")
    if fn.get("purpose"):
        print(f"          {str(fn['purpose'])[:96]}")
    print(f"          {' | '.join(why)}")
    print(f"          callers={len(fn.get('callers') or [])} "
          f"tests={len(fn.get('tests') or [])} layer={fn.get('layer') or '-'}")


def main(argv: list[str] | None = None, *, config: Config | None = None,
         settings: LensSettings | None = None, prog: str | None = None) -> int:
    utf8_console()
    s = settings or from_config(config or load_config())
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--like", help="describe what the new function will do")
    ap.add_argument("--like-function", help="a lens key, or a bare function name")
    ap.add_argument("--touches", default="",
                    help="comma-separated collections/tables it will read (strongest signal)")
    ap.add_argument("--language", choices=["python", "javascript"])
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--clusters", action="store_true",
                    help="report groups that look like re-implementations of each other")
    args = ap.parse_args(argv)

    fns = _load(s)
    if args.language:
        fns = [f for f in fns if f.get("language") == args.language]

    if args.clusters:
        return _clusters(fns, args.limit)

    if not (args.like or args.like_function):
        ap.error("give --like, --like-function, or --clusters")

    want_words: set[str] = _tokens(args.like or "")
    want_stores = {x.strip() for x in args.touches.split(",") if x.strip()}
    want_callees: set[str] = set()
    seed_key = None

    if args.like_function:
        seed = next((f for f in fns if f["key"] == args.like_function), None) or \
               next((f for f in fns if f["name"] == args.like_function), None)
        if not seed:
            print(f"no function matching {args.like_function!r} in the index")
            return 2
        seed_key = seed["key"]
        want_words |= _profile(seed)
        want_stores |= _stores(seed)
        want_callees |= {c.split("::")[-1] for c in (seed.get("callees") or [])}
        print(f"seed: {seed_key}\n")

    scored = []
    for fn in fns:
        if fn["key"] == seed_key:
            continue
        score, why = _score(fn, want_words, want_stores, want_callees)
        if score >= 3.0:
            scored.append((score, fn, why))
    scored.sort(key=lambda t: -t[0])

    print(f"{len(scored)} candidate(s); showing {min(args.limit, len(scored))}\n")
    for score, fn, why in scored[:args.limit]:
        _print(fn, score, why)
        print()

    registry = s.owners_yaml or "your capability index"
    print("  These are CANDIDATES ranked by what they touch, not proof of duplication.")
    print("  Read the top few. If one of them already does the job, call it. If you write")
    print("  a new one anyway and the concept will be reused, add it to")
    print(f"  {registry} in the same PR.")
    return 0


def _clusters(fns: list[dict], limit: int) -> int:
    """Group by the exact set of stores touched — the cheapest honest duplicate signal."""
    by_stores: dict[frozenset, list[dict]] = defaultdict(list)
    for fn in fns:
        stores = frozenset(_stores(fn))
        # Two or more stores, so a cluster means "reads this same combination", not
        # "touches users" — which half a codebase does and which says nothing.
        if len(stores) >= 2:
            by_stores[stores].append(fn)

    clusters = [(st, group) for st, group in by_stores.items() if len(group) > 1]
    clusters.sort(key=lambda t: -len(t[1]))
    print(f"{len(clusters)} store-signature cluster(s) with more than one function\n")
    for stores, group in clusters[:limit]:
        names = {f["name"] for f in group}
        # Same name = the lens already reports it as ambiguous. Different names reading
        # the same combination of stores is the case nothing else surfaces.
        tag = "SAME NAME (lens already flags this)" if len(names) == 1 else "DIFFERENT NAMES"
        print(f"  [{tag}] {', '.join(sorted(stores))}")
        for fn in group[:6]:
            print(f"      {fn['key']}")
        if len(group) > 6:
            print(f"      ... and {len(group) - 6} more")
        print()
    print("  A cluster is not a defect. Several functions legitimately read the same two")
    print("  collections. It is a place to look for the SAME QUESTION asked twice.")
    return 0

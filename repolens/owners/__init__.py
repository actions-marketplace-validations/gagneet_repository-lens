"""The capability index: which concept has exactly one owner, and is that still true.

FeatureTrace, a call graph and a router map all describe what the code DOES. None of
them can answer "does this concept already have an owner?", because a
re-implementation creates no edge to the original — it is a new node with a new name
in a new file, and every map renders it as healthy new code.

So this is an INDEX, not a graph: a hand-curated YAML list of concepts that must have
one owner, each with a detector that finds second implementations. Every entry
carries `known_violations`, the exact debt that exists today; the check fails on a
NEW violation and equally on a listed one that has been fixed but left in the list.
"""

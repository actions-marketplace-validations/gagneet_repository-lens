"""Function Lens: one page of truth per function.

`build` indexes every function in the configured roots — purpose, callers, callees,
routes, guards, stores, the tests that name it — and joins in FeatureTrace tags and
the capability index. `similar` searches that index by behaviour rather than by name.

Call edges are NAME-based, never type-resolved, so a caller list is an upper bound.
The limits travel inside the artefact itself; see `build.CORE_LIMITS`.
"""

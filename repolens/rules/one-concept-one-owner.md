# One concept, one owner

**Rule.** Before writing a helper that resolves, converts, formats, parses or computes
something reusable, check the capability index. If the concept has an owner, call it. If
it has none and the concept will be reused, add an entry in the same change.

## Why

A call graph answers *what calls what*. It cannot answer *does this already exist*,
because a re-implementation is a new function, with a new name, in a new file, calling
nothing the original calls. Every map draws it as healthy new code — correctly, by its own
definition. Uniqueness is not derivable from reachability.

The expensive duplicates share a PURPOSE, not a name. Two functions both called
`to_cents` that disagree about `"10.005"` — one rejects a fractional cent, the other
rounds it — are a money bug that no type checker, linter or test of either function will
ever report. Five functions that each map an account to the thing it owns, under five
names, are five places a rule change must be made and four where it will not be.

## How to apply

1. **Search by behaviour first.** `repolens lens similar --like "<what it does>" --touches
   <the stores it reads>`. Naming the stores is the strongest signal.
2. **Check the index.** `repolens owners --impact <concept>`, or search the registry for
   `concept:`.
3. **Owner found:** call it. **None, and it will be reused:** add an entry —
   `concept` (kebab-case, the idea not the function), `language`, `owner` (one module),
   `symbols` (what callers use), `rule` (one sentence a reviewer can apply without reading
   the code), `why`, `detect`, `allow`, `known_violations`, `tests`, and `consumers` (every
   surface that PUBLISHES the concept's answer, so a change knows what moves with it).

## Rules for the entry itself

- **`known_violations` is debt being paid down, never an escape hatch.** A failing check
  is fixed by calling the owner, not by appending to that list.
- **A detector is worth writing only if it separates correct use from incorrect use.** A
  pattern that matches mostly legitimate code gets allowlisted until it means nothing,
  which is worse than having no detector. `detect: null`, with the reason written down, is
  a valid entry.
- **Removing a symbol from an owner module fails the build.** Callers roll their own the
  moment the canonical entry point disappears.
- **A missing `consumers:` list is not evidence of no consumers.** It means nobody wrote
  them down yet.

## Commands

```bash
repolens owners --check                     # CI: a new second implementation fails
repolens owners --impact <concept|path>     # the owner, the rule, and every consumer
```

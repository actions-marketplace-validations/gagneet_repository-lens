# Look before you edit

**Rule.** Before editing a function you did not write, and before writing any shared
helper, look it up: `repolens lens --lookup <name>`.

The lens is one page per function: its purpose (the docstring), its callers and blast
radius, the guard calls that gate it, the stores it touches, the tests that name it, and
whether its concept already has a registered owner.

## Read its limits before you cite a number

- **Call edges are name-based, not type-resolved.** When several definitions share a name
  the lens marks it `AMBIGUOUS` and its caller list is the union across all of them. Blast
  radius is an upper bound, never proof.
- **"Tested" is a name match** — a test file that mentions the function. It is not
  coverage.
- **JavaScript and TypeScript records are extracted by a regex** over declarations. There
  is no frontend call graph.
- **Everything is read from the source tree.** The lens cannot tell you that the table a
  function reads has never held a row, or that another page computes the same figure with
  a different filter. Before trusting a number a function produces, run it against real
  data and compare it with the other surface that shows the same concept. A disagreement
  is a finding, not a reconciliation.

## What it replaces, and what it does not

The lens joins the capability index in: it prints the owner when a concept has one. It
cannot discover that a concept has an owner the index does not list — see
[one-concept-one-owner](one-concept-one-owner.md).

## Staleness

The full index is a local cache. The committed digest carries a content hash, and
`repolens lens --check` fails when it drifts from the tree. Regenerate in the same change
as the code: a stale lens is a wrong answer a reader will believe.

```bash
repolens lens --lookup <name>      # the page
repolens lens similar --like "<behaviour>"
repolens lens --check              # CI: the committed digest matches the tree
```

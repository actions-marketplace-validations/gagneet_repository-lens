# Generated artefacts: never hand-merge one

**Rule.** A committed file that is derived from the source tree is regenerated, never
merged. On a conflict, take either side and run the generator on the merged tree.

## Why

Two branches that each change code produce two different artefacts, and the correct one
for the merge is NEITHER side: it is whatever the generator produces from the merged
result. A "successful" three-way text merge is worse than a conflict, because it yields a
file that describes neither branch and still looks valid.

Regenerating inside a merge driver does not work either. Git runs a driver per path while
the working tree is still half-applied, so a generator invoked there scans a tree that
does not exist yet. Measured: the result silently lacked one branch's change, and the
merge reported success.

## How it is wired

| part | job |
|---|---|
| `.gitattributes`: `<path> merge=generated` | keep one side — no conflict, no pretence of correctness |
| post-merge / post-rewrite hooks | regenerate from the COMPLETED tree: `repolens artefacts regenerate` |
| the `--check` gate in CI | the backstop: a merge made on the hosting provider runs no client hooks |

```bash
repolens artefacts install-hooks      # once per clone: git config and hooks are not versioned
repolens artefacts regenerate --all   # by hand, after resolving a conflict
repolens artefacts verify             # .gitattributes and [artefacts] rules must name the same files
```

Not installing the hooks breaks nothing: git falls back to an ordinary conflict, which is
the right degradation.

## Determinism is a prerequisite

Never put a timestamp, a hostname, a username or an absolute path into a committed
artefact. A file that changes on every run conflicts on every branch, and — worse — trains
reviewers to skim its diff, so a real change hides behind the daily noise. Stamp a content
hash instead: it says *which tree is this?* and changes only when the content does.

## Two kinds of committed file are NOT regenerated

- **Hand-written policy** (a registry, an exemptions list): regenerating would discard
  what the other branch added. Merge it by hand.
- **Ratchet baselines**: the correct merge is the LOWER of the two sides, per entry.

A generator that cannot run on a machine (a missing interpreter or dependency) is skipped
and reported, never failed: a phantom failure and a real one read identically, and the
message stops being read.

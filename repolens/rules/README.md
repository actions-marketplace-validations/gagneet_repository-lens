# repolens rules

Portable rules for a codebase that more than one person — or agent — changes. Each one
names the question it answers, why the obvious alternative fails, and the command that
enforces it. Nothing here assumes a particular repository.

| rule | the question it answers | enforced by |
|---|---|---|
| [one-concept-one-owner](one-concept-one-owner.md) | does this concept already have an owner? | `repolens owners --check` |
| [look-before-you-edit](look-before-you-edit.md) | what is this function, who calls it, what breaks if it changes? | `repolens lens --lookup`, `repolens lens similar` |
| [featuretrace-markers](featuretrace-markers.md) | what makes up this feature, from the UI to the store? | `repolens featuretrace audit --check` |
| [generated-artefacts](generated-artefacts.md) | is this committed file derived, and how is a conflict on it resolved? | `repolens artefacts verify` |
| [gates-and-ratchets](gates-and-ratchets.md) | does anything run this check, and can it fail? | `repolens gates --check` |
| [findings-report](findings-report.md) | what should be fixed first, and did this change add anything? | `repolens report --check` |
| [docstrings](docstrings.md) | can a reader learn what a public symbol is for without reading its body? | `repolens docs coverage --check` |
| [database-migrations](database-migrations.md) | will this schema change apply to a database with rows, and leave tenant isolation intact? | `repolens report --only migrations` |

**Four tools, four questions — never substitute one for another.** The lens and
FeatureTrace are reachability structures: they answer *what calls what*. Neither can tell
you a concept already has an owner, because a re-implementation creates no edge to the
original — it is new code with a new name, calling nothing the original calls. Only the
capability index answers that, and only because someone wrote the entry down.

And all of them read the source tree only. None can tell you that a table has no rows, a
queue has no consumer, or two pages filter the same data differently. Before trusting a
figure, run it against real data and compare it with the other surface that shows it.

`repolens rules show <name>` prints one rule; `repolens init` copies them into a
repository.

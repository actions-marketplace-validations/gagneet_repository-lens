# FeatureTrace markers

**Rule.** Every primary file in a cross-cutting feature — page, endpoint, service, data
access, worker, scheduled job, test — carries a marker in its first lines:

```text
@featuretrace:<tag> — <one-line role of this file in the feature>
Layer: <frontend|router|service|domain|worker|cron|model|migration|config|docs|seed|script|test>
Data flow: <source> -> <function or endpoint> -> <store or event> (<scope>)
Related: <the other files in this chain>
```

`repolens featuretrace map <tag>` renders the chain as a flowchart, a mind map and a code
tour, in the order a request travels.

## Why

A feature that spans six files is edited one file at a time, and the file nobody opened
is the one that breaks. The marker puts the chain where the next editor — or agent — is
already looking, and the map turns six scattered markers into one picture.

## What a marker cannot answer

- **It declares a data flow; nothing verifies it.** A marker naming a store renders as a
  healthy chain whether or not that store has ever held data or has a writer.
- **It cannot tell you a concept already has an owner.** That is
  [one-concept-one-owner](one-concept-one-owner.md).

## Quality is ratcheted, not merely reported

`repolens featuretrace audit --check` fails on a NEW marker issue — a missing `Data flow:`,
`Related:` or `Layer:`, a missing scope qualifier where the profile requires one, a path
that does not exist, or a marker too far down the file — and also on an un-baselined
improvement, so a fix is locked in rather than silently given back.

Two traps:

- A `Related:` path pointing at a file under a DIFFERENT tag passes the audit and draws
  no edge in either map. If the link matters, mark the file under both tags.
- Paths are checked against the files git tracks. A file you just created reads as
  dangling until it is added.

The maps are generated artefacts: regenerate them in the same change as the markers
(`repolens featuretrace map --check` gates it). See
[generated-artefacts](generated-artefacts.md).

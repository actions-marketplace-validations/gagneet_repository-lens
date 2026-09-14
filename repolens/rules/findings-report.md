# The findings report

**Rule.** One prioritised list, and a change may not add to it. `repolens report --check`
fails on a NEW finding at the configured priority or worse (default P1) with medium or
high confidence, on a tool that crashed, and on a required tool that did not run.

## Three properties, never collapsed into one

| property | question |
|---|---|
| severity | how bad is it, IF it is real? |
| confidence | how likely is it to be real? |
| exposure | who can reach it: unauthenticated, authenticated, internal, undeployed (only an app no deployment manifest runs), or unreachable (dead code)? |

Priority P0–P3 is their product. A heuristic detector reports LOW confidence, not a lower
severity: a missing ownership check is exactly as bad as it ever was, and what is
uncertain is whether this one is missing. Low-confidence findings are review candidates
and never fail the gate.

## A silent zero is not a clean result

A tool that cannot run is SKIPPED, with the reason. A tool that crashes is an ERROR.
Neither is ever shown as zero findings. In SARIF such a run is marked unsuccessful with no
`results` at all, so a viewer does not read a crash as "every earlier alert was fixed". A
check command that crashes with a traceback is an error, not a finding — otherwise it
could be baselined, and the broken check would pass forever.

In CI, name the tools you installed (`--require ruff,bandit`) so a missing one fails
instead of quietly shrinking the report.

## The baseline

`repolens report --update-baseline` accepts today's findings. It records HOW MANY of each
fingerprint are known, so a second identical finding in the same file is still new. The
fingerprint leaves out line numbers so the baseline survives unrelated edits.

- Build it with the same scanner versions CI uses; a newer ruff or bandit adds rules, and
  their findings read as new.
- Commit it, and review what it accepts. Never regenerate it in CI.

## Suppressing a finding

`[report] suppress` maps a fingerprint to the reason it is accepted. The reason stays
visible in the profile. An unexplained suppression is a bug report nobody can read.

## What a source scan cannot prove

- An object-level authorisation (IDOR/BOLA) candidate is not proof. Proof needs a request
  replayed as a second user against real data: a dynamic test.
- Row counts, index use and query cost need the database.
- Dependency advisories need the network: `--with osv-scanner,pip-audit`.

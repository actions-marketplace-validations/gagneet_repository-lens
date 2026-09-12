# Gates and ratchets

**Rule.** A check that matters must be run by something, must be able to fail, and must
be looking at the right subject. Where debt predates it, enforce it as a ratchet.

## A check dies in one of four ways, and none of them raises

| way | what it looks like |
|---|---|
| **absent** | nothing runs it. It is named in three documents and executed by nothing. |
| **defanged** | it runs and can never exit non-zero — a report wearing a gate's clothes. |
| **blind** | its subject list is a literal, and the new file is not on it. |
| **non-deterministic** | its oracle is the working tree, so it passes locally and fails in CI on the same commit. |

`repolens gates --check` catches the first two for every configured script. Reachability
is a text search of the execution surfaces — CI workflows, deploy scripts, Makefiles,
tests — with comments stripped. Prose (a README, an instructions file) is deliberately not
a surface. An exemption carries its reason in words and is reported as stale once it no
longer applies.

## Ratchet, not wall

A strict gate switched on over existing debt fails every change on debt its author did
not create, and it gets deleted. A ratchet asks the only fair question — *did this change
make it worse?*

- An increase fails, and a NEW file must be clean.
- An un-baselined IMPROVEMENT also fails, so a win cannot be silently given back. The fix
  is one command.
- A missing baseline fails in check mode and writes nothing. A check that creates its own
  baseline passes by construction, so deleting the file would disarm it.

## Build a detector that separates right from wrong

If most of what a detector flags is legitimate code, it will be allowlisted into
uselessness. Prefer measuring the OUTCOME — "does a test record reach a real user's page?"
— to scanning for a shape. Report a heuristic as a low-confidence candidate, never as a
gate failure.

## Assert the wiring, not only the function

A unit-tested module with no callers passes every test it has. A route no server
registers, a job no scheduler runs, a store nothing dispatches to: test that the thing is
CONNECTED, not only that it is correct.

## Fix the gate's output, not just its verdict

A job that runs ten gates in sequence reports only the first failure. Let each gate run
(`if: !cancelled()` in GitHub Actions) so one push shows every problem.

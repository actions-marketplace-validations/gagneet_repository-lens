<!-- repolens:rules:start -->
## Code-visibility rules (repolens)

CI enforces these with `repolens`. Full text: `@@RULES_DIR@@/`.

- **Before writing a shared helper**, search by behaviour
  (`repolens lens similar --like "<what it does>"`) and check the capability index
  (`repolens owners --impact <concept>`). If the concept has an owner, call it. If it has
  none and will be reused, register it in the same change.
- **Before editing a function you did not write**, read its lens:
  `repolens lens --lookup <name>`. Blast radius is an upper bound, and "tested" is a name
  match.
- **Never hand-merge a generated artefact.** Take either side and run
  `repolens artefacts regenerate --all`.
- **A check must be run by something and able to fail.** A new gate over existing debt is
  a ratchet (`repolens gates --check`).
- **Document public symbols.** `repolens docs coverage --check` is a per-file ratchet.
- **`repolens report --check` must pass.** A skipped or crashed tool is never a clean
  result.
<!-- repolens:rules:end -->

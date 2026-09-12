# Docstrings on public symbols

**Rule.** Every public symbol says what it is FOR. In Python that means the module and
every public class, function and method. In TypeScript and JavaScript it means every
exported function, class, constant, interface, type and enum. Private helpers (`_name`)
and dunders are exempt.

## Why

A docstring is the one piece of intent that travels with the code into every tool that
reads it. The function lens prints it as the purpose, pdoc and TypeDoc render it, an
editor shows it at the call site, and an agent reads it before deciding whether to call a
helper or write another. Missing intent is how a helper gets rebuilt under a second name.

## What a good one says

It says what the symbol is for and what it promises: units, the empty case, what it
refuses and what it never does. Not a restatement of the signature.

A generated placeholder ("Function header", "TODO: describe") is not a docstring. List
its pattern in `[docs] placeholder_patterns`, and it counts as missing. Otherwise coverage
rises while nothing a reader can use was written.

## Enforced as a ratchet

```bash
repolens docs coverage                    # per-language summary, most-undocumented files
repolens docs coverage --missing <path>   # every gap under a path, with its line
repolens docs coverage --check            # CI
repolens docs coverage --update-baseline  # after documenting (an improvement must be locked in)
repolens docs build                       # the code reference: pdoc (Python) and TypeDoc (TypeScript)
```

A file may not gain an undocumented public symbol, and a new file documents all of its
public symbols. An improvement fails until the baseline is updated. A file that stops
parsing keeps its baseline count and is printed as unmeasured, so a syntax error is never
mistaken for progress.

## Limits

Python is parsed with `ast`. TypeScript and JavaScript are read with a regex over lines:
only top-level exported declarations are seen, and a re-export counts where it is
declared, not where it is re-exported.

pdoc imports the modules it documents, so a module that needs the whole application to
import belongs in `[docs.python] exclude`, with the reason written beside it.

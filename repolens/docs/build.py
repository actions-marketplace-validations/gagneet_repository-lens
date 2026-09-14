"""`repolens docs build`: code-reference HTML, from the docstrings already in the tree.

    repolens docs build                  both halves that are configured
    repolens docs build --python         pdoc only
    repolens docs build --typescript     TypeDoc only
    repolens docs build --strict         a half that cannot run fails, instead of skipping

Python pages come from pdoc and TypeScript pages from TypeDoc, into `[docs] out_dir`
(default `.repolens/docs/`, which is build output and not committed). An `index.html`
there links whichever halves were built.

pdoc IMPORTS the modules it documents, so it runs under `[docs.python] interpreter` and
needs their dependencies. A module that cannot import without the application's full
environment belongs in `[docs.python] exclude`, with the reason written beside it.

Before pdoc runs, every module it would document is imported once under that
interpreter. A module whose import fails only because a THIRD-PARTY package is not
installed (an optional extra such as FastAPI for `repolens.api.app`) is left out and
named in the output and in `index.html`; `[docs.python] missing_dependency = "fail"`
turns that into a failure instead. Any other import failure, including an ImportError
inside the documented packages themselves, fails the build before pdoc is started.
TypeDoc is run through `[docs.typescript] command`, pinned, so the output cannot change
under an unchanged tree.

A half that is not configured, or whose tool is not installed, is SKIPPED with the reason
— never reported as built. A tool that exits non-zero FAILS the build.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from .settings import DocsSettings, from_config

#: Written into a directory this command generated. Only a directory carrying it is
#: ever cleared, so a misconfigured `out_dir` can never delete something else.
MARKER = ".repolens-generated"


@dataclass
class Part:
    """One half of the build: what happened, and where the output is."""
    name: str
    status: str  # built | skipped | failed
    detail: str = ""
    path: Path | None = None


def _clear(target: Path) -> None:
    """Remove a previous build, but only one this command wrote."""
    if target.is_dir() and (target / MARKER).is_file():
        shutil.rmtree(target)


def _run(argv: list[str], s: DocsSettings, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=s.root, env=env, capture_output=True, text=True,
                          timeout=s.timeout_seconds)


def _tail(text: str, lines: int = 6) -> str:
    kept = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip()]
    return "\n      ".join(kept[-lines:])


#: Marks the probe's result line, so output a documented module prints on import is ignored.
_PROBE_TAG = "REPOLENS-DOCS-PROBE:"

#: Run under the docs interpreter with the pdoc module specs as argv[1] (JSON). It asks
#: pdoc itself which modules those specs expand to, so `!pattern` exclusions and package
#: walking follow the installed pdoc exactly, then imports each module the way pdoc will.
#: A failure is "missing" only when a ModuleNotFoundError names a top-level package that
#: is not one of the documented packages and cannot be found at all. Anything else,
#: including a missing first-party module or `cannot import name`, is an "error".
_PROBE = r"""
import importlib, importlib.util, json, sys, traceback, warnings
try:
    from pdoc import extract
    walk_specs = extract.walk_specs
except Exception:
    print("%(tag)s" + json.dumps({"unsupported": True}))
    raise SystemExit(0)
specs = json.loads(sys.argv[1])
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        names = walk_specs(specs)
    except Exception as exc:
        print("%(tag)s" + json.dumps({"unsupported": True, "reason": repr(exc)}))
        raise SystemExit(0)
first_party = {name.split(".")[0] for name in names}
load = getattr(extract, "load_module", importlib.import_module)
missing, errors = {}, {}
for name in names:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            load(name)
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        cause = exc.__cause__ if isinstance(exc, RuntimeError) and exc.__cause__ else exc
        top = (getattr(cause, "name", None) or "").split(".")[0]
        if (isinstance(cause, ModuleNotFoundError) and top and top not in first_party
                and importlib.util.find_spec(top) is None):
            missing[name] = cause.name
        else:
            errors[name] = "".join(traceback.format_exception_only(type(cause), cause)).strip()
print("%(tag)s" + json.dumps({"modules": names, "missing": missing, "errors": errors}))
""" % {"tag": _PROBE_TAG}


@dataclass
class ImportProbe:
    """What importing the documented modules showed, before pdoc is asked to render them."""
    missing: dict[str, str]  # module -> the third-party package it needs and is not installed
    errors: dict[str, str]  # module -> why it failed to import, for any other reason
    supported: bool = True  # False when this pdoc cannot expand specs; pdoc then runs unprobed


def probe_imports(s: DocsSettings, interpreter: str, specs: list[str],
                  env: dict[str, str] | None = None) -> ImportProbe:
    """Import every module pdoc would document for `specs`, under `interpreter`.

    Runs in a subprocess so a module's import side effects stay out of this process, as
    they do for pdoc. A probe that cannot run or report is `supported=False`, and the
    build falls back to pdoc's own verdict rather than guessing."""
    proc = _run([interpreter, "-c", _PROBE, json.dumps(specs)], s, env)
    for line in reversed((proc.stdout or "").splitlines()):
        if line.startswith(_PROBE_TAG):
            data = json.loads(line[len(_PROBE_TAG):])
            if data.get("unsupported"):
                break
            return ImportProbe(dict(data.get("missing") or {}), dict(data.get("errors") or {}))
    return ImportProbe({}, {}, supported=False)


def build_python(s: DocsSettings, out: Path) -> Part:
    """Render the pdoc half into `out/python`, or say why it was skipped or failed."""
    cfg = s.python
    modules = list(cfg.get("modules") or [])
    if not modules:
        return Part("python", "skipped", "no [docs.python] modules configured")
    interpreter = s.python_interpreter()
    configured = str(cfg.get("interpreter") or "")
    # The fallback is deliberate (a venv that exists locally and not in CI), but it must
    # be visible: silently building with another interpreter also hides a typo.
    note = (f" [configured interpreter {configured} not found; used {interpreter}]"
            if configured and not (s.root / configured).exists() else "")
    env = dict(os.environ)
    paths = [str(s.root / p) for p in cfg.get("path") or []]
    env["PYTHONPATH"] = os.pathsep.join(paths + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    probe = _run([interpreter, "-c", "import pdoc"], s, env)
    if probe.returncode != 0:
        return Part("python", "skipped", f"pdoc is not installed for {interpreter} (pip install pdoc){note}")
    specs = modules + [f"!{name}" for name in cfg.get("exclude") or []]
    imports = probe_imports(s, interpreter, specs, env)
    if imports.errors:
        return Part("python", "failed", "cannot import " + ", ".join(sorted(imports.errors))
                    + f"{note}:\n      " + "\n      ".join(
                        f"{name}: {_tail(reason, 1)}" for name, reason in sorted(imports.errors.items())))
    left_out = ""
    if imports.missing:
        listed = ", ".join(f"{name} (needs {dep})" for name, dep in sorted(imports.missing.items()))
        if str(cfg.get("missing_dependency") or "exclude") == "fail":
            return Part("python", "failed", f"dependency not installed for {interpreter}: {listed}{note}")
        left_out = f"; NOT DOCUMENTED, dependency not installed: {listed}"
        # Anchored: pdoc matches a `!` spec as a regex prefix, and only these modules go.
        specs += [f"!{re.escape(name)}$" for name in sorted(imports.missing)]
    target = out / "python"
    _clear(target)
    argv = [interpreter, "-m", "pdoc", "-o", str(target)]
    if cfg.get("docformat"):
        argv += ["--docformat", str(cfg["docformat"])]
    argv += [str(a) for a in cfg.get("extra_args") or []]
    argv += specs
    proc = _run(argv, s, env)
    if proc.returncode != 0:
        return Part("python", "failed", f"pdoc exited {proc.returncode}{note}{left_out}:\n      "
                    + _tail(proc.stderr or proc.stdout))
    target.mkdir(parents=True, exist_ok=True)
    (target / MARKER).write_text("repolens docs build\n", encoding="utf-8")
    pages = sum(1 for _ in target.rglob("*.html"))
    return Part("python", "built", f"{pages} pages for {', '.join(modules)}{left_out}{note}", target)


def build_typescript(s: DocsSettings, out: Path) -> Part:
    """Render the TypeDoc half into `out/typescript`, or say why it was skipped or failed."""
    cfg = s.typescript
    entry_points = list(cfg.get("entry_points") or [])
    if not entry_points:
        return Part("typescript", "skipped", "no [docs.typescript] entry_points configured")
    command = [str(c) for c in cfg.get("command") or []]
    if not command:
        return Part("typescript", "skipped", "[docs.typescript] command is empty")
    exe = shutil.which(command[0])
    if not exe:
        return Part("typescript", "skipped", f"{command[0]} is not on PATH (install Node.js)")
    missing = [e for e in entry_points if not (s.root / e).exists()]
    tsconfig = cfg.get("tsconfig") or ""
    if tsconfig and not (s.root / tsconfig).is_file():
        missing.append(tsconfig)
    if missing:
        return Part("typescript", "failed", "configured but missing: " + ", ".join(missing))
    target = out / "typescript"
    _clear(target)
    argv = [exe, *command[1:], "--entryPointStrategy", "expand"]
    for entry in entry_points:
        argv += ["--entryPoints", entry]
    if tsconfig:
        argv += ["--tsconfig", tsconfig]
    argv += ["--out", str(target), *[str(a) for a in cfg.get("extra_args") or []]]
    proc = _run(argv, s)
    if proc.returncode != 0:
        return Part("typescript", "failed", f"typedoc exited {proc.returncode}:\n      "
                    + _tail(proc.stdout + "\n" + proc.stderr))
    target.mkdir(parents=True, exist_ok=True)
    (target / MARKER).write_text("repolens docs build\n", encoding="utf-8")
    pages = sum(1 for _ in target.rglob("*.html"))
    return Part("typescript", "built", f"{pages} pages for {', '.join(entry_points)}", target)


def write_index(out: Path, parts: list[Part], title: str) -> Path:
    """A landing page linking what was built. No timestamp: same tree, same bytes."""
    rows = []
    for part in parts:
        if part.status == "built" and part.path is not None:
            link = f'<a href="{html.escape(part.path.name)}/index.html">{html.escape(part.name)}</a>'
        else:
            link = html.escape(part.name)
        rows.append(f"<li>{link} — {html.escape(part.status)}: {html.escape(part.detail.splitlines()[0] if part.detail else '')}</li>")
    page = (f"<!doctype html><meta charset=utf-8><title>{html.escape(title)}</title>"
            f"<h1>{html.escape(title)}</h1><ul>{''.join(rows)}</ul>\n")
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(page, encoding="utf-8")
    return out / "index.html"


def main(argv: list[str] | None = None, *, config: Config | None = None,
         settings: DocsSettings | None = None, prog: str | None = None) -> int:
    """`repolens docs build`. Exit 1 if a half failed, or under `--strict` was skipped."""
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--python", action="store_true", help="build only the pdoc half")
    ap.add_argument("--typescript", action="store_true", help="build only the TypeDoc half")
    ap.add_argument("--out", help="output directory (default [docs] out_dir)")
    ap.add_argument("--strict", action="store_true", help="a SKIPPED half fails the build")
    args = ap.parse_args(argv)

    s = settings or from_config(config)
    out = Path(args.out).resolve() if args.out else s.out_dir
    wanted = [name for name, flag in (("python", args.python), ("typescript", args.typescript)) if flag] \
        or ["python", "typescript"]
    builders = {"python": build_python, "typescript": build_typescript}
    parts = []
    for name in wanted:
        try:
            parts.append(builders[name](s, out))
        except subprocess.TimeoutExpired:
            parts.append(Part(name, "failed", f"timed out after {s.timeout_seconds}s"))
    index = write_index(out, parts, "Code reference")
    for part in parts:
        print(f"  {part.name:<11} {part.status.upper():<8} {part.detail}")
    print(f"\nwrote {index}")
    failed = any(p.status == "failed" for p in parts)
    skipped = any(p.status == "skipped" for p in parts)
    return 1 if failed or (args.strict and skipped) else 0


if __name__ == "__main__":
    sys.exit(main())

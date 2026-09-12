"""Static security detectors: authentication, object-level authorisation, injection.

What is detectable from source, and what is not
-----------------------------------------------
BOLA / IDOR (OWASP API1:2023) is a missing CHECK, and a static tool can only see where a
check is conspicuously absent. So `object-route-without-ownership-check` fires only when
a route addresses an object by a path id AND never consults who is asking — no role
dependency, no guard call, no 401/403 raised, and the caller's identity parameter unused.
A handler that passes `current_user` to a service that checks ownership is not flagged;
a service that forgets is invisible here.

Confidence comes from CONTRAST, not from the route alone. A route that never consults
the caller is ordinary when the object belongs to the whole building (an asset's health
history); it is suspicious when a SIBLING route addressing the same `{id}` does consult
the caller — someone thought a check was needed there. That contrast (the MACE idea:
an access check present on one path and absent on its sibling) lifts the confidence;
without it the finding stays low-confidence, a review candidate.

Proving object-level authorisation needs a request replayed as a second user against
real data (a DAST pass), which no source scan can substitute for.

Tenant scoping by a database wrapper (one building cannot read another's rows) is not
object-level authorisation: it stops cross-TENANT access, and says nothing about one
member of a building addressing another member's object.

A signed webhook authenticates in its BODY — it verifies an HMAC over the raw payload —
so a call matching `body_auth_call_pattern` counts as authentication. The pattern is a
NAME match: a verify function that does not actually fail closed is not detectable here.

Known false negatives, all in the direction of NOT flagging (every one is a name or
shape heuristic, and each was reproduced against a fixture):

  * Reading the caller's identity anywhere counts as consulting it, so a route that
    deletes by id and writes `current_user["id"]` only into an audit row is not flagged.
    Such a route does NOT raise its siblings' confidence (`checks_caller` does).
  * Any 401/403 the handler raises counts as a check, including one about something
    other than the caller ("accept the terms first").
  * A guard is recognised by name (`guard_calls`, `guard_call_patterns`); a guard called
    something else is invisible, and a non-guard that matches is taken on trust.
  * An ownership check inside a service the handler calls is invisible; so is its absence.
"""
from __future__ import annotations

import ast

from ..core.findings import Finding
from .python_ast import (MUTATING, Route, bound_names, dotted, functions, last, literal_locals,
                         literal_text, names_read, parse, python_files, raises_auth_error,
                         routes, walk_body)
from .mounts import MountIndex
from .settings import ScanSettings
from .wiring import mark_unreachable, unreachable_route_files

TOOL = "security"


def _exposure(authenticated: bool) -> str:
    return "authenticated" if authenticated else "unauthenticated"


class RouteAuth:
    """What a route's signature and body say about who may call it."""

    def __init__(self, route: Route, s: ScanSettings):
        sec = s.security
        names = [d.name for d in route.dependencies]
        self.authn = [n for n in names if sec.authenticates(n) and n not in sec.optional_dependencies]
        self.optional = [n for n in names if n in sec.optional_dependencies]
        self.role = [n for n in names if sec.restricts_role(n)]
        body = names_read(route.node)
        # A secret header authenticates only if the handler READS it: a declared,
        # never-compared `authorization: str = Header(None)` checks nothing.
        self.secret_header = [h for h in route.header_params
                              if sec.secret_header.search(h) and h in body]
        self.identity_params = [d.param for d in route.dependencies
                                if d.param and d.name in self.authn and "building" not in d.name]
        self.identity_used = any(p in body for p in self.identity_params)
        called = {last(n.func) for n in walk_body(route.node, lambdas=True) if isinstance(n, ast.Call)}
        self.guard_called = sorted(c for c in called if sec.is_guard(c))
        self.secret_verified = sorted(c for c in called if sec.body_auth_call.search(c))
        self.raises_auth = raises_auth_error(route.node)

    @property
    def authenticated(self) -> bool:
        return bool(self.authn or self.secret_header or self.raises_auth or self.secret_verified)

    @property
    def checks_caller(self) -> bool:
        """An explicit authorisation decision: a role dependency, a guard call, a 401/403."""
        return bool(self.role or self.guard_called or self.raises_auth)

    @property
    def consults_caller(self) -> bool:
        """A check, or merely reading the caller's identity — which may be an ownership
        filter or may be an audit field; the scanner cannot tell, and gives the benefit."""
        return self.checks_caller or self.identity_used


def _param_used_in_call(route: Route, param: str) -> bool:
    for node in walk_body(route.node, lambdas=True):
        if isinstance(node, ast.Call):
            for value in [*node.args, *(k.value for k in node.keywords)]:
                if any(isinstance(n, ast.Name) and n.id == param for n in ast.walk(value)):
                    return True
    return False


def _route_findings(s: ScanSettings, rel: str, route: Route, auth: RouteAuth,
                    peers: list[tuple[Route, RouteAuth]]) -> list[Finding]:
    sec = s.security
    where = f"{route.method} {route.path} ({route.qualname})"
    out: list[Finding] = []
    # A public_routes entry may be written with or without the prefix the route inherits.
    public = sec.public_reason(route.path) or (
        sec.public_reason(route.declared_path) if route.declared_path != route.path else None)
    object_params = [p for p in route.path_params if sec.object_id.search(p)]

    if not auth.authenticated and public is None:
        if route.method in MUTATING:
            out.append(Finding(
                tool=TOOL, rule="security/unauthenticated-mutation-route", severity="high",
                confidence="low" if auth.optional else "medium", category="security",
                exposure="unauthenticated", file=rel, line=route.line,
                message=f"{where} changes state and declares no authenticating dependency"
                        + (f" (only optional: {', '.join(auth.optional)})" if auth.optional else ""),
                remedy="Add an authenticating Depends() (and a role/permission one if it is not "
                       "for every user). If it is public by design — login, a signed webhook — "
                       "list its path in [scan.security.public_routes] with the reason.",
            ))
        elif object_params:
            out.append(Finding(
                tool=TOOL, rule="security/unauthenticated-object-read", severity="medium",
                confidence="low", category="security", exposure="unauthenticated",
                file=rel, line=route.line,
                message=f"{where} returns an object by {{{object_params[0]}}} to an anonymous caller",
                remedy="Require authentication, or check the object's own visibility flag "
                       "(is_public) before returning it; record deliberate public reads in "
                       "[scan.security.public_routes].",
            ))

    if auth.authn and object_params and not auth.consults_caller:
        used = [p for p in object_params if _param_used_in_call(route, p)]
        if used:
            who = (f"never reads {', '.join(auth.identity_params)}" if auth.identity_params
                   else "has no caller-identity parameter at all")
            # Only a sibling that CHECKS counts as contrast: one that merely reads the
            # caller (an audit field, a created_by) is no evidence that a check was needed.
            siblings = [f"{r.method} {r.path}" for r, a in peers
                        if r is not route and a.checks_caller and set(used) & set(r.path_params)]
            mutating = route.method in MUTATING
            if siblings:
                confidence = "high" if mutating else "medium"
                contrast = (f"; {len(siblings)} sibling route(s) on {{{used[0]}}} DO check the "
                            f"caller — role dependency, guard call or 401/403 "
                            f"({', '.join(siblings[:3])})")
            else:
                confidence = "medium" if mutating else "low"
                contrast = ""
            out.append(Finding(
                tool=TOOL, rule="security/object-route-without-ownership-check", severity="high",
                confidence=confidence, category="security", exposure="authenticated",
                file=rel, line=route.line,
                message=f"{where} addresses an object by {{{used[0]}}} and {who}: any "
                        f"authenticated caller who can reach the route can name any id "
                        f"(BOLA/IDOR candidate){contrast}",
                remedy="Load the object, then compare its owner/unit/building with the caller "
                       "(or call the ownership helper) before acting; a role dependency is "
                       "function-level authorisation and does not replace an object check. "
                       "If the object belongs to the whole building, say so in a comment and "
                       "suppress by fingerprint. Confirm with a two-user replay test.",
            ))
    return out


_NUMERIC_CASTS = frozenset({"int", "float", "bool", "len", "abs", "round", "ord", "Decimal"})


def _numeric_cast(node: ast.AST) -> bool:
    """`int(x)` and friends: the value is a number or the call raised."""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in _NUMERIC_CASTS)


def _add_operands(node: ast.AST) -> list[ast.AST]:
    """The operands of a `+` chain, left to right."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_add_operands(node.left), *_add_operands(node.right)]
    return [node]


#: Keyword arguments that carry the SQL text when it is not passed positionally.
_SQL_KEYWORDS = frozenset({"query", "sql", "statement", "stmt"})
#: psycopg's composition API: `sql.SQL("... {}").format(sql.Identifier(x))` quotes what
#: it interpolates, so a `.format()` or `.join()` made on one is not string building.
_SAFE_COMPOSERS = frozenset({"SQL", "Composed", "Identifier", "Literal", "Placeholder"})


def _is_text(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _interpolated_parts(sql: ast.AST) -> list[ast.AST] | None:
    """The pieces interpolated into SQL text, or None when `sql` is not built by
    interpolation (a plain literal, a name, a call the scanner cannot see into).

    Only text in SQL position is asked about: a query argument, or a name later passed
    as one. There `+`, `%` and `.format()` build a string whatever their operands are
    spelled, so a template held in a name (`BASE + column`, `TEMPLATE.format(x)`,
    `query % x`) is interpolation as much as a literal one is. The parts are then
    judged one by one: a module constant or a literal local passes."""
    if isinstance(sql, ast.JoinedStr):
        return [v.value for v in sql.values if isinstance(v, ast.FormattedValue)]
    if isinstance(sql, ast.BinOp) and isinstance(sql.op, ast.Mod):
        return [p for p in (sql.left, sql.right) if not _is_text(p)]
    if isinstance(sql, ast.BinOp) and isinstance(sql.op, ast.Add):
        # `"... " + uid + " ..."` nests as ((str + uid) + str): walk the whole chain.
        return [o for o in _add_operands(sql) if not _is_text(o)]
    if isinstance(sql, ast.Call) and isinstance(sql.func, ast.Attribute):
        receiver = sql.func.value
        if isinstance(receiver, ast.Call) and last(receiver.func) in _SAFE_COMPOSERS:
            return None
        own = [] if _is_text(receiver) else [receiver]
        if sql.func.attr == "format":
            return [*own, *sql.args, *(k.value for k in sql.keywords)]
        if (sql.func.attr == "join" and len(sql.args) == 1 and not sql.keywords
                and isinstance(sql.args[0], (ast.List, ast.Tuple))):
            return [*own, *(e for e in sql.args[0].elts if not _is_text(e))]
    return None


def _assignments(fn: ast.AST, name: str) -> list[tuple[ast.stmt, ast.AST, bool]]:
    """(statement, value, appended) for every `name = v`, `name: T = v` and `name += v`
    in the body, in source order. `appended` marks the augmented form, which adds to
    the text where the other two replace it."""
    found: list[tuple[ast.stmt, ast.AST, bool]] = []
    for node in walk_body(fn):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            targets = [node.target]
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            found.append((node, node.value, isinstance(node, ast.AugAssign)))
    return sorted(found, key=lambda f: (f[0].lineno, f[0].col_offset))


def _writes(fn: ast.AST, name: str) -> list[tuple[int, ast.AST]]:
    """(line, value) for every `name = v`, `name: T = v` and `name += v` in the body."""
    return [(stmt.lineno, value) for stmt, value, _ in _assignments(fn, name)]


def _parents(fn: ast.AST) -> dict[int, ast.AST]:
    """id(node) -> the node that holds it, for every node under `fn`."""
    return {id(child): node for node in ast.walk(fn) for child in ast.iter_child_nodes(node)}


def _precedes(first: ast.stmt, target: ast.AST, parents: dict[int, ast.AST], fn: ast.AST) -> bool:
    """Whether `first` has run on every path that reaches `target`: it is an earlier
    statement of a block that holds `target`, directly or nested.

    Line order is not enough. A check in one branch of an `if` does not guard a query
    in the other branch. A check inside a `try` whose exception is caught and
    ignored does not guard a query after the `try`. Both come earlier in the file."""
    node = target
    while node is not fn and id(node) in parents:
        parent = parents[id(node)]
        if parent is not fn and isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                    ast.Lambda, ast.ClassDef)):
            return False  # a nested function runs when it is called, not here
        for field in ("body", "orelse", "finalbody"):
            block = getattr(parent, field, None)
            if not (isinstance(block, list) and any(s is node for s in block)):
                continue
            for stmt in block:
                if stmt is node:
                    break
                if stmt is first:
                    return True
        node = parent
    return False


def _built_parts(fn: ast.AST, name: str, call: ast.AST,
                 parents: dict[int, ast.AST]) -> tuple[list[ast.AST] | None, int]:
    """What was interpolated into `name` on its way to `call`, and the line of the last
    write that added some.

    An assignment that runs on every path to the call replaces whatever came before it.
    So only that assignment and the writes after it count. One that runs on only some
    paths replaces nothing. `name += x` adds `x`, and so does `name = name + x`."""
    writes = [w for w in _assignments(fn, name) if w[0].lineno <= call.lineno]

    def mentions_itself(value: ast.AST) -> bool:
        return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(value))

    start = max((i for i, (stmt, value, appended) in enumerate(writes)
                 if not appended and not mentions_itself(value)
                 and _precedes(stmt, call, parents, fn)), default=0)
    parts: list[ast.AST] = []
    line = 0
    for stmt, value, appended in writes[start:]:
        found = _interpolated_parts(value)
        if found is None and appended and not _is_text(value):
            found = [value]
        found = [p for p in found or [] if not (isinstance(p, ast.Name) and p.id == name)]
        if found:
            parts.extend(found)
            line = stmt.lineno
    return (parts or None), line


def _allow_listed(test: ast.AST, safe, shadowed: set[str]) -> str | None:
    """`name not in ALLOWED` (a constant, a literal collection, or `CONST.keys()`): the
    name checked, else None."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn) and isinstance(test.left, ast.Name)):
        return None
    allowed = test.comparators[0]
    if (isinstance(allowed, ast.Call) and isinstance(allowed.func, ast.Attribute)
            and allowed.func.attr == "keys" and not allowed.args):
        allowed = allowed.func.value
    if isinstance(allowed, (ast.Tuple, ast.List, ast.Set)):
        ok = all(isinstance(e, ast.Constant) for e in allowed.elts)
    elif isinstance(allowed, ast.Name):
        ok = allowed.id not in shadowed and bool(safe.search(allowed.id))
    elif isinstance(allowed, ast.Attribute):
        ok = literal_text(allowed, set(), safe, shadowed)  # `request.GET` is not a constant
    else:
        ok = False
    return test.left.id if ok else None


def _allow_list_guards(fn: ast.AST, safe, shadowed: set[str]) -> dict[str, list[ast.If]]:
    """Names checked against an allow-list, with the `if` that checks each.

    `if col not in ALLOWED: raise ...` (or `return`, `continue`, `break`), and `if col
    not in ALLOWED: col = "default"`, all leave `col` holding one of a fixed set of
    identifiers past the check — the remedy this rule's own message recommends, and it
    used to be flagged anyway. A test of the form `not col or col not in ALLOWED`
    counts too. Whether the check GUARDS a given query is `_guarded_at`'s question."""
    guards: dict[str, list[ast.If]] = {}
    for node in walk_body(fn):
        if not isinstance(node, ast.If) or not node.body:
            continue
        tests = node.test.values if (isinstance(node.test, ast.BoolOp)
                                     and isinstance(node.test.op, ast.Or)) else [node.test]
        for test in tests:
            name = _allow_listed(test, safe, shadowed)
            if name is None:
                continue
            final = node.body[-1]
            resets = (isinstance(final, ast.Assign) and len(final.targets) == 1
                      and isinstance(final.targets[0], ast.Name) and final.targets[0].id == name
                      and isinstance(final.value, ast.Constant))
            if isinstance(final, (ast.Raise, ast.Return, ast.Continue, ast.Break)) or resets:
                guards.setdefault(name, []).append(node)
    return guards


def _guarded_at(call: ast.AST, guards: dict[str, list[ast.If]], fn: ast.AST,
                parents: dict[int, ast.AST]) -> set[str]:
    """The allow-listed names still holding a checked value at `call`: the check has run
    on every path to it (`_precedes`), and nothing rebinds the name between the two."""
    held: set[str] = set()
    for name, checks in guards.items():
        writes = [line for line, _ in _writes(fn, name)]
        for check in checks:
            end = check.end_lineno or check.lineno
            if _precedes(check, call, parents, fn) and not any(end < w < call.lineno for w in writes):
                held.add(name)
                break
    return held


def _sql_findings(s: ScanSettings, rel: str, tree: ast.Module, route_by_node: dict[int, Route]) -> list[Finding]:
    sec = s.security
    safe = sec.sql_safe_interpolation
    out: list[Finding] = []
    for fn, qualname in functions(tree):
        route = route_by_node.get(id(fn))
        request = set(route.request_params) if route else set()
        trusted: set[str] | None = None
        shadowed: set[str] = set()
        guards: dict[str, list[ast.If]] = {}
        parents: dict[int, ast.AST] = {}
        for node in walk_body(fn):
            if not isinstance(node, ast.Call) or last(node.func) not in sec.sql_calls:
                continue
            sql = node.args[0] if node.args else next(
                (k.value for k in node.keywords if k.arg in _SQL_KEYWORDS), None)
            if sql is None:
                continue
            if trusted is None:
                trusted = literal_locals(fn, safe)
                shadowed = bound_names(fn) - trusted
                guards = _allow_list_guards(fn, safe, shadowed)
                parents = _parents(fn)
            via = ""
            parts = _interpolated_parts(sql)
            if parts is None and isinstance(sql, ast.Name) and sql.id not in trusted:
                # `query = f"... {x}"` then `execute(query)`: the text was built one
                # statement earlier, and reading only the call's argument saw a bare name.
                parts, built_at = _built_parts(fn, sql.id, node, parents)
                if parts:
                    via = f" (via `{sql.id}`, built at line {built_at})"
            if parts is None:
                continue
            # `LIMIT {int(limit)}` cannot carry SQL: a numeric cast raises on anything else.
            parts = [p for p in parts if not _numeric_cast(p)]
            if not parts:
                continue
            guarded = _guarded_at(node, guards, fn, parents)
            trusted_here, shadowed_here = trusted | guarded, shadowed - guarded
            if all(literal_text(part, trusted_here, safe, shadowed_here) for part in parts):
                continue  # assembled from literals and constants only; the values are bound
            interpolated: set[str] = set()
            for part in parts:
                interpolated.update(n.id for n in ast.walk(part) if isinstance(n, ast.Name))
                interpolated.update(dotted(n) for n in ast.walk(part)
                                    if isinstance(n, ast.Attribute) and dotted(n))
            names = sorted(n for n in interpolated if n.split(".")[0] not in trusted
                           and (n in shadowed or not safe.search(n.rsplit(".", 1)[-1]))) \
                or sorted(interpolated)
            from_request = sorted(set(names) & request)
            if from_request:
                severity, confidence = "high", "high"
            elif route is not None:
                severity, confidence = "high", "low"
            else:
                severity, confidence = "medium", "low"
            exposure = ("internal" if s.is_internal(rel) else
                        _exposure(RouteAuth(route, s).authenticated) if route else "")
            out.append(Finding(
                tool=TOOL, rule="security/sql-built-from-string", severity=severity,
                confidence=confidence, category="security", exposure=exposure,
                file=rel, line=node.lineno,
                message=(f"{qualname}() builds SQL for {last(node.func)}() by interpolation"
                         + (f" of REQUEST input {', '.join(from_request)}" if from_request else
                            f" of {', '.join(names[:4])}") + via),
                remedy="Bind values as parameters (text(':x') with params, asyncpg $1). An "
                       "identifier cannot be bound: check it against an allow-list. For "
                       "`SET app.tenant_id = '…'` use `SELECT set_config('app.tenant_id', $1, false)`.",
            ))
    return out


def _model_findings(s: ScanSettings, rel: str, tree: ast.Module) -> list[Finding]:
    sec = s.security
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or not node.name.endswith(sec.request_model_suffixes):
            continue
        for stmt in node.body:
            if (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
                    and stmt.target.id in sec.privileged_fields):
                out.append(Finding(
                    tool=TOOL, rule="security/caller-settable-privileged-field", severity="medium",
                    confidence="medium", category="security", file=rel, line=stmt.lineno,
                    message=f"request model {node.name} lets the caller set `{stmt.target.id}`",
                    remedy="Derive it server-side and drop it from the request model (or "
                           "ignore it unless the caller is authorised to set it). A flag a "
                           "caller can set is an authorisation decision the caller makes.",
                ))
    return out


def scan(s: ScanSettings) -> list[Finding]:
    findings: list[Finding] = []
    dead = unreachable_route_files(s)
    mounts = MountIndex(s)
    for path in python_files(s):
        tree = parse(str(path))
        if tree is None:
            continue
        rel = s.rel(path)
        found_routes = routes(tree, mounts.for_file(rel))
        peers = [(r, RouteAuth(r, s)) for r in found_routes]
        file_findings: list[Finding] = []
        for route, auth in peers:
            for finding in _route_findings(s, rel, route, auth, peers):
                if s.is_internal(rel):
                    finding.exposure = "internal"
                file_findings.append(finding)
        file_findings.extend(_sql_findings(s, rel, tree, {id(r.node): r for r in found_routes}))
        file_findings.extend(_model_findings(s, rel, tree))
        if rel in dead:
            mark_unreachable(file_findings)
        findings.extend(file_findings)
    return findings

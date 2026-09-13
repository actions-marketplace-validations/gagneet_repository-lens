"""Scanner settings: generic defaults, overridden by `[scan]` in repolens.toml."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config, load_config, merge

DEFAULTS: dict[str, Any] = {
    "python_roots": ["."],
    "skip_parts": [".git", "venv", ".venv", "node_modules", "__pycache__", "site-packages",
                   "dist", "build", "alembic/versions"],
    # Code that never serves a request (one-off scripts, seeds). Findings there are
    # reported with exposure "internal", which lowers their priority, never hides them.
    "internal_prefixes": [],
    # Files the server runs. Any non-internal file that constructs an app (a call named
    # below) is one automatically; a route module none of them reaches by import is dead
    # code, and its findings are reported with exposure "unreachable".
    "entrypoints": [],
    "app_constructors": ["FastAPI", "Flask", "Starlette", "Quart", "Sanic"],
    "security": {
        # Dependency callables that AUTHENTICATE the caller when used as Depends(...).
        "auth_dependencies": ["get_current_user"],
        "auth_dependency_patterns": ["^_?get_current_", "^_?get_approved_", "^_?require_",
                                     "^_?verify_", "^_?authenticate"],
        # Dependencies that RESTRICT by role/permission (function-level authorisation).
        "role_dependency_patterns": ["^_?require_(?!feature$|approved_feature$|auth$)"],
        # Dependencies that allow an anonymous caller.
        "optional_dependencies": ["get_optional_user"],
        # Calls inside a handler that make an authorisation decision. `require_*` is how
        # most codebases spell a guard, but not every `require_*` is one: the exclusions
        # are the VALIDATION shapes (`require_fields`, `require_uuid`, `require_valid_id`,
        # `require_domain_source`), which check the input, not the caller.
        "guard_calls": ["effective_role", "assert_roles", "require_roles", "has_permission"],
        "guard_call_patterns": [r"^_?require_(?!(approved_)?feature$|u?uid$|\w*_id$|valid_\w*$"
                                r"|\w*source$|fields?$|params?$|body$|json$|payload$)",
                                "^_?ensure_(can|access|owner|role|permission)"],
        # A call in the BODY that authenticates the request by a shared secret: a signed
        # webhook verifies its HMAC before reading the payload, with no Depends() to see.
        # It must name the SECRET (signature, hmac, secret): `validate_webhook_payload`
        # checks a shape, not a sender. `verify_webhook` is the provider-protocol spelling.
        "body_auth_call_pattern": (r"^_?(verify|validate|check)_\w*(signature|hmac|secret)\w*$"
                                   r"|^_?verify_webhook$|^construct_event$"),
        # Header parameters with these names are treated as a shared-secret check.
        "secret_header_pattern": "(secret|token|signature|api_key|apikey|auth)",
        # A path parameter naming one object: `{id}`, `{unit_id}`, `{doc_uuid}`.
        "object_id_pattern": "(^id$|_id$|_uuid$|^uuid$)",
        # Route path regex -> why it is public by design.
        "public_routes": {},
        # Fields a CALLER must never set on a request model.
        "privileged_fields": ["is_test_data", "is_approved", "is_admin", "is_superuser",
                              "role", "permissions", "tenant_id"],
        "request_model_suffixes": ["Create", "Update", "Request", "Payload", "Input", "In"],
        # Calls whose first argument (or `query=` / `sql=` / `statement=`) is SQL text.
        # `SQL` and `literal_column` make SQL of their argument; psycopg's
        # `sql.SQL("...").format(sql.Identifier(x))` stays clean, since what it
        # interpolates is quoted.
        "sql_calls": ["text", "execute", "executemany", "fetch", "fetchrow", "fetchval",
                      "exec_driver_sql", "prepare", "copy_from_query", "SQL", "literal_column"],
        # Interpolations that cannot carry caller input (module constants).
        "sql_safe_interpolation": "^[A-Z][A-Z0-9_]*$",
    },
    "performance": {
        # Calls that block the thread on the network or another process. Mirrors
        # tests/backend/test_no_blocking_io_in_async_handlers.py's deliberately narrow list.
        "blocking_calls": ["smtplib.SMTP", "smtplib.SMTP_SSL", "requests.get", "requests.post",
                           "requests.put", "requests.patch", "requests.delete", "requests.request",
                           "time.sleep", "subprocess.run", "subprocess.call",
                           "subprocess.check_output", "urllib.request.urlopen",
                           # Synchronous database drivers: connecting is a network round
                           # trip, and every query on the result is another.
                           "psycopg2.connect", "psycopg.connect", "sqlalchemy.create_engine",
                           "pymongo.MongoClient"],
        # Awaited calls that are a database round trip (method names).
        "db_methods": ["find_one", "find", "count_documents", "update_one", "update_many",
                       "insert_one", "insert_many", "delete_one", "delete_many", "aggregate",
                       "replace_one", "find_one_and_update", "find_one_and_delete", "distinct",
                       "execute", "fetch", "fetchrow", "fetchval", "scalar", "scalars"],
    },
    "migrations": {
        # Directories of migration files. Empty: every `alembic/versions` and
        # `migrations/versions` directory under the root.
        "roots": [],
        # Width of the version table's revision column. Alembic creates VARCHAR(32).
        "revision_max_length": 32,
        # Report a table created in `rls_schemas` (every schema when empty) that no
        # migration puts under row-level security. Off by default: not every table holds
        # tenant data, and a check that cries wolf gets switched off.
        "require_rls": False,
        "rls_schemas": [],
    },
}


@dataclass
class SecuritySettings:
    auth_dependencies: frozenset[str]
    auth_patterns: tuple[re.Pattern[str], ...]
    role_patterns: tuple[re.Pattern[str], ...]
    optional_dependencies: frozenset[str]
    guard_calls: frozenset[str]
    guard_patterns: tuple[re.Pattern[str], ...]
    body_auth_call: re.Pattern[str]
    secret_header: re.Pattern[str]
    object_id: re.Pattern[str]
    public_routes: tuple[tuple[re.Pattern[str], str], ...]
    privileged_fields: frozenset[str]
    request_model_suffixes: tuple[str, ...]
    sql_calls: frozenset[str]
    sql_safe_interpolation: re.Pattern[str]

    def authenticates(self, name: str) -> bool:
        return name in self.auth_dependencies or any(p.search(name) for p in self.auth_patterns)

    def restricts_role(self, name: str) -> bool:
        return any(p.search(name) for p in self.role_patterns)

    def is_guard(self, call_name: str) -> bool:
        return call_name in self.guard_calls or any(p.search(call_name) for p in self.guard_patterns)

    def public_reason(self, path: str) -> str | None:
        return next((why for pattern, why in self.public_routes if pattern.search(path)), None)


@dataclass
class PerformanceSettings:
    blocking_calls: frozenset[str]
    db_methods: frozenset[str]


@dataclass
class MigrationSettings:
    """`[scan.migrations]`: where the migrations live and what the rules enforce."""

    roots: tuple[str, ...] = ()
    revision_max_length: int = 32
    require_rls: bool = False
    rls_schemas: tuple[str, ...] = ()


@dataclass
class ScanSettings:
    root: Path
    python_roots: tuple[str, ...]
    skip_parts: tuple[str, ...]
    internal_prefixes: tuple[str, ...]
    entrypoints: tuple[str, ...]
    app_constructors: frozenset[str]
    security: SecuritySettings
    performance: PerformanceSettings
    migrations: MigrationSettings = field(default_factory=MigrationSettings)
    # Set by the shared analysis service after bounded discovery. Not repo config.
    admitted_python_files: tuple[str, ...] | None = None
    max_file_bytes: int = 2_000_000

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def is_internal(self, rel: str) -> bool:
        return rel.startswith(self.internal_prefixes)


def _patterns(values: list[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(v) for v in values)


def from_config(cfg: Config | None = None, *, max_file_bytes: int = 2_000_000) -> ScanSettings:
    cfg = cfg if cfg is not None else load_config()
    section = merge(DEFAULTS, cfg.section("scan"))
    sec, perf, mig = section["security"], section["performance"], section["migrations"]
    return ScanSettings(
        root=cfg.root,
        python_roots=tuple(section["python_roots"]),
        skip_parts=tuple(section["skip_parts"]),
        internal_prefixes=tuple(section["internal_prefixes"]),
        entrypoints=tuple(section["entrypoints"]),
        app_constructors=frozenset(section["app_constructors"]),
        security=SecuritySettings(
            auth_dependencies=frozenset(sec["auth_dependencies"]),
            auth_patterns=_patterns(sec["auth_dependency_patterns"]),
            role_patterns=_patterns(sec["role_dependency_patterns"]),
            optional_dependencies=frozenset(sec["optional_dependencies"]),
            guard_calls=frozenset(sec["guard_calls"]),
            guard_patterns=_patterns(sec["guard_call_patterns"]),
            body_auth_call=re.compile(sec["body_auth_call_pattern"]),
            secret_header=re.compile(sec["secret_header_pattern"], re.I),
            object_id=re.compile(sec["object_id_pattern"]),
            public_routes=tuple((re.compile(k), v) for k, v in sec["public_routes"].items()),
            privileged_fields=frozenset(sec["privileged_fields"]),
            request_model_suffixes=tuple(sec["request_model_suffixes"]),
            sql_calls=frozenset(sec["sql_calls"]),
            sql_safe_interpolation=re.compile(sec["sql_safe_interpolation"]),
        ),
        performance=PerformanceSettings(
            blocking_calls=frozenset(perf["blocking_calls"]),
            db_methods=frozenset(perf["db_methods"]),
        ),
        migrations=MigrationSettings(
            roots=tuple(mig["roots"]),
            revision_max_length=int(mig["revision_max_length"]),
            require_rls=bool(mig["require_rls"]),
            rls_schemas=tuple(mig["rls_schemas"]),
        ),
        max_file_bytes=max_file_bytes,
    )

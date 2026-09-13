"""Syntax-backed JS/TS facts; never load a target package or run its build.

Tree-sitter establishes syntax and lexical ownership, not runtime dispatch or type
resolution. Callers must keep those distinctions in the resulting graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import re

EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}


@dataclass
class Symbol:
    name: str
    qualified: str
    line: int
    end_line: int
    start: int
    end: int
    kind: str
    exported: bool
    is_async: bool
    default_export: bool = False


@dataclass
class JSFacts:
    symbols: list[Symbol] = field(default_factory=list)
    # (module, local binding, exported name, line); * denotes a namespace import.
    imports: list[tuple[str, str, str, int]] = field(default_factory=list)
    calls: list[tuple[str, str, int]] = field(default_factory=list)
    # (owning symbol, HTTP method, literal/template URL, dynamic, line)
    requests: list[tuple[str, str, str, bool, int]] = field(default_factory=list)
    # (owning symbol, SQL text, line, dynamic)
    queries: list[tuple[str, str, int, bool]] = field(default_factory=list)
    errors: list[int] = field(default_factory=list)
    uncertain_requests: list[int] = field(default_factory=list)


@lru_cache(maxsize=3)
def _language(kind: str):
    from tree_sitter import Language
    if kind == "javascript":
        import tree_sitter_javascript
        return Language(tree_sitter_javascript.language())
    import tree_sitter_typescript
    return Language(tree_sitter_typescript.language_tsx() if kind == "tsx"
                    else tree_sitter_typescript.language_typescript())


def available() -> bool:
    try:
        for kind in ("javascript", "typescript", "tsx"):
            _language(kind)
        return True
    except (ImportError, AttributeError, TypeError, ValueError, RuntimeError):
        return False


def parse_source(text: str, suffix: str) -> JSFacts:
    from tree_sitter import Parser
    data = text.encode("utf-8")
    kind = "tsx" if suffix == ".tsx" else "typescript" if suffix in {".ts", ".mts", ".cts"} else "javascript"
    root = Parser(_language(kind)).parse(data).root_node
    facts = JSFacts()

    def value(node) -> str:
        return data[node.start_byte:node.end_byte].decode("utf-8") if node else ""

    def literal(node) -> tuple[str, bool] | None:
        if node is None or node.type not in {"string", "template_string"}:
            return None
        raw = value(node)[1:-1]
        dynamic = any(child.type == "template_substitution" for child in node.named_children)
        if dynamic:
            # Replace by byte spans, not a regex that breaks nested expressions.
            pieces, at = [], node.start_byte + 1
            for child in node.named_children:
                if child.type == "template_substitution":
                    pieces.append(data[at:child.start_byte].decode("utf-8"))
                    pieces.append("{dynamic}")
                    at = child.end_byte
            pieces.append(data[at:node.end_byte - 1].decode("utf-8"))
            raw = "".join(pieces)
        # Escaped URLs/SQL need a language string decoder; don't assert a target.
        if "\\" in raw:
            return None
        return raw, dynamic

    def owner_for(node) -> str:
        owned = [s for s in facts.symbols if s.start <= node.start_byte < s.end]
        return min(owned, key=lambda s: s.end - s.start).qualified if owned else ""

    stack = [(root, ())]
    nodes = []
    while stack:
        node, scope = stack.pop()
        nodes.append(node)
        if node.type == "ERROR" or node.is_missing:
            facts.errors.append(node.start_point.row + 1)
        name_node = node.child_by_field_name("name")
        name = value(name_node)
        symbol_kind = ""
        if node.type in {"function_declaration", "generator_function_declaration", "method_definition"}:
            symbol_kind = "function"
        elif node.type in {"class_declaration", "abstract_class_declaration"}:
            symbol_kind = "class"
        elif node.type in {"arrow_function", "function_expression", "generator_function"}:
            parent = node.parent
            if parent and parent.type in {"variable_declarator", "pair"}:
                name = value(parent.child_by_field_name("name") or parent.child_by_field_name("key"))
            elif parent and parent.type == "export_statement":
                name = "default"
            else:
                # Anonymous callbacks get a stable location-derived scope, preventing
                # their calls being attributed to a neighbouring top-level function.
                name = name or f"anonymous@{node.start_point.row + 1}:{node.start_point.column}"
            symbol_kind = "function"
        if symbol_kind and name:
            qualified = ".".join((*scope, name))
            ancestor = node.parent
            exported = False
            default_export = False
            while ancestor and ancestor.type in {"variable_declarator", "lexical_declaration", "variable_declaration", "export_statement"}:
                exported = exported or ancestor.type == "export_statement"
                default_export = default_export or (ancestor.type == "export_statement" and any(c.type == "default" for c in ancestor.children))
                ancestor = ancestor.parent
            facts.symbols.append(Symbol(name, qualified, node.start_point.row + 1,
                                        node.end_point.row + 1, node.start_byte, node.end_byte,
                                        symbol_kind, exported, any(c.type == "async" for c in node.children), default_export))
            scope = (*scope, name)
        stack.extend((child, scope) for child in reversed(node.named_children))

    # `export { GET }` is common in generated or adapter-style Next.js route files.
    # It exports a local declaration without placing that declaration underneath the
    # export_statement node, so recover the export status from the specifier.
    reexports: dict[str, str] = {}
    for node in nodes:
        if node.type != "export_statement" or node.child_by_field_name("source") is not None:
            continue
        for specifier in walk(node):
            if specifier.type != "export_specifier":
                continue
            local = value(specifier.child_by_field_name("name"))
            public = value(specifier.child_by_field_name("alias")) or local
            if local:
                reexports[local] = public
    for symbol in facts.symbols:
        public = reexports.get(symbol.name)
        if public:
            symbol.exported = True
            symbol.default_export = symbol.default_export or public == "default"

    for node in nodes:
        line = node.start_point.row + 1
        if node.type in {"import_statement", "export_statement"}:
            module = literal(node.child_by_field_name("source"))
            if module and not module[1]:
                found = False
                for child in walk(node):
                    if child.type == "import_specifier":
                        imported = value(child.child_by_field_name("name"))
                        local = value(child.child_by_field_name("alias")) or imported
                        facts.imports.append((module[0], local, imported, line))
                        found = True
                    elif child.type == "namespace_import":
                        facts.imports.append((module[0], value(child.named_children[-1]), "*", line))
                        found = True
                    elif child.type == "import_clause":
                        for binding in child.named_children:
                            if binding.type == "identifier":
                                facts.imports.append((module[0], value(binding), "default", line))
                                found = True
                if not found:
                    facts.imports.append((module[0], "", "", line))
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        called = value(function)
        arguments = node.child_by_field_name("arguments")
        args = arguments.named_children if arguments else []
        owner = owner_for(node)
        # Tagged templates are call_expression nodes with template_string arguments.
        if arguments and arguments.type == "template_string":
            sql = literal(arguments)
            if sql and re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b", sql[0], re.I):
                facts.queries.append((owner, sql[0], line, sql[1]))
        facts.calls.append((owner, called, line))
        if called in {"require", "import"} and args:
            module = literal(args[0])
            if module and not module[1]:
                parent = node.parent
                binding = value(parent.child_by_field_name("name")) if parent and parent.type == "variable_declarator" else ""
                facts.imports.append((module[0], binding if binding.isidentifier() else "", "*", line))
        first = literal(args[0]) if args else None
        if called in {"fetch", "globalThis.fetch"} or re.fullmatch(r"(?:api|axios)\.(?:get|post|put|patch|delete|head|options)", called):
            if first is None:
                facts.uncertain_requests.append(line)
            else:
                method = called.rsplit(".", 1)[-1].upper() if called not in {"fetch", "globalThis.fetch"} else "GET"
                if called in {"fetch", "globalThis.fetch"} and len(args) > 1:
                    if args[1].type != "object" or any(c.type == "spread_element" for c in args[1].named_children):
                        method = "UNKNOWN"
                    else:
                        for pair in args[1].named_children:
                            if value(pair.child_by_field_name("key")).strip("\"'") == "method":
                                method_value = literal(pair.child_by_field_name("value"))
                                method = method_value[0].upper() if method_value and not method_value[1] else "UNKNOWN"
                if method == "UNKNOWN":
                    facts.uncertain_requests.append(line)
                facts.requests.append((owner, method, first[0], first[1], line))
        if first and re.fullmatch(r".*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)", called):
            if re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|ALTER)\b", first[0], re.I):
                facts.queries.append((owner, first[0], line, first[1]))
    facts.errors = sorted(set(facts.errors))
    return facts


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))

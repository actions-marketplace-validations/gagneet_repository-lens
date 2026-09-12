# Extractor plugins

The scanner has a deliberately small extension seam for languages and databases that
are not in the focused Python/JavaScript/TypeScript/PostgreSQL core. Plugins are trusted
Python code: they run in the same process as Repository Lens and are not a sandbox.

## Contract

Register a factory in the `repolens.extractors` entry-point group. The factory must
return an object with:

```python
from repolens.impact.plugins import Extraction, SourceFile

class ExampleExtractor:
    api_version = 1
    name = "example"
    version = "1.0.0"
    extensions = (".example",)

    def analyze(self, source: SourceFile) -> Extraction:
        # Return only repository-relative paths and JSON-serializable metadata.
        return Extraction()
```

The package metadata can register it with:

```toml
[project.entry-points."repolens.extractors"]
example = "my_package:ExampleExtractor"
```

Suffixes must be lowercase and begin with a dot. Node IDs must be stable, paths must be
repository-relative, and every edge/diagnostic must refer to a node already returned by
the extractor or to a built-in node. The scanner validates the complete result before
merging it and caps records per source file.

## Enabling a plugin

Discovery is metadata-only:

```bash
repolens analyze --list-plugins
```

Loading is explicit and command-line controlled:

```bash
repolens analyze --plugin example --out .repolens/analysis
```

The local API does not accept plugin names and never loads entry points during a
request. This avoids turning a network-facing request into arbitrary code execution.
The plugin name, version, API version and extensions are recorded in graph metadata.

## Design guidance

An adapter should report syntax or declared evidence, not claim runtime behavior. For a
database extractor, use a distinct node kind and a detail field that says whether the
reference came from a migration, query literal, schema file or live catalog. A C#
adapter can later use Roslyn or a separate SARIF producer without changing the core
graph format.

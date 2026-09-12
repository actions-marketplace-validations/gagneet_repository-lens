"""FeatureTrace: `@featuretrace:<tag>` markers, the maps built from them, and their audit.

A marker declares which feature a file belongs to and how data moves through it:

    # @featuretrace:<tag> — <one-line description>
    # Layer: frontend|router|service|domain|worker|cron|model|test|seed|script|migration|config|docs
    # Data flow: <A> → <B> → <C> (<scope>)
    # Related: <file-path>
    #          <file-path>
    # Toggle: <feature_toggle_key>
    # Collection: <store>, <store>
    # Table: <schema.table>
    # Tests: <test_file>

`maps` renders every tag as a Mermaid flowchart, a mindmap, a markdown tour and a JSON
graph; `audit` checks the markers themselves and ratchets their quality.
"""

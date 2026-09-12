"""Console setup."""
from __future__ import annotations

import sys


def utf8_console() -> None:
    """Print arrows and box-drawing characters without dying on a cp1252 console.

    On a Windows checkout stdout defaults to cp1252 and `print` raises
    UnicodeEncodeError, so a generator dies AFTER doing its work and before saying so —
    and the post-merge hook that calls it dies with it. CI (UTF-8 by default) never
    sees this, which is what makes it easy to leave broken.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):  # pragma: no cover - platform shim
            stream.reconfigure(encoding="utf-8", errors="replace")

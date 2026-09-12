"""Start the authenticated loopback API for one local checkout."""
from __future__ import annotations

import argparse
import os
from pathlib import Path


def main(argv=None, *, config=None, prog=None) -> int:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    token = os.environ.get("REPOLENS_API_TOKEN", "")
    if len(token) < 32:
        parser.error("set REPOLENS_API_TOKEN to a random token of at least 32 characters")
    try:
        import uvicorn
        from .app import create_app
    except ImportError:
        parser.error("install the API dependencies: pip install 'repolens[stack,api]'")
    root = config.root if config else Path.cwd()
    uvicorn.run(create_app(root, token), host="127.0.0.1", port=args.port, access_log=False)
    return 0

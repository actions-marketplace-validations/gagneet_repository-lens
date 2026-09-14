"""Bounded source reads shared by indexing and cache validation.

This is defensive local-file handling, not an OS sandbox. Hosted workers still need
an immutable checkout, process/resource isolation and an egress policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat


@dataclass(frozen=True)
class SourceRead:
    """One bounded read: the text when `status` is "read", otherwise None and why (too_large, binary, ...)."""
    text: str | None
    status: str
    size: int = 0

    def fingerprint(self, relative_path: str) -> bytes:
        """Hash exactly the input the scanner used, including skipped-file status."""
        content = self.text.encode("utf-8") if self.text is not None else b""
        prefix = f"{relative_path}\0{self.status}\0{self.size}\0".encode("utf-8")
        return hashlib.sha256(prefix + content).digest()


def read_source(root: Path, path: Path, max_bytes: int) -> SourceRead:
    """Never follow a file symlink or allocate an unbounded source buffer."""
    if max_bytes < 1:
        raise ValueError("max_file_bytes must be positive")
    descriptor: int | None = None
    raw = b""
    try:
        if not path.resolve().is_relative_to(root.resolve()):
            return SourceRead(None, "outside_root")
        if path.is_symlink():
            return SourceRead(None, "symlink")
        # O_NONBLOCK keeps a file replaced with a FIFO from hanging the scanner.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None  # ownership transferred to the context manager
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return SourceRead(None, "not_regular")
            if info.st_size > max_bytes:
                return SourceRead(None, "too_large", info.st_size)
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return SourceRead(None, "too_large", len(raw))
        if b"\0" in raw:
            return SourceRead(None, "binary", len(raw))
        # `utf-8-sig`: a leading byte-order mark is valid in Python and JS sources, and
        # left in place it is a parse error on line 1 that marks the whole scan incomplete.
        return SourceRead(raw.decode("utf-8-sig"), "read", len(raw))
    except UnicodeDecodeError:
        return SourceRead(None, "invalid_utf8", len(raw))
    except (OSError, ValueError, RuntimeError):
        return SourceRead(None, "unreadable")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

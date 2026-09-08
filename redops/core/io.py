"""Bounded local input and atomic output helpers."""

import os
import tempfile
from pathlib import Path

from redops.core.errors import InputError


def read_bounded(path: Path, limit: int = 8 * 1024 * 1024) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise InputError(f"Input exceeds the {limit}-byte limit.")
    return content


def require_distinct_paths(paths: list[Path]) -> None:
    """Reject aliases before an audit append or export can damage another artifact."""
    for index, path in enumerate(paths):
        for previous in paths[:index]:
            if path.resolve() == previous.resolve() or (
                path.exists() and previous.exists() and path.samefile(previous)
            ):
                raise InputError("Input, output, database, and audit paths must be distinct.")


def atomic_write(path: Path, content: str | bytes, *, overwrite: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".redops-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content.encode("utf-8") if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            # A hard link publishes the complete file atomically and fails if it exists.
            os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)

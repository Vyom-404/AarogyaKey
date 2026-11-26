"""No-follow, bounded regular-file reads for untrusted input paths."""

from __future__ import annotations

import os
import stat
import hashlib
from pathlib import Path


def read_regular_file(path: Path, maximum_bytes: int) -> bytes:
    """Read a bounded regular file without following a symlink at open time."""
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("unsafe_or_unreadable_file") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("unsafe_or_unreadable_file") from None
        if info.st_size > maximum_bytes:
            raise ValueError("max_file_size_exceeded") from None
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum_bytes:
                raise ValueError("max_file_size_exceeded") from None
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def hash_regular_file(path: Path) -> str:
    """Hash a regular file without following links or loading it all in memory."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("unsafe_or_unreadable_file") from None
    digest = hashlib.sha256()
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("unsafe_or_unreadable_file") from None
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(descriptor)

"""Deterministic test file generator for integration tests."""

import hashlib
from pathlib import Path


def generate_test_file(path: Path, size_bytes: int, seed: int = 42) -> tuple[Path, str]:
    """
    Generate a deterministic test file of given size and return (path, sha256_hex).
    Writes in 64 KiB blocks to minimize memory usage.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    hasher = hashlib.sha256()
    block_size = 65536
    pattern = bytes((seed + i) % 256 for i in range(block_size))

    remaining = size_bytes
    with open(path, "wb") as f:
        while remaining > 0:
            chunk = pattern[: min(remaining, block_size)]
            f.write(chunk)
            hasher.update(chunk)
            remaining -= len(chunk)

    return path, hasher.hexdigest()

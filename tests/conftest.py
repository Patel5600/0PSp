"""Pytest configuration and fixture setup for 0PSP test suite."""

import os
from pathlib import Path


def pytest_configure(config):
    """Auto-detect native library if not explicitly provided in environment."""
    if "PSP_NULLIFIER_LIBRARY" not in os.environ:
        repo_root = Path(__file__).resolve().parent.parent
        candidates = [
            repo_root / "native" / "build" / "libpsp_native.dll",
            repo_root / "native" / "build" / "libpsp_nullifier.dll",
            repo_root / "native" / "build" / "libpsp_native.so",
            repo_root / "native" / "build" / "libpsp_nullifier.so",
        ]
        for candidate in candidates:
            if candidate.is_file():
                os.environ["PSP_NULLIFIER_LIBRARY"] = str(candidate)
                break

"""Hypothesis fuzz targets for fleet ingest. Skipped unless the `verify` extra (hypothesis) is installed.

`PQCSCAN_FUZZ_EXAMPLES` raises the example count (default 200). Run: pytest -m fuzz tests/fuzz
"""
from __future__ import annotations

import os

import pytest

try:
    from hypothesis import HealthCheck, settings
except ImportError:                                        # tests/fuzz/test_*.py importorskip on their own
    settings = None

if settings is not None:
    settings.register_profile(
        "pqcscan-fuzz",
        max_examples=int(os.environ.get("PQCSCAN_FUZZ_EXAMPLES", "200")),
        deadline=None,
        suppress_health_check=list(HealthCheck),           # hostile inputs are big and slow to generate by design
        print_blob=True,
    )
    settings.load_profile("pqcscan-fuzz")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/fuzz/" in item.nodeid.replace("\\", "/"):
            item.add_marker(pytest.mark.fuzz)

"""Cross-OS graceful degradation.

Every probe's `applies()` gate must be safe to evaluate on any OS with a bare
ScanContext (no target, no paths) — that gate is what lets POSIX-specific
probes skip cleanly on Windows/macOS instead of crashing. The runner also
wraps `run()` in try/except, but a probe should never raise from `applies()`.
Also: importing every probe module must not fail on this OS (e.g. a Windows
probe importing `winreg` lazily, not at module top-level).
"""
import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes._registry import default_registry


def _bare_ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


@pytest.mark.asyncio
async def test_every_probe_applies_is_safe_on_bare_context():
    reg = default_registry()
    ctx = _bare_ctx()
    failures = []
    for probe in reg.all():
        try:
            result = await probe.applies(ctx)
        except Exception as e:
            failures.append(f"{probe.id}: {type(e).__name__}: {e}")
            continue
        if not isinstance(result, bool):
            failures.append(f"{probe.id}: applies() returned {type(result).__name__}, not bool")
    assert not failures, "probes with unsafe applies():\n" + "\n".join(failures)


def test_registry_imports_every_probe_module_on_this_os():
    # default_registry() import-loads all ~160 probe modules; if any did a
    # top-level OS-specific import (winreg, etc.) this would already have
    # raised. Reaching here with a full registry proves clean cross-OS import.
    reg = default_registry()
    assert len(reg.ids()) > 150

import pytest

from pqcscan.core.types import (
    Capability,
    Classification,
    Finding,
    ProbeFamily,
    Severity,
)
from pqcscan.probes._base import Probe
from pqcscan.probes._registry import Registry
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo


class _OneFindingProbe(Probe):
    id = "test.one"
    family = ProbeFamily.AUX

    async def run(self, ctx, emit):
        emit(Finding(
            probe_id=self.id,
            algorithm="RSA-2048",
            classification=Classification.TINGGI,
            severity=Severity.HIGH,
            title="hello",
        ))


class _RootOnlyProbe(Probe):
    id = "test.root"
    family = ProbeFamily.AUX
    requires = frozenset({Capability.ROOT})

    async def run(self, ctx, emit):
        emit(Finding(
            probe_id=self.id,
            algorithm="X",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title="should not fire in user mode",
        ))


class _CrashProbe(Probe):
    id = "test.crash"
    family = ProbeFamily.AUX

    async def run(self, ctx, emit):
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_runner_emits_findings_and_persists(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    bus = EventBus()
    reg = Registry(); reg.register(_OneFindingProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=bus)
    scan_id = await runner.run(mode="user", available_capabilities=set())
    findings = repo.list_findings(scan_id)
    assert len(findings) == 1 and findings[0].title == "hello"


@pytest.mark.asyncio
async def test_root_only_probe_skipped_in_user_mode(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    bus = EventBus()
    reg = Registry(); reg.register(_RootOnlyProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=bus)
    scan_id = await runner.run(mode="user", available_capabilities=set())
    findings = repo.list_findings(scan_id)
    assert len(findings) == 1
    assert findings[0].classification == "info"
    assert "skipped" in findings[0].title.lower()
    # Skip notes bypass the emit() confidence pipeline, so the confidence must
    # be stamped explicitly — a definite fact, not a detection heuristic.
    assert findings[0].evidence["confidence"] == "high"


@pytest.mark.asyncio
async def test_crash_does_not_abort_run(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    bus = EventBus()
    reg = Registry()
    reg.register(_CrashProbe())
    reg.register(_OneFindingProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=bus)
    scan_id = await runner.run(mode="user", available_capabilities=set())
    findings = repo.list_findings(scan_id)
    classifications = {f.classification for f in findings}
    assert "error" in classifications
    assert "tinggi" in classifications
    scan = repo.get_scan(scan_id)
    assert scan is not None and scan.status == "done"

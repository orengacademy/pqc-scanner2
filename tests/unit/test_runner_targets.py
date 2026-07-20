"""The runner must forward scan_paths/server_target/ot_targets into the
ScanContext so target-gated probes actually activate."""
import pytest

from pqcscan.core.types import (
    Classification,
    Finding,
    ProbeFamily,
    Severity,
)
from pqcscan.probes._base import OTTarget, Probe
from pqcscan.probes._registry import Registry
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo


class _TargetGatedProbe(Probe):
    id = "test.target"
    family = ProbeFamily.NETWORK

    async def applies(self, ctx):
        return ctx.server_target is not None

    async def run(self, ctx, emit):
        emit(Finding(
            probe_id=self.id,
            algorithm="ECDHE",
            classification=Classification.TINGGI,
            severity=Severity.HIGH,
            title=f"scanned {ctx.server_target}",
        ))


class _ContextEchoProbe(Probe):
    id = "test.echo"
    family = ProbeFamily.AUX

    async def run(self, ctx, emit):
        emit(Finding(
            probe_id=self.id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title="ctx",
            evidence={
                "paths": [str(p) for p in ctx.scan_paths],
                "ot": [t.host for t in ctx.ot_targets],
            },
        ))


@pytest.mark.asyncio
async def test_target_gated_probe_skips_without_target(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    reg = Registry(); reg.register(_TargetGatedProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=EventBus())
    scan_id = await runner.run(mode="user", available_capabilities=set())
    assert repo.list_findings(scan_id) == []


@pytest.mark.asyncio
async def test_target_gated_probe_fires_with_target(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    reg = Registry(); reg.register(_TargetGatedProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=EventBus())
    scan_id = await runner.run(
        mode="user", available_capabilities=set(),
        server_target="example.com:443",
    )
    findings = repo.list_findings(scan_id)
    assert len(findings) == 1
    assert "example.com:443" in findings[0].title


@pytest.mark.asyncio
async def test_paths_and_ot_reach_context(tmp_db_path):
    from pathlib import Path
    repo = Repo(tmp_db_path); repo.init_schema()
    reg = Registry(); reg.register(_ContextEchoProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=EventBus())
    scan_id = await runner.run(
        mode="user", available_capabilities=set(),
        scan_paths=[Path("/etc/ssl")],
        ot_targets=[OTTarget(host="plc.local", port=502, proto_hint="modbus")],
    )
    f = repo.list_findings(scan_id)[0]
    assert f.evidence["paths"] == ["/etc/ssl"]
    assert f.evidence["ot"] == ["plc.local"]

from __future__ import annotations

import asyncio
import platform
from collections import defaultdict
from pathlib import Path

from loguru import logger

from pqcscan.compliance.engine import ComplianceEngine
from pqcscan.core.remediation import enrich as enrich_remediation
from pqcscan.core.types import Capability, Classification, Finding, Severity
from pqcscan.probes._base import OTTarget, Probe, ScanContext
from pqcscan.probes._registry import Registry
from pqcscan.runner.event_bus import (
    EventBus,
    FindingDiscovered,
    ScanCompleted,
    StageCompleted,
    StageStarted,
)
from pqcscan.store.repo import Repo


class ProbeRunner:
    def __init__(
        self,
        *,
        registry: Registry,
        repo: Repo,
        bus: EventBus,
        per_probe_timeout_s: float = 30.0,
        compliance: ComplianceEngine | None = None,
    ) -> None:
        self.registry = registry
        self.repo = repo
        self.bus = bus
        self.timeout = per_probe_timeout_s
        # Default: load every YAML in pqcscan/compliance/frameworks/.
        self.compliance = compliance if compliance is not None else ComplianceEngine()
        # Strong refs to fire-and-forget event-bus publish tasks (RUF006).
        self._bg_tasks: set[asyncio.Task[None]] = set()

    async def run(
        self,
        *,
        mode: str,
        available_capabilities: set[Capability],
        scan_paths: list[Path] | None = None,
        server_target: str | None = None,
        ot_targets: list[OTTarget] | None = None,
    ) -> int:
        probe_versions = {p.id: p.version for p in self.registry.all()}
        scan_id = self.repo.create_scan(
            mode=mode,
            probe_versions=probe_versions,
            tool_versions={"python": platform.python_version()},
        )
        ctx = ScanContext(
            scan_id=scan_id,
            mode=mode,
            available_capabilities=available_capabilities,
            scan_paths=scan_paths or [],
            server_target=server_target,
            ot_targets=ot_targets or [],
        )

        by_family: dict[str, list[Probe]] = defaultdict(list)
        for p in self.registry.all():
            by_family[p.family.value].append(p)

        for family_name, probes in by_family.items():
            await self.bus.publish(StageStarted(stage=family_name))
            await asyncio.gather(*(self._run_one(p, ctx) for p in probes))
            await self.bus.publish(StageCompleted(stage=family_name))

        self.repo.finish_scan(scan_id, status="done")
        await self.bus.publish(ScanCompleted(scan_id=scan_id))
        return scan_id

    async def _run_one(self, probe: Probe, ctx: ScanContext) -> None:
        if not probe.requires.issubset(ctx.available_capabilities):
            self.repo.record_finding(ctx.scan_id, Finding(
                probe_id=probe.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"skipped: probe requires {sorted(c.value for c in probe.requires)}",
                evidence={"reason": "skipped_privilege"},
            ))
            return
        if not await probe.applies(ctx):
            return

        def emit(f: Finding) -> None:
            # Centrally attach typed PQC-replacement guidance so every stored
            # finding carries a migration target + deadline without each probe
            # duplicating the mapping (probe-authored remediation is kept).
            enrich_remediation(f)
            finding_id = self.repo.record_finding(ctx.scan_id, f)
            for verdict in self.compliance.evaluate(f):
                self.repo.record_framework_view(
                    finding_id,
                    framework=verdict.framework,
                    clause=verdict.clause,
                    verdict=verdict.verdict,
                    deadline=verdict.deadline,
                )
            task = asyncio.create_task(self.bus.publish(FindingDiscovered(
                probe_id=f.probe_id, title=f.title, algorithm=f.algorithm,
                classification=f.classification.value, severity=f.severity.value,
            )))
            self._bg_tasks.add(task)
            task.add_done_callback(self._bg_tasks.discard)

        try:
            await asyncio.wait_for(probe.run(ctx, emit), timeout=self.timeout)
        except TimeoutError:
            self.repo.record_probe_error(
                ctx.scan_id, probe_id=probe.id, message="timeout"
            )
        except Exception as e:
            logger.exception("probe {} crashed", probe.id)
            self.repo.record_probe_error(
                ctx.scan_id, probe_id=probe.id, message=str(e)
            )

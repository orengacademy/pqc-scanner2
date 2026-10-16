from __future__ import annotations

import asyncio
import copy
import platform
import socket
from collections import defaultdict
from pathlib import Path

from loguru import logger

from pqcscan.compliance.engine import ComplianceEngine
from pqcscan.core.confidence import assess as assess_confidence
from pqcscan.core.remediation import enrich as enrich_remediation
from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import OTTarget, Probe, ScanContext, SniffConfig
from pqcscan.probes._registry import Registry
from pqcscan.runner.event_bus import (
    EventBus,
    FindingDiscovered,
    ScanCompleted,
    StageCompleted,
    StageStarted,
)
from pqcscan.store.repo import Repo


def _target_host(server_target: str) -> str:
    """Host part of a `host[:port]` / `[v6]:port` target ('' if none)."""
    if server_target.startswith("["):
        return server_target[1:].partition("]")[0]
    return server_target.partition(":")[0]


def bind_context(probe: Probe, ctx: ScanContext) -> Probe:
    """Per-scan copy of `probe` with --path / --target applied.

    The registry holds one instance of each probe, built with its host
    defaults (`roots=[/etc, /srv, ...]`, `host="127.0.0.1"`). Rather than
    teach ~90 probes about ScanContext, point a shallow copy at the user's
    inputs here: `scan_paths` REPLACE the default roots (``--path .`` in CI
    must not sweep the runner's /etc and /usr/bin — a plain host scan is the
    run without --path), and `server_target` replaces the default host on
    NETWORK probes. Probes that already resolve ctx themselves (`roots=None`,
    or that read ctx.server_target) are unaffected and follow the same rule.
    """
    roots: list[Path] | None = getattr(probe, "roots", None)
    host = getattr(probe, "host", None)
    want_roots = bool(ctx.scan_paths) and isinstance(roots, list)
    want_host = (
        bool(ctx.server_target) and isinstance(host, str)
        and probe.family is ProbeFamily.NETWORK
    )
    if not (want_roots or want_host):
        return probe
    bound = copy.copy(probe)
    if want_roots:
        bound.roots = list(ctx.scan_paths)  # type: ignore[attr-defined]
    if want_host:
        new_host = _target_host(ctx.server_target or "")
        if new_host:
            bound.host = new_host  # type: ignore[attr-defined]
    return bound


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

    def _scan_metadata(self) -> tuple[dict[str, str], dict[str, str]]:
        return (
            {p.id: p.version for p in self.registry.all()},
            {"python": platform.python_version()},
        )

    def begin_scan_if_idle(self, *, mode: str) -> int | None:
        """Atomically claim a new 'running' scan row, or None if one is already
        running. Lets the daemon create the row synchronously (closing the
        check-then-start race) before handing the id to run()."""
        probe_versions, tool_versions = self._scan_metadata()
        return self.repo.begin_scan_if_idle(
            mode=mode, probe_versions=probe_versions, tool_versions=tool_versions,
            host_fingerprint=socket.gethostname() or None,
        )

    async def run(
        self,
        *,
        mode: str,
        available_capabilities: set[Capability],
        scan_paths: list[Path] | None = None,
        server_target: str | None = None,
        ot_targets: list[OTTarget] | None = None,
        sniff: SniffConfig | None = None,
        scan_id: int | None = None,
    ) -> int:
        if scan_id is None:
            probe_versions, tool_versions = self._scan_metadata()
            scan_id = self.repo.create_scan(
                mode=mode,
                probe_versions=probe_versions,
                tool_versions=tool_versions,
                host_fingerprint=socket.gethostname() or None,
            )
        ctx = ScanContext(
            scan_id=scan_id,
            mode=mode,
            available_capabilities=available_capabilities,
            scan_paths=scan_paths or [],
            server_target=server_target,
            ot_targets=ot_targets or [],
            sniff=sniff,
        )

        by_family: dict[str, list[Probe]] = defaultdict(list)
        for p in self.registry.all():
            by_family[p.family.value].append(p)

        for family_name, probes in by_family.items():
            await self.bus.publish(StageStarted(scan_id=scan_id, stage=family_name))
            await asyncio.gather(*(self._run_one(p, ctx) for p in probes))
            await self.bus.publish(StageCompleted(scan_id=scan_id, stage=family_name))

        self.repo.finish_scan(scan_id, status="done")
        await self.bus.publish(ScanCompleted(scan_id=scan_id))
        return scan_id

    async def _run_one(self, probe: Probe, ctx: ScanContext) -> None:
        probe = bind_context(probe, ctx)
        if not probe.requires.issubset(ctx.available_capabilities):
            self.repo.record_finding(ctx.scan_id, Finding(
                probe_id=probe.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"skipped: probe requires {sorted(c.value for c in probe.requires)}",
                evidence={"reason": "skipped_privilege", "confidence": "high"},
                confidence="high",
            ))
            return
        # applies() runs inside the same timeout/error envelope as run(): a
        # raising or hanging applies() must degrade to a probe-error row, not
        # abort the whole scan out of the bare asyncio.gather above.
        try:
            if not await asyncio.wait_for(probe.applies(ctx), timeout=self.timeout):
                return
        except TimeoutError:
            self.repo.record_probe_error(
                ctx.scan_id, probe_id=probe.id, message="applies() timeout"
            )
            return
        except Exception as e:
            logger.exception("probe {} applies() crashed", probe.id)
            self.repo.record_probe_error(
                ctx.scan_id, probe_id=probe.id, message=f"applies() failed: {e}"
            )
            return

        def emit(f: Finding) -> None:
            # Centrally attach typed PQC-replacement guidance so every stored
            # finding carries a migration target + deadline without each probe
            # duplicating the mapping (probe-authored remediation is kept).
            enrich_remediation(f)
            # Assign detection confidence (down-ranks regex-in-a-comment etc.)
            # and persist it in evidence so it survives to reports/SARIF/CBOM
            # (the findings table has no dedicated column).
            f.confidence = assess_confidence(f.probe_id, f.evidence)
            f.evidence = {**f.evidence, "confidence": f.confidence}
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
                scan_id=ctx.scan_id,
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

"""host.lynis — Lynis (GPL-3) Linux system audit."""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none

_REPORT_PATH = Path("/var/log/lynis-report.dat")
_WARN_RE = re.compile(r"^warning\[\]=(.+)$", re.MULTILINE)
_SUGG_RE = re.compile(r"^suggestion\[\]=(.+)$", re.MULTILINE)


class HostLynis(Probe):
    id = "host.lynis"
    family = ProbeFamily.HOST
    requires = frozenset({Capability.ROOT})  # full audit needs root
    framework_tags = ("bukukerja:host", "mykripto:host")

    def __init__(self, lynis_bin: str | None = None, timeout_s: float = 600.0):
        self.lynis_bin = lynis_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return (
            Capability.ROOT in ctx.available_capabilities
            and resolve_or_none(self.lynis_bin, "lynis") is not None
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = resolve_or_none(self.lynis_bin, "lynis")
        if bin_path is None:
            return
        proc = await asyncio.create_subprocess_exec(
            str(bin_path), "audit", "system", "--quick",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=self.timeout_s)
        except TimeoutError:
            proc.kill()
            return
        if not _REPORT_PATH.exists():
            return
        try:
            text = _REPORT_PATH.read_text(errors="replace")
        except OSError:
            return
        for m in _WARN_RE.finditer(text):
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title=f"lynis warning: {m.group(1)[:160]}",
                evidence={"raw": m.group(1)},
            ))
        for m in _SUGG_RE.finditer(text):
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=f"lynis suggestion: {m.group(1)[:160]}",
                evidence={"raw": m.group(1)},
            ))

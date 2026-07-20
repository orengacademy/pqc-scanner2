"""host.platform_info — record the host OS/arch/runtime the scan ran on.

Always applies, on every platform. It gives the report an explicit statement
of *what was scanned* (OS, version, CPU arch, Python/glibc), so a reader can
see the coverage context — and it is the one probe guaranteed to produce a
finding even on an OS where every posix-specific probe skips. Informational
only.
"""
from __future__ import annotations

import platform
import sys

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class HostPlatformInfo(Probe):
    id = "host.platform_info"
    family = ProbeFamily.AUX
    framework_tags = ()

    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        # `overrides` lets tests pin values without monkeypatching platform.*
        self._overrides = overrides or {}

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    def _info(self) -> dict[str, str]:
        o = self._overrides
        info = {
            "os": o.get("os", platform.system() or sys.platform),
            "os_release": o.get("os_release", platform.release()),
            "os_version": o.get("os_version", platform.version()),
            "arch": o.get("arch", platform.machine()),
            "python": o.get("python", platform.python_version()),
            "frozen": o.get("frozen", str(getattr(sys, "frozen", False))),
        }
        # glibc version is meaningful only on Linux; guard everything.
        try:
            libc, libc_ver = platform.libc_ver()
            if libc:
                info["libc"] = f"{libc} {libc_ver}".strip()
        except Exception:
            pass
        return info

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        info = self._info()
        title = (
            f"Scanned on {info['os']} {info.get('os_release', '')} "
            f"({info['arch']}), Python {info['python']}"
        ).strip()
        emit(Finding(
            probe_id=self.id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=title,
            evidence=info,
        ))

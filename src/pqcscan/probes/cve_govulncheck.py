"""cve.govulncheck — `govulncheck` (Apache-2.0) Go module vuln scanner."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none


class CveGovulncheck(Probe):
    id = "cve.govulncheck"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    def __init__(self, roots: list[Path] | None = None,
                 bin_name: str | None = None, timeout_s: float = 120.0):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]
        self.bin_name = bin_name
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return resolve_or_none(self.bin_name, "govulncheck") is not None and any(
            list(r.rglob("go.mod")) for r in self.roots if r.exists()
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        resolved = resolve_or_none(self.bin_name, "govulncheck")
        if resolved is None:
            return
        bin_path = str(resolved)
        for root in self.roots:
            if not root.exists():
                continue
            for go_mod in root.rglob("go.mod"):
                proc = await asyncio.create_subprocess_exec(
                    bin_path, "-json", "./...",
                    cwd=str(go_mod.parent),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
                except asyncio.TimeoutError:
                    proc.kill()
                    continue
                # govulncheck emits NDJSON; one JSON object per line.
                for line in stdout.splitlines():
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    finding = rec.get("finding") or rec.get("osv")
                    if not finding:
                        continue
                    osv_id = finding.get("id") or rec.get("osv", {}).get("id", "?")
                    emit(Finding(
                        probe_id=self.id,
                        algorithm="N/A",
                        classification=Classification.TINGGI,
                        severity=Severity.HIGH,
                        title=f"{osv_id} in Go module at {go_mod.parent}",
                        evidence={"osv_id": osv_id,
                                  "module_dir": str(go_mod.parent),
                                  "summary": finding.get("summary", "")[:200]},
                    ))

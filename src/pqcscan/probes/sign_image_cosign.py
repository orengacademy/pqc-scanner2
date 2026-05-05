"""sign.image.cosign — Sigstore Cosign-signed images (cosign verify availability)."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class SignImageCosign(Probe):
    id = "sign.image.cosign"
    family = ProbeFamily.SIGN
    framework_tags = ("bukukerja:sign", "mykripto:sign")

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which("cosign") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        # Surface cosign presence + version so audit reports can confirm
        # signature-verification capability is available on the host.
        proc = await asyncio.create_subprocess_exec(
            "cosign", "version",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        except TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")
        emit(Finding(
            probe_id=self.id,
            algorithm="cosign",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title="cosign present (Sigstore image-signature verification available)",
            evidence={"version_output": text[:200]},
        ))

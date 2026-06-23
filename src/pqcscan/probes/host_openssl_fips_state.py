"""host.openssl.fips_state — detect whether FIPS 140 mode is active.

FIPS 140 validates *classical* cryptography (RSA/ECDSA/ECDHE, AES, SHA-2).
A FIPS-enabled host is therefore still fully quantum-vulnerable — FIPS does
not imply PQC. This probe reports the host's FIPS posture by reading the
kernel flag /proc/sys/crypto/fips_enabled ("1" = on) and, when available,
running `openssl list -providers` to see whether a FIPS provider is loaded.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class HostOpenSSLFipsState(Probe):
    """Report whether FIPS 140 mode is active (kernel flag and/or provider)."""

    id = "host.openssl.fips_state"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(
        self,
        openssl: str = "openssl",
        fips_enabled_path: Path | None = None,
    ) -> None:
        self.openssl = openssl
        self.fips_enabled_path = fips_enabled_path or Path("/proc/sys/crypto/fips_enabled")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.fips_enabled_path.exists() or shutil.which(self.openssl) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        kernel_value = self._read_kernel_flag()
        provider_loaded, provider_text = await self._read_providers()

        kernel_on = kernel_value == "1"
        fips_active = kernel_on or provider_loaded

        evidence = {
            "fips_enabled": kernel_value,
            "fips_enabled_path": str(self.fips_enabled_path),
            "fips_provider_loaded": provider_loaded,
            "providers_source": provider_text,
        }

        if fips_active:
            emit(Finding(
                probe_id=self.id,
                algorithm="fips-140-classical",
                classification=Classification.SEDERHANA,
                severity=_sev(Classification.SEDERHANA),
                title="FIPS 140 mode active (classical crypto — quantum-vulnerable)",
                evidence=evidence,
                remediation={
                    "snippet": (
                        "# FIPS 140 validated but fully classical crypto — "
                        "quantum-vulnerable; FIPS does not imply PQC.\n"
                        "# Plan PQC migration (ML-KEM/ML-DSA) alongside FIPS."
                    ),
                },
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm="fips-140-classical",
                classification=Classification.INFO,
                severity=_sev(Classification.INFO),
                title="FIPS mode not enabled",
                evidence=evidence,
            ))

    def _read_kernel_flag(self) -> str | None:
        try:
            if self.fips_enabled_path.is_file():
                return self.fips_enabled_path.read_text(errors="replace").strip()
        except OSError:
            return None
        return None

    async def _read_providers(self) -> tuple[bool, str]:
        """Run `openssl list -providers` and detect a loaded FIPS provider."""
        if shutil.which(self.openssl) is None:
            return False, ""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.openssl, "list", "-providers",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (TimeoutError, OSError, ValueError):
            return False, ""
        text = stdout.decode("utf-8", errors="replace")
        return self._providers_have_fips(text), f"{self.openssl} list -providers"

    @staticmethod
    def _providers_have_fips(text: str) -> bool:
        lowered = text.lower()
        return "fips" in lowered or "openssl fips provider" in lowered


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]

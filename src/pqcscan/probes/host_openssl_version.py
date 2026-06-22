"""host.openssl.version — OpenSSL library version & PQC capability tier.

`openssl version -a` pins which crypto stack is installed, which decides PQC
support: OpenSSL >=3.5 ships native ML-KEM/ML-DSA/SLH-DSA; 3.0-3.4 needs the
external oqs-provider; <3.0 (1.1.1, 1.0.x) is EOL and classical-only;
LibreSSL/BoringSSL have their own (non-standard / limited) PQC story.
"""
from __future__ import annotations

import asyncio
import re
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_VERSION_RE = re.compile(r"(OpenSSL|LibreSSL|BoringSSL)\s+(\d+)\.(\d+)\.(\d+)")


class HostOpenSSLVersion(Probe):
    """Report the OpenSSL library version and its PQC capability tier."""

    id = "host.openssl.version"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "mykripto:host", "nacsa-9:pqc-readiness")

    def __init__(
        self,
        openssl: str = "openssl",
        version_output: str | None = None,
    ) -> None:
        self.openssl = openssl
        # version_output is an injectable seam so tests need no real openssl.
        self._version_output = version_output

    async def applies(self, ctx: ScanContext) -> bool:
        return self._version_output is not None or shutil.which(self.openssl) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        out = self._version_output
        if out is None:
            out = await self._run_version()
        if not out:
            return
        first = out.splitlines()[0].strip()
        m = _VERSION_RE.match(first)
        if not m:
            return

        name = m.group(1)
        major, minor, patch = int(m.group(2)), int(m.group(3)), int(m.group(4))
        version = f"{major}.{minor}.{patch}"

        classification, note = self._tier(name, major, minor)
        emit(Finding(
            probe_id=self.id,
            algorithm=f"{name}/{version}",
            classification=classification,
            severity=_severity(classification),
            title=f"Crypto library is {name} {version} — {note}",
            evidence={"version_line": first, "library": name, "version": version},
        ))

    @staticmethod
    def _tier(name: str, major: int, minor: int) -> tuple[Classification, str]:
        if name == "OpenSSL":
            if (major, minor) >= (3, 5):
                return (
                    Classification.PQC_READY,
                    "native ML-KEM/ML-DSA/SLH-DSA support (OpenSSL >=3.5)",
                )
            if major == 3:
                return (
                    Classification.SEDERHANA,
                    "classical; PQC needs the external oqs-provider (OpenSSL <3.5)",
                )
            return (
                Classification.TINGGI,
                "end-of-life and classical-only; no PQC (upgrade to OpenSSL >=3.5)",
            )
        if name in ("LibreSSL", "BoringSSL"):
            return (
                Classification.SEDERHANA,
                f"{name} has no standard NIST PQC support",
            )
        return (Classification.INFO, "unrecognised crypto library")

    async def _run_version(self) -> str | None:
        if not shutil.which(self.openssl):
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.openssl, "version", "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (TimeoutError, OSError):
            return None
        if proc.returncode != 0:
            return None
        return stdout.decode("utf-8", errors="replace")


def _severity(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]

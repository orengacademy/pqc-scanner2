"""host.openssl.pqc_provenance — how the host's OpenSSL provides PQC.

`host.openssl.version` reports the version tier and `host.openssl.oqs_provider`
reports whether the add-on is loaded, but neither answers the question a
migration owner actually asks: *is this host's PQC native or bolted-on?* An
OpenSSL 3.3 host with oqs-provider loaded is PQC-capable **today**, yet the
version probe alone reads it as "classical; needs oqs-provider". The 2025 UMBC
crypto-library survey calls out distinguishing native OpenSSL 3.5 PQC from
OQS-provider-enabled OpenSSL 3.x as a required scanner capability.

This probe synthesizes both signals into one provenance verdict:
- **native**       — OpenSSL >=3.5 (built-in ML-KEM/ML-DSA/SLH-DSA).
- **oqs-provider** — OpenSSL 3.0-3.4 with oqs-provider loaded (add-on; works,
  but non-default, draft-heavy, and a separate dependency to maintain).
- **none**         — OpenSSL <3.5 without oqs-provider (no PQC), or EOL <3.0.

INFO-skip when no `openssl` binary is available (minimal containers / Windows).
"""
from __future__ import annotations

import asyncio
import re
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_VERSION_RE = re.compile(r"(OpenSSL|LibreSSL|BoringSSL)\s+(\d+)\.(\d+)\.(\d+)")


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


class HostOpenSSLPqcProvenance(Probe):
    id = "host.openssl.pqc_provenance"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:tls", "cnsa2:tls", "nacsa-9:pqc-readiness")

    def __init__(
        self,
        openssl_bin: str = "openssl",
        *,
        version_output: str | None = None,
        providers_output: str | None = None,
    ) -> None:
        self.openssl_bin = openssl_bin
        # Injectable seams so tests need no real openssl.
        self._version_output = version_output
        self._providers_output = providers_output

    def _seams_provided(self) -> bool:
        return self._version_output is not None and self._providers_output is not None

    async def applies(self, ctx: ScanContext) -> bool:
        return self._seams_provided() or shutil.which(self.openssl_bin) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        version_out = self._version_output
        if version_out is None:
            version_out = await self._exec("version", "-a")
        if not version_out:
            return
        m = _VERSION_RE.search(version_out.splitlines()[0])
        if not m:
            return
        name = m.group(1)
        major, minor, patch = int(m.group(2)), int(m.group(3)), int(m.group(4))
        version = f"{major}.{minor}.{patch}"

        # Non-OpenSSL stacks have their own (non-standard / limited) PQC story;
        # provider probing does not apply.
        if name != "OpenSSL":
            emit(self._finding(
                Classification.SEDERHANA, "none", name, version,
                oqs_loaded=False,
                title=f"{name} {version} — non-OpenSSL stack, no standard NIST PQC",
            ))
            return

        providers_out = self._providers_output
        if providers_out is None:
            providers_out = await self._exec("list", "-providers") or ""
        low = providers_out.lower()
        oqs_loaded = "oqsprovider" in low or "oqs-provider" in low

        if (major, minor) >= (3, 5):
            provenance, cls = "native", Classification.PQC_READY
            note = "PQC provided NATIVELY (OpenSSL >=3.5 built-in ML-KEM/ML-DSA/SLH-DSA)"
            if oqs_loaded:
                note += "; oqs-provider also loaded (redundant on 3.5+)"
        elif major == 3 and oqs_loaded:
            provenance, cls = "oqs-provider", Classification.PQC_READY
            note = ("PQC provided via the oqs-provider ADD-ON (OpenSSL <3.5) — "
                    "works, but non-default and a separate dependency; upgrade to "
                    "OpenSSL >=3.5 for native support")
        elif major == 3:
            provenance, cls = "none", Classification.SEDERHANA
            note = ("NO PQC — OpenSSL <3.5 and oqs-provider not loaded (upgrade to "
                    ">=3.5 or load oqs-provider)")
        else:
            provenance, cls = "none", Classification.TINGGI
            note = "NO PQC — end-of-life OpenSSL <3.0 (upgrade to >=3.5)"

        emit(self._finding(
            cls, provenance, name, version, oqs_loaded=oqs_loaded,
            title=f"OpenSSL {version} PQC provenance: {provenance} — {note}",
        ))

    def _finding(
        self, cls: Classification, provenance: str, library: str, version: str,
        *, oqs_loaded: bool, title: str,
    ) -> Finding:
        return Finding(
            probe_id=self.id,
            algorithm=f"openssl-pqc-{provenance}",
            classification=cls,
            severity=_severity(cls),
            title=title,
            evidence={
                "library": library,
                "version": version,
                "pqc_provenance": provenance,       # native | oqs-provider | none
                "native_pqc": provenance == "native",
                "oqs_provider_loaded": oqs_loaded,
            },
        )

    async def _exec(self, *args: str) -> str | None:
        if not shutil.which(self.openssl_bin):
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.openssl_bin, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (TimeoutError, OSError):
            return None
        if proc.returncode != 0:
            return None
        return stdout.decode("utf-8", errors="replace")

"""host.crypto_policies.profile — system-wide crypto policy (RHEL/Fedora).

A single setting (`update-crypto-policies`) governs OpenSSL, GnuTLS, NSS,
OpenSSH, Java and Kerberos at once. LEGACY re-enables broken classical crypto
(SHA-1 signatures, RC4, 3DES, <=1024-bit DH/RSA); DEFAULT / FIPS / FUTURE are
modern but still fully classical (RSA/ECDSA/ECDHE) and therefore
quantum-vulnerable. This probe reports the active policy and flags weak
profiles — one finding that reflects the host's whole crypto posture.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


def _severity(classification: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[classification]


# base policy name -> (classification, human note)
_BASE_POLICY: dict[str, tuple[Classification, str]] = {
    "LEGACY": (
        Classification.TINGGI,
        "LEGACY re-enables broken classical crypto (SHA-1 signatures, RC4, "
        "3DES, <=1024-bit DH/RSA).",
    ),
    "DEFAULT": (
        Classification.SEDERHANA,
        "DEFAULT is modern but fully classical (RSA/ECDSA/ECDHE) — "
        "quantum-vulnerable; no PQC. This is the system-wide migration lever.",
    ),
    "FIPS": (
        Classification.SEDERHANA,
        "FIPS mode is classical FIPS 140 crypto — quantum-vulnerable; no PQC.",
    ),
    "FUTURE": (
        Classification.RENDAH,
        "FUTURE is hardened classical (no SHA-1, >=3072-bit) but still "
        "quantum-vulnerable; no PQC.",
    ),
    "EMPTY": (
        Classification.INFO,
        "EMPTY disables all cryptographic algorithms (unusual).",
    ),
}


class HostCryptoPolicies(Probe):
    """Report the active system-wide crypto-policies profile (RHEL/Fedora)."""

    id = "host.crypto_policies.profile"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(
        self,
        command: str = "update-crypto-policies",
        config_dir: Path | None = None,
    ) -> None:
        self.command = command
        self.config_dir = config_dir or Path("/etc/crypto-policies")

    async def applies(self, ctx: ScanContext) -> bool:
        return (
            shutil.which(self.command) is not None
            or (self.config_dir / "state" / "current").exists()
            or (self.config_dir / "config").exists()
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        policy, source = await self._read_policy()
        if not policy:
            return

        base, _, submods = policy.partition(":")
        base = base.strip().upper()
        submodules = [s.strip() for s in submods.split(":") if s.strip()]

        classification, note = _BASE_POLICY.get(
            base, (Classification.INFO, f"Unrecognised crypto policy: {base}.")
        )
        # A SHA-1 submodule (e.g. DEFAULT:SHA1) re-enables SHA-1 signatures —
        # escalate regardless of the base policy.
        if any(s.upper() == "SHA1" for s in submodules):
            classification = Classification.TINGGI
            note += " The :SHA1 submodule re-enables SHA-1 signatures."

        emit(Finding(
            probe_id=self.id,
            algorithm=f"crypto-policies/{base}",
            classification=classification,
            severity=_severity(classification),
            title=f"System crypto-policy is {policy} ({source})",
            evidence={
                "policy": policy,
                "base": base,
                "submodules": submodules,
                "source": source,
                "note": note,
            },
            remediation={
                "snippet": (
                    "# Inspect / raise the system policy:\n"
                    "sudo update-crypto-policies --show\n"
                    "sudo update-crypto-policies --set DEFAULT   # or FUTURE"
                ),
            },
        ))

    async def _read_policy(self) -> tuple[str | None, str]:
        """Resolve the active policy: CLI first (authoritative, incl.
        submodules), then the on-disk state/config files."""
        if shutil.which(self.command):
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.command, "--show",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                value = stdout.decode("utf-8", errors="replace").strip()
                if value:
                    return value, f"{self.command} --show"
            except (TimeoutError, OSError):
                pass

        # Fallback: state/current carries the full applied policy (base +
        # submodules); config carries only the base policy name.
        for rel in (Path("state") / "current", Path("config")):
            path = self.config_dir / rel
            try:
                if path.is_file():
                    value = path.read_text(errors="replace").strip()
                    if value:
                        return value, str(path)
            except OSError:
                continue
        return None, ""

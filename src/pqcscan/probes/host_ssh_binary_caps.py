"""host.ssh.binary_caps — what the installed OpenSSH binary can actually do.

`sshd_config` says what is *offered*; `ssh -Q kex` says what is *compiled in*.
A host whose OpenSSH lists a PQC hybrid KEX (sntrup761x25519, mlkem768x25519)
CAN negotiate quantum-safe SSH; an older binary cannot, no matter how the
config is written. This probe reports that capability so config-silent hosts
that do vs do not support PQC SSH are distinguishable.
"""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# Substrings identifying a post-quantum hybrid KEX in `ssh -Q kex` output.
_PQC_KEX_MARKERS = ("sntrup", "mlkem", "kyber")


def _is_pqc_kex(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _PQC_KEX_MARKERS)


class HostSshBinaryCaps(Probe):
    """Report whether the local OpenSSH binary has a PQC hybrid KEX built in."""

    id = "host.ssh.binary_caps"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:ssh", "mykripto:ssh", "nacsa-9:pqc-readiness")

    def __init__(
        self,
        ssh: str = "ssh",
        kex_output: str | None = None,
        version: str | None = None,
    ) -> None:
        self.ssh = ssh
        # kex_output / version are injectable seams so tests are deterministic
        # and need no real ssh binary.
        self._kex_output = kex_output
        self._version = version

    async def applies(self, ctx: ScanContext) -> bool:
        return self._kex_output is not None or shutil.which(self.ssh) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        kex_text = self._kex_output
        if kex_text is None:
            kex_text = await self._query("kex")
        if kex_text is None:
            return
        kex = [line.strip() for line in kex_text.splitlines() if line.strip()]
        if not kex:
            return

        version = self._version
        if version is None:
            version = await self._ssh_version()

        pqc_kex = [k for k in kex if _is_pqc_kex(k)]
        if pqc_kex:
            emit(Finding(
                probe_id=self.id,
                algorithm=pqc_kex[0],
                classification=Classification.PQC_READY,
                severity=Severity.INFO,
                title=("OpenSSH supports PQC hybrid key exchange "
                       f"({', '.join(pqc_kex)})"),
                evidence={
                    "pqc_kex": pqc_kex,
                    "version": version,
                    "kex_count": len(kex),
                },
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm="ssh-kex/classical-only",
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=("OpenSSH has no PQC hybrid KEX compiled in — this host "
                       "cannot negotiate quantum-safe SSH"),
                evidence={
                    "version": version,
                    "note": ("No sntrup761x25519 / mlkem768x25519 in `ssh -Q "
                             "kex`. Upgrade OpenSSH (>=9.0 for sntrup761, "
                             ">=9.9 for ML-KEM) to enable PQC key exchange."),
                    "kex_sample": kex[:8],
                },
            ))

    async def _query(self, what: str) -> str | None:
        if not shutil.which(self.ssh):
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.ssh, "-Q", what,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (TimeoutError, OSError):
            return None
        if proc.returncode != 0:
            return None
        return stdout.decode("utf-8", errors="replace")

    async def _ssh_version(self) -> str:
        # `ssh -V` writes the version banner to stderr.
        if not shutil.which(self.ssh):
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.ssh, "-V",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (TimeoutError, OSError):
            return ""
        return stderr.decode("utf-8", errors="replace").strip()

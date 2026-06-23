"""host.kernel.crypto_registry — kernel's registered crypto algorithm table.

Parse /proc/crypto, the in-kernel registry of crypto algorithms available to
kernel consumers (dm-crypt, IPsec/XFRM, kTLS). Blocks are separated by blank
lines; each block carries "name : <alg>", "driver : <drv>", "type : <type>"
lines. We collect the distinct registered algorithm NAMES and flag legacy or
broken primitives (DES, 3DES, MD5/MD4, RC4) — modern algorithms (AES, SHA-2,
XTS, GCM) are not flagged. Pure text parse, no network.
"""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_PATH = Path("/proc/crypto")

# Substrings (lower-cased) that mark a registered algorithm name as legacy or
# broken. Matched against the bare primitive token so that wrappers such as
# "ecb(des)" or "cbc(des3_ede)" are caught alongside the bare names.
_WEAK_TOKENS = (
    "des3_ede",
    "des",
    "md5",
    "md4",
    "rc4",
    "arc4",
)


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


def _is_weak(name: str) -> bool:
    # Extract the primitive tokens — split on non-alphanumeric/underscore so
    # wrappers like "ecb(des)" yield {"ecb", "des"} and bare names yield the
    # name itself. Match weak tokens exactly to avoid false hits (e.g. the
    # modern "aes" must never match "des").
    lowered = name.lower()
    tokens = set()
    current = ""
    for ch in lowered:
        if ch.isalnum() or ch == "_":
            current += ch
        else:
            if current:
                tokens.add(current)
            current = ""
    if current:
        tokens.add(current)
    return any(tok in tokens for tok in _WEAK_TOKENS)


class HostKernelCryptoRegistry(Probe):
    """Flag legacy/broken algorithms registered in /proc/crypto."""

    id = "host.kernel.crypto_registry"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(self, proc_crypto_path: Path | None = None) -> None:
        self.proc_crypto_path = proc_crypto_path or _DEFAULT_PATH

    async def applies(self, ctx: ScanContext) -> bool:
        return self.proc_crypto_path.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        try:
            text = self.proc_crypto_path.read_text(errors="replace")
        except (OSError, ValueError):
            return

        seen_weak: set[str] = set()
        for name in self._registered_names(text):
            if name in seen_weak:
                continue
            if not _is_weak(name):
                continue
            seen_weak.add(name)
            emit(Finding(
                probe_id=self.id,
                algorithm=name,
                classification=Classification.TINGGI,
                severity=_sev(Classification.TINGGI),
                title=f"Kernel crypto registry exposes legacy algorithm {name}",
                evidence={
                    "name": name,
                    "source": str(self.proc_crypto_path),
                },
                remediation={
                    "snippet": (
                        f"# Legacy/broken algorithm '{name}' is registered in "
                        f"{self.proc_crypto_path}.\n"
                        "# Avoid it in dm-crypt/IPsec/kTLS configs; prefer "
                        "AES-GCM / AES-XTS / SHA-2."
                    ),
                },
            ))

    def _registered_names(self, text: str) -> list[str]:
        """Collect distinct algorithm names from "name : <alg>" lines, in
        first-seen order."""
        names: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            key, sep, value = line.partition(":")
            if not sep or key.strip() != "name":
                continue
            name = value.strip()
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        return names

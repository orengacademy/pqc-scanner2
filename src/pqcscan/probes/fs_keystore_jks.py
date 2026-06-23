"""fs.keystore.jks — Java keystore (JKS/JCEKS) inventory by magic bytes.

Java keystores hold classical RSA/EC keys + certs and are pervasive in
enterprise/Java estates, but the JKS format is unparsed by the cryptography
library. This probe inventories them by their file magic (no `pyjks`
dependency): JKS = 0xFEEDFEED, JCEKS = 0xCECECECE. Per-entry key algorithms
are NOT enumerated here — that needs `pyjks` (tracked as a follow-up); this is
presence + format inventory so Java keystores aren't a blind spot.
"""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# magic (first 4 bytes) -> keystore format label
_MAGIC = {
    b"\xfe\xed\xfe\xed": "JKS",
    b"\xce\xce\xce\xce": "JCEKS",
}
_EXTS = (".jks", ".jceks", ".keystore", ".ts", ".truststore")
_NAMES = ("cacerts",)


class FsKeystoreJks(Probe):
    """Inventory Java keystores (JKS/JCEKS) by file magic — no pyjks needed."""

    id = "fs.keystore.jks"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None) -> None:
        self.roots = roots or [
            Path("/etc/pki"), Path("/opt"), Path("/usr/lib/jvm"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in _EXTS and path.name not in _NAMES:
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                self._scan_one(path, emit)

    def _scan_one(self, path: Path, emit: Emitter) -> None:
        try:
            with path.open("rb") as fh:
                magic = fh.read(4)
        except OSError:
            return
        fmt = _MAGIC.get(magic)
        if fmt is None:
            return
        emit(Finding(
            probe_id=self.id,
            algorithm=fmt,
            classification=Classification.SEDERHANA,
            severity=Severity.MED,
            title=f"{path.name}: {fmt} Java keystore",
            evidence={
                "path": str(path),
                "format": fmt,
                "note": (f"{fmt} keystore holds classical RSA/EC keys/certs "
                         "(quantum-vulnerable). Per-entry algorithms not "
                         "enumerated (needs pyjks); the JKS/JCEKS format also "
                         "uses a weak SHA-1-based integrity check. Review for "
                         "PQC migration."),
            },
        ))

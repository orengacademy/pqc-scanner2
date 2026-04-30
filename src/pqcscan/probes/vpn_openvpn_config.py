"""vpn.openvpn.config — parse OpenVPN configs for cipher / auth / tls-version-min."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


# OpenVPN directives we care about. Each maps to "is this token a single
# algorithm name we should classify directly?".
_DIRECTIVES = {
    "cipher": True,         # data-channel cipher e.g. AES-256-GCM
    "auth": True,           # HMAC e.g. SHA256
    "tls-cipher": False,    # TLS suite list (colon-separated)
    "tls-version-min": False,  # protocol version
    "data-ciphers": False,  # NCP list (colon-separated)
}


class VpnOpenvpnConfig(Probe):
    id = "vpn.openvpn.config"
    family = ProbeFamily.VPN
    framework_tags = ("nist-ir-8547:vpn", "bukukerja:vpn", "mykripto:vpn")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/openvpn"),
            Path("/etc/openvpn/server"),
            Path("/etc/openvpn/client"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for ext in ("*.conf", "*.ovpn"):
                for path in root.rglob(ext):
                    if not path.is_file():
                        continue
                    try:
                        text = path.read_text(errors="replace")
                    except OSError:
                        continue
                    self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        for line_no, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            for directive, single_alg in _DIRECTIVES.items():
                m = re.match(rf"^{directive}\s+(.+)$", line, re.IGNORECASE)
                if not m:
                    continue
                value = m.group(1).strip()
                tokens = [value] if single_alg else re.split(r"[:,\s]+", value)
                for token in tokens:
                    if not token:
                        continue
                    # tls-version-min special-case.
                    if directive == "tls-version-min":
                        v = token.upper().replace("V", "V")
                        if v in {"1.0", "1.1"}:
                            emit(Finding(
                                probe_id=self.id,
                                algorithm=f"TLSv{v}",
                                classification=Classification.SANGAT_TINGGI,
                                severity=Severity.CRIT,
                                title=f"OpenVPN tls-version-min={v} at {path}:{line_no}",
                                evidence={"path": str(path), "line": line_no,
                                          "directive": directive},
                            ))
                        continue
                    cls = classify(token)
                    if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                        emit(Finding(
                            probe_id=self.id,
                            algorithm=normalise(token),
                            classification=cls,
                            severity=_sev(cls),
                            title=f"OpenVPN {directive} = {token} at {path}:{line_no}",
                            evidence={"path": str(path), "line": line_no,
                                      "directive": directive, "token": token},
                        ))


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

"""host.gnutls.config — parse the GnuTLS system priority configuration.

GnuTLS resolves its default priority string from a small set of files (the
crypto-policies back-end on RHEL/Fedora, or /etc/gnutls/default-priorities).
The priority string drives every GnuTLS-backed TLS endpoint on the host, so a
permissive string (legacy protocols, weak primitives, no PQC groups) leaves the
whole machine exposed. This probe reads the priority string(s) and flags weak
posture. Pure text parse — no GnuTLS binary is invoked.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_PATHS = [
    Path("/etc/crypto-policies/back-ends/gnutls.config"),
    Path("/etc/gnutls/default-priorities"),
]

# Explicitly-enabled legacy protocol versions (+VERS-...). NORMAL on its own is
# acceptable; only an explicit re-enable of a broken protocol is flagged.
_LEGACY_PROTO_RE = re.compile(r"\+VERS-(?:SSL3\.0|TLS1\.0|TLS1\.1)", re.IGNORECASE)

# Weak/broken primitives explicitly enabled via +TOKEN.
_WEAK_PRIMITIVE_RE = re.compile(
    r"\+(?:ARCFOUR-128|3DES-CBC|NULL|MD5)\b", re.IGNORECASE
)

# A configured PQC key-exchange group (ML-KEM / Kyber).
_PQC_GROUP_RE = re.compile(r"\+GROUP-\S*(?:MLKEM|KYBER)", re.IGNORECASE)


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


class HostGnutlsConfig(Probe):
    """Parse GnuTLS system priority config and flag weak/legacy/no-PQC posture."""

    id = "host.gnutls.config"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(self, config_paths: list[Path] | None = None) -> None:
        self.config_paths = config_paths if config_paths is not None else _DEFAULT_PATHS

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.config_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in self.config_paths:
            if not path.exists():
                continue
            try:
                text = path.read_text(errors="replace")
            except (OSError, ValueError):
                continue
            self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        # The priority string may span multiple lines / multiple settings;
        # examine each non-comment line that carries priority tokens.
        priority = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        if not priority.strip():
            return

        legacy = _LEGACY_PROTO_RE.findall(priority)
        if legacy:
            emit(Finding(
                probe_id=self.id,
                algorithm="gnutls/legacy-protocols",
                classification=Classification.TINGGI,
                severity=_sev(Classification.TINGGI),
                title=f"GnuTLS priority enables legacy protocols in {path}",
                evidence={"path": str(path), "tokens": legacy},
                remediation={
                    "snippet": "# Drop +VERS-SSL3.0/+VERS-TLS1.0/+VERS-TLS1.1 from the GnuTLS priority string",
                },
            ))

        weak = _WEAK_PRIMITIVE_RE.findall(priority)
        if weak:
            emit(Finding(
                probe_id=self.id,
                algorithm="gnutls/weak-primitives",
                classification=Classification.TINGGI,
                severity=_sev(Classification.TINGGI),
                title=f"GnuTLS priority permits weak primitives in {path}",
                evidence={"path": str(path), "tokens": weak},
                remediation={
                    "snippet": "# Remove +ARCFOUR-128/+3DES-CBC/+NULL/+MD5 from the GnuTLS priority string",
                },
            ))

        if not _PQC_GROUP_RE.search(priority):
            emit(Finding(
                probe_id=self.id,
                algorithm="gnutls/no-pqc-groups",
                classification=Classification.SEDERHANA,
                severity=_sev(Classification.SEDERHANA),
                title=f"No PQC groups in GnuTLS priority in {path}",
                evidence={"path": str(path), "note": "no PQC groups in GnuTLS priority"},
                remediation={
                    "snippet": "# Add a PQC group, e.g. +GROUP-X25519-MLKEM768, to the GnuTLS priority string",
                },
            ))

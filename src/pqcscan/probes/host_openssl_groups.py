from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_PATHS = [
    Path("/etc/ssl/openssl.cnf"),
    Path("/etc/pki/tls/openssl.cnf"),
]

# Protocol floors at or below this are considered weak (<= TLSv1.1).
_WEAK_PROTOCOLS = {"", "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}

_POLICY_SECTION = "system_default_sect"
_KEYS = {"groups", "signaturealgorithms", "minprotocol", "maxprotocol", "cipherstring"}
_PQC_TOKENS = ("mlkem", "kyber")

_SECTION_RE = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]")
_KV_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$")
_SECLEVEL_RE = re.compile(r"@SECLEVEL\s*=\s*(\d+)", re.IGNORECASE)


class HostOpenSSLGroups(Probe):
    """Parse openssl.cnf system_default_sect for protocol floor, SECLEVEL and PQC groups."""
    id = "host.openssl.groups"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots if roots is not None else _DEFAULT_PATHS

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in self.roots:
            if not path.exists() or not path.is_file():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            try:
                self._scan_text(text, path, emit)
            except (OSError, ValueError):
                continue

    def _parse_policy(self, text: str) -> dict[str, str]:
        """Extract recognised keys from [system_default_sect]. Last value wins."""
        policy: dict[str, str] = {}
        in_section = False
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0].rstrip()
            sec = _SECTION_RE.match(line)
            if sec:
                in_section = sec.group(1).strip().lower() == _POLICY_SECTION
                continue
            if not in_section:
                continue
            kv = _KV_RE.match(line)
            if not kv:
                continue
            key = kv.group(1).lower()
            if key in _KEYS:
                policy[key] = kv.group(2).strip()
        return policy

    def _seclevel(self, cipherstring: str) -> int | None:
        m = _SECLEVEL_RE.search(cipherstring)
        return int(m.group(1)) if m else None

    def _groups_has_pqc(self, groups: str) -> bool:
        low = groups.lower()
        return any(tok in low for tok in _PQC_TOKENS)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        policy = self._parse_policy(text)
        if not policy:
            return

        # Weak / unset protocol floor.
        minproto = policy.get("minprotocol", "")
        if minproto.upper().replace(" ", "") in _WEAK_PROTOCOLS:
            shown = minproto or "(unset)"
            emit(Finding(
                probe_id=self.id,
                algorithm="TLS-protocol-floor",
                classification=Classification.SEDERHANA,
                severity=_sev(Classification.SEDERHANA),
                title=f"Weak MinProtocol {shown} in {path}",
                evidence={"path": str(path), "minprotocol": minproto},
                remediation={
                    "snippet": "MinProtocol = TLSv1.2",
                },
            ))

        # Permissive SECLEVEL (@SECLEVEL=0 or 1).
        cipherstring = policy.get("cipherstring", "")
        seclevel = self._seclevel(cipherstring)
        if seclevel is not None and seclevel <= 1:
            emit(Finding(
                probe_id=self.id,
                algorithm="openssl-SECLEVEL",
                classification=Classification.TINGGI,
                severity=_sev(Classification.TINGGI),
                title=f"Permissive @SECLEVEL={seclevel} in {path}",
                evidence={"path": str(path), "cipherstring": cipherstring, "seclevel": seclevel},
                remediation={
                    "snippet": "CipherString = DEFAULT:@SECLEVEL=2",
                },
            ))

        # Group policy: PQC hybrid present -> ready; classical-only -> weak.
        if "groups" in policy:
            groups = policy["groups"]
            if self._groups_has_pqc(groups):
                emit(Finding(
                    probe_id=self.id,
                    algorithm="TLS-key-exchange-groups",
                    classification=Classification.PQC_READY,
                    severity=_sev(Classification.PQC_READY),
                    title=f"PQC hybrid groups configured in {path}",
                    evidence={"path": str(path), "groups": groups},
                ))
            else:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="TLS-key-exchange-groups",
                    classification=Classification.SEDERHANA,
                    severity=_sev(Classification.SEDERHANA),
                    title=f"No PQC groups configured in {path}",
                    evidence={"path": str(path), "groups": groups},
                    remediation={
                        "snippet": "Groups = X25519MLKEM768:x25519:secp256r1",
                    },
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

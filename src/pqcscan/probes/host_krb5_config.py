"""host.krb5.config — Kerberos krb5.conf weak enctypes + PKINIT.

Flags weak symmetric enctypes (DES, 3DES, RC4) and `allow_weak_crypto`, and
notes PKINIT, whose pre-authentication uses classical asymmetric crypto
(RSA / DH / ECDH) and is therefore the quantum-vulnerable part of a Kerberos
deployment.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DES = ("DES", Classification.SANGAT_TINGGI)
_3DES = ("3DES", Classification.TINGGI)
_RC4 = ("RC4", Classification.TINGGI)

# Weak Kerberos enctype name -> (canonical algorithm, classification).
_WEAK_ENCTYPES: dict[str, tuple[str, Classification]] = {
    "des-cbc-crc": _DES, "des-cbc-md4": _DES, "des-cbc-md5": _DES,
    "des-cbc-raw": _DES, "des-hmac-sha1": _DES, "des": _DES,
    "des3-cbc-sha1": _3DES, "des3-cbc-sha1-kd": _3DES, "des3-cbc-raw": _3DES,
    "des3-hmac-sha1": _3DES, "des3": _3DES,
    "arcfour-hmac": _RC4, "arcfour-hmac-md5": _RC4, "arcfour-hmac-exp": _RC4,
    "arcfour-hmac-md5-exp": _RC4, "rc4-hmac": _RC4, "rc4-hmac-exp": _RC4,
    "rc4": _RC4,
}

_ENCTYPE_DIRECTIVES = (
    "permitted_enctypes", "default_tkt_enctypes",
    "default_tgs_enctypes", "default_tgt_enctypes",
)

_DEFAULT_PATHS = [Path("/etc/krb5.conf")]


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


class HostKrb5Config(Probe):
    """Parse krb5.conf for weak enctypes and PKINIT asymmetric exposure."""

    id = "host.krb5.config"
    family = ProbeFamily.HOST
    framework_tags = (
        "nist-ir-8547:kerberos", "bukukerja:kerberos", "mykripto:kerberos",
    )

    def __init__(self, config_paths: list[Path] | None = None) -> None:
        if config_paths is not None:
            self.config_paths = config_paths
        else:
            paths = list(_DEFAULT_PATHS)
            conf_d = Path("/etc/krb5.conf.d")
            if conf_d.is_dir():
                paths.extend(sorted(conf_d.glob("*.conf")))
            self.config_paths = paths

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.config_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        # token -> (canonical, classification, source path)
        weak: dict[str, tuple[str, Classification, str]] = {}
        allow_weak_src: str | None = None
        pkinit_src: str | None = None

        for path in self.config_paths:
            if not path.exists():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].split(";", 1)[0].strip()
                if not line:
                    continue
                low = line.lower()

                m = re.match(r"allow_weak_crypto\s*=\s*(\S+)", low)
                if m and m.group(1) in ("true", "yes", "1"):
                    allow_weak_src = allow_weak_src or str(path)
                    continue

                if low.startswith("pkinit_"):
                    pkinit_src = pkinit_src or str(path)
                    continue

                for directive in _ENCTYPE_DIRECTIVES:
                    dm = re.match(rf"{directive}\s*=\s*(.+)", low)
                    if not dm:
                        continue
                    for tok in re.split(r"[,\s]+", dm.group(1).strip()):
                        if tok in _WEAK_ENCTYPES and tok not in weak:
                            canonical, cls = _WEAK_ENCTYPES[tok]
                            weak[tok] = (canonical, cls, str(path))
                    break

        for tok, (canonical, cls, src) in weak.items():
            emit(Finding(
                probe_id=self.id,
                algorithm=canonical,
                classification=cls,
                severity=_severity(cls),
                title=f"krb5.conf permits weak Kerberos enctype {tok} ({canonical})",
                evidence={"path": src, "enctype": tok},
                remediation={
                    "snippet": ("# Remove DES/3DES/RC4 enctypes; keep only "
                                "aes256-cts-hmac-sha384-192 / "
                                "aes128-cts-hmac-sha256-128."),
                },
            ))

        if allow_weak_src:
            emit(Finding(
                probe_id=self.id,
                algorithm="krb5/allow_weak_crypto",
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title="krb5.conf sets allow_weak_crypto = true (re-enables DES/RC4)",
                evidence={"path": allow_weak_src},
                remediation={"snippet": "# Set allow_weak_crypto = false"},
            ))

        if pkinit_src:
            emit(Finding(
                probe_id=self.id,
                algorithm="PKINIT/asymmetric",
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=("Kerberos PKINIT configured — classical asymmetric "
                       "pre-auth (RSA/DH/ECDH), quantum-vulnerable"),
                evidence={
                    "path": pkinit_src,
                    "note": ("PKINIT's initial AS exchange relies on classical "
                             "public-key crypto; no standard PQC enctype exists "
                             "yet. Track for migration."),
                },
            ))

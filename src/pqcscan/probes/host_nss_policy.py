"""host.nss.policy — NSS system crypto policy (RHEL/Fedora back-end).

`/etc/crypto-policies/back-ends/nss.config` is the NSS rendering of the
system-wide crypto policy. It is a flat key=value file, e.g.::

    allow=HMAC-SHA1:HMAC-SHA256:...:RSA-MIN=2048:DH-MIN=2048
    disallow=ALL
    min-tls=tls1.2
    min-dtls=dtls1.2

This probe parses that file and flags weak settings: a low/unset TLS floor
(ssl3.0/tls1.0/tls1.1) and weak primitives left in the allow list (RC4, DES,
MD5, SHA-1 signatures, sub-2048-bit DH/RSA). NSS policy has no PQC concept
yet, so every finding is classical-only by construction.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_PATH = Path("/etc/crypto-policies/back-ends/nss.config")

# TLS floors considered weak (or, when unset, treated as weak).
_WEAK_TLS = {"ssl3.0", "tls1.0", "tls1.1"}

# Weak primitive tokens to look for in the allow= list (lower-cased).
_WEAK_PRIMITIVES = {
    "rc4": "RC4",
    "des": "DES",
    "des-ede3-cbc": "3DES",
    "md5": "MD5",
    "hmac-md5": "HMAC-MD5",
}


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


class HostNssPolicy(Probe):
    """Parse the NSS system crypto policy and flag weak classical settings."""

    id = "host.nss.policy"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path or _DEFAULT_PATH

    async def applies(self, ctx: ScanContext) -> bool:
        return self.config_path.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        try:
            if not self.config_path.is_file():
                return
            text = self.config_path.read_text(errors="replace")
        except OSError:
            return

        settings = self._parse(text)
        path = str(self.config_path)

        self._check_tls_floor(settings, path, emit)
        self._check_allow_list(settings, path, emit)

    @staticmethod
    def _parse(text: str) -> dict[str, str]:
        settings: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            settings[key.strip().lower()] = value.strip()
        return settings

    def _check_tls_floor(
        self, settings: dict[str, str], path: str, emit: Emitter
    ) -> None:
        # NSS spells the floor `min-tls`; tolerate the camelCase `minTLS` too.
        floor = settings.get("min-tls") or settings.get("mintls")
        normalised = (floor or "").strip().lower()
        if normalised and normalised not in _WEAK_TLS:
            return

        shown = floor if floor else "(unset)"
        emit(Finding(
            probe_id=self.id,
            algorithm="nss/min-tls",
            classification=Classification.SEDERHANA,
            severity=_sev(Classification.SEDERHANA),
            title=f"NSS policy TLS floor is weak ({shown})",
            evidence={
                "path": path,
                "min-tls": shown,
                "note": (
                    "TLS floor allows ssl3.0/tls1.0/tls1.1 (or is unset). "
                    "NSS policy is classical-only — no PQC concept exists."
                ),
            },
            remediation={
                "snippet": (
                    "# Raise the floor in the system crypto policy:\n"
                    "sudo update-crypto-policies --set DEFAULT   # min-tls=tls1.2"
                ),
            },
        ))

    def _check_allow_list(
        self, settings: dict[str, str], path: str, emit: Emitter
    ) -> None:
        allow = settings.get("allow")
        if not allow:
            return

        # The allow list is colon-separated; tokens may be KEY=VALUE pairs.
        tokens = [t.strip() for t in allow.split(":") if t.strip()]

        weak_found: list[str] = []
        for token in tokens:
            if token.lower() in _WEAK_PRIMITIVES:
                weak_found.append(_WEAK_PRIMITIVES[token.lower()])

        # SHA-1 signatures: NSS uses HMAC-SHA1 for MACs (acceptable) but
        # DSA/RSA/ECDSA *-SHA1 signature schemes are the real risk.
        sha1_sig = any(
            re.search(r"(?:rsa|dsa|ecdsa)[-/]?sha1", t.lower()) for t in tokens
        )
        if sha1_sig:
            weak_found.append("SHA-1 signatures")

        # Sub-2048-bit DH / RSA minimums (e.g. DH-MIN=1024, RSA-MIN=1536).
        for primitive in ("dh-min", "rsa-min"):
            value = self._min_bits(tokens, primitive)
            if value is not None and value < 2048:
                weak_found.append(f"{primitive.upper()}={value}")

        if not weak_found:
            return

        emit(Finding(
            probe_id=self.id,
            algorithm="nss/allow",
            classification=Classification.TINGGI,
            severity=_sev(Classification.TINGGI),
            title=f"NSS policy allow list contains weak primitives ({', '.join(weak_found)})",
            evidence={
                "path": path,
                "weak": weak_found,
                "allow": allow,
                "note": (
                    "Weak classical primitives are enabled in the NSS allow "
                    "list. NSS policy is classical-only — no PQC concept exists."
                ),
            },
            remediation={
                "snippet": (
                    "# Remove weak primitives / raise minimums via the system policy:\n"
                    "sudo update-crypto-policies --set DEFAULT   # or FUTURE"
                ),
            },
        ))

    @staticmethod
    def _min_bits(tokens: list[str], primitive: str) -> int | None:
        for token in tokens:
            key, sep, value = token.partition("=")
            if sep and key.strip().lower() == primitive:
                try:
                    return int(value.strip())
                except ValueError:
                    return None
        return None

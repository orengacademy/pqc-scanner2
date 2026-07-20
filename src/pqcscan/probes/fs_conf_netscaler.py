from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# NetScaler stores config as flat CLI lines, one directive per line, e.g.
#   set ssl vserver vs1 -ssl3 ENABLED -tls1 ENABLED -tls13 DISABLED
#   bind ssl cipher mygroup -cipherName SSL3-DES-CBC3-SHA
#   bind ssl vserver vs1 -cipherName RC4-MD5

# `set ssl <kind> <entity> <flags...>` — protocol version toggles live here.
_SET_SSL_RE = re.compile(
    r"^\s*(?:set|add)\s+ssl\s+(vserver|service|serviceGroup|monitor)\s+(\S+)\s+(.*)$",
    re.IGNORECASE,
)
# `bind ssl <kind> <entity> ... -cipherName <name>` — a cipher binding. Lines
# that only bind a cert (`-certkeyName`) carry no -cipherName and don't match.
_BIND_CIPHER_RE = re.compile(
    r"^\s*bind\s+ssl\s+(cipher|vserver|service|serviceGroup)\s+(\S+)\b.*?-cipherName\s+(\S+)",
    re.IGNORECASE,
)
# Protocol toggles inside a `set ssl` line. Longer names first so `-tls1` never
# swallows `-tls11`/`-tls12`/`-tls13`.
_FLAG_RE = re.compile(r"-(ssl3|tls13|tls12|tls11|tls1)\s+(ENABLED|DISABLED)", re.IGNORECASE)

_PROTO_MAP = {
    "ssl3": "SSLV3",
    "tls1": "TLSV1.0",
    "tls11": "TLSV1.1",
    "tls13": "TLSV1.3",
}

# Substrings in a NetScaler cipher name that mark it broken-now (SANGAT_TINGGI),
# independent of any quantum threat. `classify()` catches most single tokens
# (DES, RC4, MD5) too, but SSL3/EXPORT/NULL only surface as substrings.
_BROKEN_FRAGMENTS = (
    "SSL3", "RC4", "DES-CBC3", "3DES", "DES-CBC-", "-DES-", "MD5", "EXPORT", "NULL",
)


def _classify_cipher(name: str) -> Classification | None:
    """Classify a NetScaler cipher-suite name (e.g. TLS1-ECDHE-RSA-AES256-GCM-SHA384).

    Broken-now suites → SANGAT_TINGGI. Otherwise fall back to `classify()` on the
    hyphen-separated tokens and keep the worst tier — a classical key-exchange
    token (ECDHE/DHE/RSA) lands the whole suite at TINGGI (quantum-vulnerable).
    Returns None when nothing weak or quantum-vulnerable is named.
    """
    u = name.upper()
    if any(frag in u for frag in _BROKEN_FRAGMENTS):
        return Classification.SANGAT_TINGGI
    worst: Classification | None = None
    for tok in u.split("-"):
        if not tok:
            continue
        c = classify(tok)
        if c is Classification.SANGAT_TINGGI:
            return c
        if c is Classification.TINGGI:
            worst = Classification.TINGGI
    return worst


class FsConfNetscaler(Probe):
    id = "fs.conf.netscaler"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/nsconfig/ns.conf"),
            Path("/flash/nsconfig/ns.conf"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.is_file():
                continue
            try:
                text = root.read_text(errors="replace")
            except OSError:
                continue
            self._scan_text(text, root, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        for line in text.splitlines():
            if m := _SET_SSL_RE.match(line):
                self._scan_protocol(m.group(1), m.group(2), m.group(3), path, emit)
            if bm := _BIND_CIPHER_RE.match(line):
                self._scan_cipher(bm.group(1), bm.group(2), bm.group(3), path, emit)

    def _scan_protocol(self, kind: str, entity: str, rest: str, path: Path, emit: Emitter) -> None:
        for fm in _FLAG_RE.finditer(rest):
            flag = fm.group(1).lower()
            state = fm.group(2).upper()
            proto = _PROTO_MAP.get(flag)
            if proto is None:  # -tls12: a healthy protocol, nothing to flag.
                continue
            if flag in {"ssl3", "tls1", "tls11"} and state == "ENABLED":
                emit(Finding(
                    probe_id=self.id,
                    algorithm=proto,
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=f"NetScaler ssl {kind} {entity} enables {proto}",
                    evidence={"path": str(path), "entity": entity, "directive": flag},
                    remediation={"snippet": f"set ssl {kind} {entity} -{flag} DISABLED"},
                ))
            elif flag == "tls13" and state == "DISABLED":
                emit(Finding(
                    probe_id=self.id,
                    algorithm=proto,
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"NetScaler ssl {kind} {entity} has TLSv1.3 disabled",
                    evidence={"path": str(path), "entity": entity, "directive": flag},
                    remediation={"snippet": f"set ssl {kind} {entity} -tls13 ENABLED"},
                ))

    def _scan_cipher(self, kind: str, entity: str, name: str, path: Path, emit: Emitter) -> None:
        cls = _classify_cipher(name)
        if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
            assert cls is not None  # narrow for mypy
            emit(Finding(
                probe_id=self.id,
                algorithm=normalise(name),
                classification=cls,
                severity=_sev(cls),
                title=f"NetScaler ssl {kind} {entity} binds cipher {name}",
                evidence={"path": str(path), "entity": entity, "directive": "cipherName"},
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

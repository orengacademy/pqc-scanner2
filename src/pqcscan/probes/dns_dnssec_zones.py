"""dns.dnssec.zones — flag DNSSEC algorithms in BIND zones / named.conf.

DNSSEC alg IDs per IANA registry:
  1  RSAMD5         (deprecated, MUST NOT use)
  3  DSA-SHA1       (deprecated)
  5  RSASHA1        (deprecated)
  6  DSA-NSEC3-SHA1 (deprecated)
  7  RSASHA1-NSEC3-SHA1 (deprecated)
  8  RSASHA256      (recommended classical)
  10 RSASHA512      (recommended classical)
  13 ECDSAP256SHA256
  14 ECDSAP384SHA384
  15 ED25519
  16 ED448
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


_DEPRECATED = {1, 3, 5, 6, 7}
_RSA = {8, 10}
_ECDSA = {13, 14}
_EDDSA = {15, 16}

# DNSKEY record line: "<name> <ttl> IN DNSKEY <flags> <proto> <alg> <key>"
_DNSKEY_RE = re.compile(
    r"\bDNSKEY\s+\d+\s+\d+\s+(\d+)\s+", re.IGNORECASE,
)
# Also catch dnssec-policy {} algorithm directives.
_POLICY_ALG_RE = re.compile(r"\balgorithm\s+(\w+)\s*;", re.IGNORECASE)


_POLICY_NAMES = {
    "rsasha1": (Classification.SANGAT_TINGGI, Severity.CRIT, 5),
    "rsasha256": (Classification.TINGGI, Severity.HIGH, 8),
    "rsasha512": (Classification.TINGGI, Severity.HIGH, 10),
    "ecdsap256sha256": (Classification.TINGGI, Severity.HIGH, 13),
    "ecdsap384sha384": (Classification.TINGGI, Severity.HIGH, 14),
    "ed25519": (Classification.TINGGI, Severity.HIGH, 15),
    "ed448": (Classification.TINGGI, Severity.HIGH, 16),
}


class DnsDnssecZones(Probe):
    id = "dns.dnssec.zones"
    family = ProbeFamily.DNS_EMAIL
    framework_tags = ("nist-ir-8547:dns", "bukukerja:dns", "mykripto:dns")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/bind"), Path("/var/lib/bind"),
            Path("/etc/named"), Path("/var/named"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix not in {".zone", ".conf", ".db", ".local", ""}:
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                # DNSKEY records
                for m in _DNSKEY_RE.finditer(text):
                    alg = int(m.group(1))
                    if alg in _DEPRECATED:
                        cls, sev = Classification.SANGAT_TINGGI, Severity.CRIT
                    elif alg in _RSA:
                        cls, sev = Classification.TINGGI, Severity.HIGH
                    elif alg in _ECDSA or alg in _EDDSA:
                        cls, sev = Classification.TINGGI, Severity.HIGH
                    else:
                        cls, sev = Classification.INFO, Severity.INFO
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=f"DNSSEC-alg-{alg}",
                        classification=cls, severity=sev,
                        title=f"DNSKEY algorithm {alg} in {path.name}",
                        evidence={"path": str(path), "alg": alg},
                    ))
                # dnssec-policy / algorithm directives
                for m in _POLICY_ALG_RE.finditer(text):
                    name = m.group(1).lower()
                    if name in _POLICY_NAMES:
                        cls, sev, alg_id = _POLICY_NAMES[name]
                        emit(Finding(
                            probe_id=self.id,
                            algorithm=f"DNSSEC-{name.upper()}",
                            classification=cls, severity=sev,
                            title=f"dnssec-policy algorithm = {name} (id {alg_id}) in {path.name}",
                            evidence={"path": str(path), "policy_name": name},
                        ))

"""Crypto-agility: how cheaply can this asset's cryptography be changed? 0 (rebuild hardware) to 100 (edit a config)."""
from __future__ import annotations

from dataclasses import dataclass, field

from pqcscan.core.parity import is_drift

_VULNERABLE = {"sangat-tinggi", "tinggi", "sederhana"}
# (prefixes, score, source label). First match wins, so order matters.
_RULES: tuple[tuple[tuple[str, ...], int, str], ...] = (
    (("fs.conf.ibmi_sysval",), 10, "hardware"),
    (("hw.", "host.tpm", "ot."), 10, "hardware"),
    (("storage.", "vpn."), 20, "rebuild"),
    (("code.",), 30, "source"),
    (("sbom.", "container."), 50, "dependency"),
    (("fs.cert.", "fs.keystore.", "email.", "dns.", "sign.", "trust.", "host.cloud_kms", "fs.keyref.cloud"),
     70, "rotate"),
    (("net.",), 80, "server-config"),
    (("host.crypto_policies", "host.java.security", "host.openssl.", "fs.conf.", "app.", "host.ssh.",
      "host.gnutls", "host.nss", "host.windows.schannel", "k8s.", "fs.iac."), 90, "config"),
)


def finding_agility(probe_id: str, evidence: dict) -> int:
    ev = evidence or {}
    if probe_id == "fs.binary.crypto":
        if ev.get("detection") == "constant-signature" or ev.get("linked") == "embedded":
            return 20
        return 50
    for prefixes, score, _src in _RULES:
        if probe_id.startswith(prefixes):
            return score
    return 50


def _source(probe_id: str, evidence: dict) -> str:
    if probe_id == "fs.binary.crypto":
        return "rebuild" if finding_agility(probe_id, evidence) == 20 else "dependency"
    for prefixes, _score, src in _RULES:
        if probe_id.startswith(prefixes):
            return src
    return "unknown"


@dataclass(slots=True)
class AgilityResult:
    score: int
    band: str
    by_source: dict[str, int] = field(default_factory=dict)


def score_findings(findings: list) -> AgilityResult:
    """Mean agility of the quantum-vulnerable findings; ``fleet.drift`` bookkeeping findings never count."""
    rows = [f for f in findings
            if str(getattr(f, "classification", "")) in _VULNERABLE and not is_drift(f)]
    if not rows:
        return AgilityResult(100, "high", {})
    total = 0
    by: dict[str, int] = {}
    for f in rows:
        ev = getattr(f, "evidence", {}) or {}
        total += finding_agility(f.probe_id, ev)
        src = _source(f.probe_id, ev)
        by[src] = by.get(src, 0) + 1
    score = round(total / len(rows))
    return AgilityResult(score, "high" if score >= 70 else "medium" if score >= 40 else "low", by)

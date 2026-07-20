"""net.ct.crtsh — Certificate Transparency inventory via crt.sh.

The live TLS probes see only the certificate a server is serving *right now*.
Certificate Transparency logs record every publicly-trusted certificate ever
issued for a domain — so a CT lookup reveals the full certificate/subdomain
footprint an organisation must migrate, not just the one endpoint scanned. This
is the certificate-discovery surface the peer tools (open-quantum-secure's
ct-lookup, commercial cert-discovery platforms) cover.

Active + opt-in: only runs when a *domain* target is set, and makes a single
outbound request to crt.sh. Wrapped so a scan never fails on network error.
Confidence is medium — CT metadata is authoritative for existence/expiry but
does not carry the signature algorithm, so this complements (not replaces) the
live TLS cert-chain probes.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _fetch_crtsh(domain: str, timeout: float) -> list[dict[str, Any]]:
    """Fetch crt.sh JSON for `domain`. Returns [] on any failure."""
    try:
        import httpx
        url = f"https://crt.sh/?q={domain}&output=json"
        resp = httpx.get(url, timeout=timeout, follow_redirects=True,
                         headers={"User-Agent": "pqcscan"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        return data if isinstance(data, list) else []
    except Exception:
        # crt.sh occasionally returns non-JSON / HTML under load.
        return []


class NetCtCrtsh(Probe):
    id = "net.ct.crtsh"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:cert", "mykripto:cert")

    def __init__(self, target: str | None = None, fetcher=None, timeout: float = 10.0):
        self.target = target
        self.timeout = timeout
        # Injectable for tests: fetcher(domain) -> list[dict].
        self._fetch = fetcher or (lambda d: _fetch_crtsh(d, self.timeout))

    def _domain(self, ctx: ScanContext) -> str | None:
        raw = self.target or ctx.server_target
        if not raw:
            return None
        host = raw.partition(":")[0].strip().lower()
        # Only a registrable domain makes sense for a CT lookup — skip bare IPs.
        if not host or _IP_RE.match(host) or "." not in host:
            return None
        return host

    async def applies(self, ctx: ScanContext) -> bool:
        return self._domain(ctx) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        domain = self._domain(ctx)
        if domain is None:
            return
        try:
            entries = self._fetch(domain)
        except Exception:
            return
        if not entries:
            return

        names: set[str] = set()
        expired = 0
        now = datetime.utcnow()
        for e in entries:
            for nv in str(e.get("name_value", "")).splitlines():
                nv = nv.strip().lower().lstrip("*.")
                if nv and domain in nv:
                    names.add(nv)
            na = e.get("not_after")
            if isinstance(na, str):
                try:
                    if datetime.fromisoformat(na.replace("Z", "")) < now:
                        expired += 1
                except ValueError:
                    pass

        subdomains = sorted(n for n in names if n != domain)
        # One inventory finding: the CT-derived certificate/subdomain footprint.
        emit(Finding(
            probe_id=self.id,
            algorithm="x509-classical",
            classification=Classification.SEDERHANA,
            severity=Severity.MED,
            title=(
                f"{len(entries)} certificate(s) for {domain} in CT logs "
                f"({len(subdomains)} subdomain(s)) — classical X.509 to migrate"
            ),
            evidence={
                "domain": domain,
                "certificate_count": len(entries),
                "unique_names": len(names),
                "subdomains": subdomains[:100],
                "expired_in_logs": expired,
                "source": "crt.sh",
                "confidence": "medium",
            },
            remediation={
                "note": "CT logs reveal the full public certificate footprint. "
                        "Inventory every host + migrate its cert to a PQC/hybrid "
                        "signature (ML-DSA / composite) as CAs enable it.",
            },
        ))

    def _entries_json(self, raw: str) -> list[dict]:  # pragma: no cover - helper
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except (ValueError, TypeError):
            return []

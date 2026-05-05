"""net.tls.sslyze — wraps SSLyze (Apache-2.0). Python TLS scanner."""
from __future__ import annotations

import asyncio
import json

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none


class NetTlsSslyze(Probe):
    id = "net.tls.sslyze"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 443,
                 sslyze_bin: str | None = None, timeout_s: float = 120.0):
        self.host, self.port = host, port
        self.sslyze_bin = sslyze_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return resolve_or_none(self.sslyze_bin, "sslyze") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = resolve_or_none(self.sslyze_bin, "sslyze")
        if bin_path is None:
            return
        proc = await asyncio.create_subprocess_exec(
            str(bin_path), f"{self.host}:{self.port}", "--json_out=-", "--quiet",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return
        for result in doc.get("server_scan_results", []) or []:
            sr = result.get("scan_result", {}) or {}
            for proto in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
                          "tls_1_0_cipher_suites", "tls_1_1_cipher_suites"):
                pr = sr.get(proto, {}) or {}
                accepted = pr.get("result", {}).get("accepted_cipher_suites", [])
                if accepted:
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=proto.replace("_cipher_suites", "").upper(),
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=f"sslyze: {proto} enabled at {self.host}:{self.port}",
                        evidence={"endpoint": f"{self.host}:{self.port}",
                                  "accepted": [c.get("cipher_suite", {}).get("name", "")
                                               for c in accepted[:5]]},
                    ))

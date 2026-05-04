"""net.tls.nmap_ssl — wraps nmap with --script ssl-enum-ciphers."""
from __future__ import annotations

import asyncio
import re
import shutil

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


_LETTER_TO_CLASS = {
    "F": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "E": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "D": (Classification.TINGGI, Severity.HIGH),
    "C": (Classification.TINGGI, Severity.HIGH),
    "B": (Classification.SEDERHANA, Severity.MED),
    "A": (Classification.RENDAH, Severity.LOW),
}


class NetTlsNmapSsl(Probe):
    id = "net.tls.nmap_ssl"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 443,
                 nmap_bin: str | None = None, timeout_s: float = 120.0):
        self.host, self.port = host, port
        self.nmap_bin = nmap_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.nmap_bin or "nmap") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.nmap_bin or "nmap"
        proc = await asyncio.create_subprocess_exec(
            bin_path, "-p", str(self.port), "--script", "ssl-enum-ciphers",
            self.host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")
        # Parse cipher suite lines from the nmap output.
        # Example: "|       TLS_RSA_WITH_AES_128_CBC_SHA - C"
        cipher_re = re.compile(r"\|\s+(\S+)\s+-\s+([A-F])")
        for m in cipher_re.finditer(text):
            cipher_name, grade = m.group(1), m.group(2)
            cls, sev = _LETTER_TO_CLASS.get(grade, (Classification.INFO, Severity.INFO))
            emit(Finding(
                probe_id=self.id,
                algorithm=cipher_name,
                classification=cls, severity=sev,
                title=f"nmap ssl-enum {cipher_name} grade {grade}",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "cipher": cipher_name, "grade": grade},
            ))

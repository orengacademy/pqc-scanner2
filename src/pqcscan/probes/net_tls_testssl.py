"""net.tls.testssl — wraps testssl.sh (FOSS, GPL-2). Comprehensive TLS scanner."""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for
from pqcscan.util.offline_pack import resolve_or_none


_SEV_MAP = {
    "CRITICAL": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "HIGH":     (Classification.TINGGI, Severity.HIGH),
    "MEDIUM":   (Classification.SEDERHANA, Severity.MED),
    "LOW":      (Classification.RENDAH, Severity.LOW),
    "WARN":     (Classification.SEDERHANA, Severity.MED),
    "INFO":     (Classification.INFO, Severity.INFO),
    "OK":       (Classification.INFO, Severity.INFO),
}


class NetTlsTestssl(Probe):
    id = "net.tls.testssl"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 443,
                 testssl_bin: str | None = None, timeout_s: float = 180.0):
        self.host, self.port = host, port
        self.testssl_bin = testssl_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return resolve_or_none(self.testssl_bin, "testssl.sh") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = resolve_or_none(self.testssl_bin, "testssl.sh")
        if bin_path is None:
            return
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_json = tf.name
        proc = await asyncio.create_subprocess_exec(
            str(bin_path), "--quiet", "--jsonfile", out_json,
            f"{self.host}:{self.port}",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            return
        try:
            data = json.loads(Path(out_json).read_text())
        except (OSError, json.JSONDecodeError):
            return
        for entry in data:
            sev_label = entry.get("severity", "INFO").upper()
            cls, sev = _SEV_MAP.get(sev_label, (Classification.INFO, Severity.INFO))
            emit(Finding(
                probe_id=self.id,
                algorithm=entry.get("id", "N/A"),
                classification=cls, severity=sev,
                title=f"testssl {sev_label}: {entry.get('finding', entry.get('id', ''))}",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "raw_severity": sev_label,
                          "section": entry.get("section", ""),
                          "id": entry.get("id", "")},
            ))

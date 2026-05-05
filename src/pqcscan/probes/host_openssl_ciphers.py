from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class HostOpenSSLCiphers(Probe):
    """Run `openssl ciphers -V` and classify each enabled cipher."""
    id = "host.openssl.ciphers"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, openssl: str | None = None):
        self.openssl = openssl  # None -> auto-detect via PATH

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.openssl or "openssl") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.openssl or "openssl"
        proc = await asyncio.create_subprocess_exec(
            bin_path, "ciphers", "-V", "ALL",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")
        # Per-line format (OpenSSL 3.x):
        #   0xC0,0x30 - ECDHE-RSA-AES256-GCM-SHA384  TLSv1.2  Kx=ECDH  Au=RSA  Enc=AESGCM(256)  Mac=AEAD
        # Extract `Enc=ALG(NN)` and classify the canonical primitive name —
        # classify() understands AES-128 / AES-256 / 3DES / RC4 etc.,
        # whereas the composite cipher-suite name does not match any pattern.
        import re as _re
        enc_re = _re.compile(r"Enc=([A-Za-z0-9]+)(?:\((\d+)\))?")
        for line in text.splitlines():
            line = line.strip()
            if not line or " - " not in line:
                continue
            cipher_name = line.split(" - ", 1)[1].split()[0]
            m = enc_re.search(line)
            if not m:
                continue
            enc_alg, key_bits = m.group(1).upper(), m.group(2)
            if enc_alg.startswith("AESGCM"):
                canonical = f"AES-{key_bits or '128'}-GCM"
            elif enc_alg.startswith("AESCCM") or enc_alg.startswith("AES"):
                canonical = f"AES-{key_bits or '128'}"
            elif enc_alg in {"DES", "3DES", "TRIPLEDES"}:
                canonical = "3DES" if enc_alg != "DES" else "DES"
            elif enc_alg.startswith("RC4"):
                canonical = "RC4"
            elif enc_alg.startswith("CHACHA"):
                canonical = "ChaCha20"
            else:
                canonical = enc_alg
            cls = classify(canonical)
            if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                emit(Finding(
                    probe_id=self.id,
                    algorithm=normalise(canonical),
                    classification=cls,
                    severity=_sev(cls),
                    title=f"openssl ciphers includes {cipher_name} ({canonical})",
                    evidence={"line": line, "enc": enc_alg, "bits": key_bits},
                    remediation={
                        "snippet": f"# Disable via SSLCipherSuite / openssl.cnf — exclude {cipher_name}",
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

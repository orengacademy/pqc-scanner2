"""fs.conf.ibmi_sysval — IBM i (AS/400) System SSL posture from exported system values.

IBM i has no agent and no binary we can run, so collect on the LPAR and scan
the export with `--path`:

    DSPSYSVAL SYSVAL(QSSLPCL)    OUTPUT(*PRINT)   # TLS protocol versions
    DSPSYSVAL SYSVAL(QSSLCSL)    OUTPUT(*PRINT)   # cipher suite list
    DSPSYSVAL SYSVAL(QSSLCSLCTL) OUTPUT(*PRINT)   # *OPSYS or *USRDFN control
    (copy the spool files to a PC as text; one file or several, any name)

Certificates: export from DCM (Digital Certificate Manager) as PEM into the
same directory — `fs.cert.x509` / `fs.cert.chain` inventory them.

Format tolerance: any text file that mentions QSSLPCL or QSSLCSL is parsed by
token (`*TLSV1.2`, `*RSA_RC4_128_SHA`, ...), so WRKSYSVAL prints, DSPSYSVAL
spools and hand-written `QSSLPCL *TLSV1.2 *TLSV1.3` notes all work.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import classify_suite, sev_for

_PROTO_RE = re.compile(r"\*(SSLV2|SSLV3|TLSV1\.3|TLSV1\.2|TLSV1\.1|TLSV1|OPSYS)\b", re.I)
_SUITE_RE = re.compile(r"\*((?:ECDHE|ECDH|DHE|RSA|ECDSA|PSK|AES|CHACHA20|3DES|RC4|DES|NULL)[A-Z0-9_]+)")
_WEAK_PROTOS = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}
# Cipher-bearing tokens; everything before the first one is the key exchange.
_CIPHER_WORDS = ("AES", "3DES", "RC4", "DES", "CHACHA20", "NULL", "RC2")
_MAX_BYTES = 2_000_000


def _to_iana(ibm: str) -> str:
    """`ECDHE_RSA_AES_128_GCM_SHA256` -> `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`;
    TLS 1.3 names (`AES_128_GCM_SHA256`) have no key-exchange prefix."""
    parts = ibm.upper().split("_")
    for i, p in enumerate(parts):
        if p in _CIPHER_WORDS:
            return "TLS_" + ("_".join(parts[:i]) + "_WITH_" if i else "") + "_".join(parts[i:])
    return "TLS_" + ibm.upper()


class FsConfIbmiSysval(Probe):
    id = "fs.conf.ibmi_sysval"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls", "nacsa-9:tls")

    def __init__(self, roots: list[Path] | None = None):
        # No host default: the export only exists where --path points.
        self.roots = roots if roots is not None else []

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
            for path in files:
                if path in seen or path.stat().st_size > _MAX_BYTES:
                    continue
                seen.add(path)
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                up = text.upper()
                if "QSSLPCL" not in up and "QSSLCSL" not in up:
                    continue
                self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        protos = sorted({m.group(1).upper() for m in _PROTO_RE.finditer(text)})
        suites = sorted({m.group(1).upper() for m in _SUITE_RE.finditer(text)})
        ev_base = {"path": str(path), "source": "ibmi-sysval"}
        for proto in protos:
            if proto in _WEAK_PROTOS:
                emit(Finding(
                    probe_id=self.id, algorithm=proto,
                    classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT,
                    title=f"IBM i QSSLPCL enables {proto}",
                    evidence={**ev_base, "sysval": "QSSLPCL"},
                    remediation={"snippet": "CHGSYSVAL SYSVAL(QSSLPCL) VALUE('*TLSV1.3 *TLSV1.2')"},
                ))
        if "OPSYS" in protos:
            emit(Finding(
                probe_id=self.id, algorithm="QSSLPCL=*OPSYS",
                classification=Classification.SEDERHANA, severity=Severity.MED,
                title="IBM i QSSLPCL is *OPSYS (protocol set follows OS release)",
                evidence={**ev_base, "sysval": "QSSLPCL",
                          "note": "*OPSYS enables TLSv1.0/1.1 on 7.3 and earlier; "
                                  "7.4+ defaults to TLSv1.2/1.3. Pin explicitly.",
                          "confidence": "medium"},
                remediation={"snippet": "CHGSYSVAL SYSVAL(QSSLPCL) VALUE('*TLSV1.3 *TLSV1.2')"},
            ))
        for s in suites:
            iana = _to_iana(s)
            cls = classify_suite(iana)
            if cls is Classification.INFO:
                # TLS 1.3 AEAD suite: no KEX in the name; classical groups → Grover-only tier.
                cls = Classification.SEDERHANA
            emit(Finding(
                probe_id=self.id, algorithm=iana, classification=cls, severity=sev_for(cls),
                title=f"IBM i QSSLCSL offers *{s}",
                evidence={**ev_base, "sysval": "QSSLCSL", "ibm_name": f"*{s}"},
            ))
        if protos or suites:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"IBM i System SSL inventory: {len(protos)} protocol tokens, {len(suites)} suites",
                evidence={**ev_base, "protocols": protos, "suites": [f"*{s}" for s in suites]},
            ))

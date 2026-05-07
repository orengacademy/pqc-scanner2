"""DTLS handshake probe — shells out to `openssl s_client -dtls<ver>`."""
from __future__ import annotations

import asyncio
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, Severity


_CIPHER_RE = re.compile(r"^\s*Cipher\s*:\s*(\S+)", re.MULTILINE)
_VERSION_RE = re.compile(r"^\s*Protocol\s*:\s*(\S+)", re.MULTILINE)
_SUBJECT_RE = re.compile(r"^\s*subject=([^\n]+)", re.MULTILINE)


@dataclass(slots=True)
class DTLSHandshakeResult:
    version: str | None
    cipher: str | None
    peer_cert_subject: str | None
    raw: str
    algorithms: list[str]


def _parse_dtls_handshake(text: str) -> DTLSHandshakeResult:
    cipher_m = _CIPHER_RE.search(text)
    ver_m = _VERSION_RE.search(text)
    subj_m = _SUBJECT_RE.search(text)
    cipher = cipher_m.group(1) if cipher_m else None
    version = ver_m.group(1) if ver_m else None
    subject = subj_m.group(1).strip() if subj_m else None

    algos: list[str] = []
    if cipher:
        mapping = {
            "AES256": "AES-256", "AES128": "AES-128",
            "3DES": "3DES", "RC4": "RC4",
            "SHA384": "SHA-384", "SHA256": "SHA-256",
            "SHA1": "SHA-1", "MD5": "MD5",
        }
        for token in cipher.split("-"):
            if token in mapping:
                algos.append(mapping[token])
            elif token in {"RSA", "ECDSA", "ECDHE", "DHE"}:
                algos.append(token)
    return DTLSHandshakeResult(
        version=version, cipher=cipher, peer_cert_subject=subject,
        raw=text, algorithms=algos,
    )


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


async def run_dtls_probe(
    *,
    host: str,
    port: int,
    version: str = "1.2",
    probe_id: str,
    emit: Callable[[Finding], None],
    timeout_s: float = 10.0,
) -> None:
    """Run an openssl s_client DTLS handshake against host:port and emit Findings."""
    if shutil.which("openssl") is None:
        emit(Finding(
            probe_id=probe_id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"DTLS probe skipped at {host}:{port}: openssl not on PATH",
            evidence={"endpoint": f"udp://{host}:{port}"},
        ))
        return

    flag = f"-dtls{version.replace('.', '_')}"
    args = [
        "openssl", "s_client", flag,
        "-connect", f"{host}:{port}",
    ]
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=b"\n"), timeout=timeout_s,
        )
    except (TimeoutError, asyncio.TimeoutError):
        proc.kill()
        emit(Finding(
            probe_id=probe_id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"DTLS probe timeout at {host}:{port}",
            evidence={"endpoint": f"udp://{host}:{port}", "timeout_s": timeout_s, "version": version},
        ))
        return

    text = (
        stdout_b.decode("utf-8", errors="replace")
        + "\n"
        + stderr_b.decode("utf-8", errors="replace")
    )
    parsed = _parse_dtls_handshake(text)

    if not parsed.cipher and not parsed.algorithms:
        emit(Finding(
            probe_id=probe_id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"DTLS handshake produced no cipher at {host}:{port}",
            evidence={"endpoint": f"udp://{host}:{port}", "raw_head": text[:400]},
        ))
        return

    for alg in parsed.algorithms:
        cls = classify(alg)
        emit(Finding(
            probe_id=probe_id,
            algorithm=normalise(alg),
            classification=cls,
            severity=_sev(cls),
            title=f"DTLS {parsed.version or version} cipher {parsed.cipher} -> {alg}",
            evidence={
                "endpoint": f"udp://{host}:{port}",
                "dtls_version": parsed.version,
                "cipher_suite": parsed.cipher,
                "peer_subject": parsed.peer_cert_subject,
            },
        ))

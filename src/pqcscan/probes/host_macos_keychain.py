"""host.macos.keychain — macOS system trust store crypto inventory.

macOS ships its trusted root CAs in the system keychain, exposed via the
`security` CLI:

    security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain

That dumps every system root CA as PEM. This probe parses each root's
signature algorithm and public-key type/size with the `cryptography` lib and
classifies it: MD5/SHA-1-signed or RSA-1024 roots are broken-now
(SANGAT_TINGGI); modern RSA/ECDSA roots are classical and therefore
quantum-vulnerable (TINGGI). One finding per weak/quantum-vulnerable root.

Live tool calls run only on macOS (`sys.platform == "darwin"`); tests inject
a PEM bundle via `security_pem=` so the probe is exercisable on Linux CI.
"""
from __future__ import annotations

import asyncio
import shutil
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqcscan.core.alg import normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_SYSTEM_ROOTS_KEYCHAIN = "/System/Library/Keychains/SystemRootCertificates.keychain"

# Signature primitives that are already broken on a classical computer.
_WEAK_SIG_SUBSTR: tuple[str, ...] = ("MD5", "MD4", "MD2", "SHA1", "SHA-1")


class HostMacosKeychain(Probe):
    """Inventory the macOS system trust store for weak / quantum-vulnerable roots."""

    id = "host.macos.keychain"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:cert", "mykripto:cert")

    def __init__(
        self,
        security_pem: str | None = None,
        security_cmd: str = "security",
    ) -> None:
        # security_pem is an injectable seam so tests need no real `security`.
        self._security_pem = security_pem
        self.security_cmd = security_cmd

    async def applies(self, ctx: ScanContext) -> bool:
        if self._security_pem is not None:
            return True
        return sys.platform == "darwin" and shutil.which(self.security_cmd) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        pem = self._security_pem
        if pem is None:
            pem = await self._dump_system_roots()
        if not pem:
            return

        seen: set[tuple[str, str]] = set()
        for cert in self._load_certs(pem):
            self._emit_for_cert(cert, seen, emit)

    def _emit_for_cert(
        self,
        cert: x509.Certificate,
        seen: set[tuple[str, str]],
        emit: Emitter,
    ) -> None:
        try:
            sigalg = normalise(cert.signature_algorithm_oid.dotted_string)
            key = self._key_desc(cert)
            subject = cert.subject.rfc4514_string()
        except Exception:  # never let a bad cert break the sweep
            return

        classification = self._classify_root(sigalg, key)
        if classification is None:
            return  # healthy modern root — skip

        dedupe = (subject, sigalg)
        if dedupe in seen:
            return
        seen.add(dedupe)

        emit(Finding(
            probe_id=self.id,
            algorithm=f"keychain-root/{sigalg}",
            classification=classification,
            severity=sev_for(classification),
            title=f"macOS trust root: {sigalg} {subject[:60]}",
            evidence={
                "subject": subject[:120],
                "sigalg": sigalg,
                "key": key,
            },
        ))

    @staticmethod
    def _classify_root(sigalg: str, key: str) -> Classification | None:
        """Classify a system root by its signature + public key.

        MD5/SHA-1 signatures and RSA-1024 keys are broken now
        (SANGAT_TINGGI); RSA/ECDSA/DSA/EdDSA roots are classical and
        quantum-vulnerable (TINGGI). Anything else (e.g. a PQC root) is
        healthy → None (skip).
        """
        up = sigalg.upper()
        if any(sub in up for sub in _WEAK_SIG_SUBSTR):
            return Classification.SANGAT_TINGGI

        kind, _, size = key.partition("-")
        if kind == "RSA" and size.isdigit() and int(size) < 2048:
            return Classification.SANGAT_TINGGI

        if kind in {"RSA", "ECDSA", "DSA", "Ed25519", "Ed448"} or key in {
            "Ed25519", "Ed448",
        }:
            return Classification.TINGGI

        return None

    @staticmethod
    def _key_desc(cert: x509.Certificate) -> str:
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            return f"RSA-{pk.key_size}"
        if isinstance(pk, ec.EllipticCurvePublicKey):
            return f"ECDSA-{pk.curve.name}"
        if isinstance(pk, dsa.DSAPublicKey):
            return f"DSA-{pk.key_size}"
        if isinstance(pk, ed25519.Ed25519PublicKey):
            return "Ed25519"
        if isinstance(pk, ed448.Ed448PublicKey):
            return "Ed448"
        return type(pk).__name__

    @staticmethod
    def _load_certs(pem: str) -> list[x509.Certificate]:
        """Split a PEM bundle and load each cert, skipping malformed blocks."""
        certs: list[x509.Certificate] = []
        try:
            data = pem.encode("utf-8", errors="replace")
        except Exception:
            return certs
        marker = b"-----BEGIN CERTIFICATE-----"
        for blk in data.split(marker)[1:]:
            blob = marker + blk
            try:
                certs.append(x509.load_pem_x509_certificate(blob))
            except Exception:  # garbage block, keep going
                continue
        return certs

    async def _dump_system_roots(self) -> str | None:
        if sys.platform != "darwin" or not shutil.which(self.security_cmd):
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.security_cmd, "find-certificate", "-a", "-p",
                _SYSTEM_ROOTS_KEYCHAIN,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        except (TimeoutError, OSError):
            return None
        if proc.returncode != 0:
            return None
        return stdout.decode("utf-8", errors="replace")

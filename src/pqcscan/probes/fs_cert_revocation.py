"""fs.cert.revocation — on-disk X.509 revocation & transparency posture.

Parse end-entity certificates under the trust roots and inspect their
revocation / transparency infrastructure WITHOUT any network access:

  * AuthorityInformationAccess -> OCSP responder URLs
  * CRLDistributionPoints      -> CRL URLs
  * TLSFeature (status_request)-> OCSP must-staple
  * embedded SCTs              -> Certificate Transparency presence

A compromised classical cert that carries NEITHER an OCSP responder NOR a CRL
distribution point cannot be quickly revoked. During PQC migration — when
operators expect to rotate / re-key a large fleet — a leaf with no revocation
path is a latent risk, so it is flagged SEDERHANA/MED. CA certs (the trust
bundle) are skipped to avoid noise.
"""
from __future__ import annotations

import warnings
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import AuthorityInformationAccessOID

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXTS = (".pem", ".crt", ".cer")

# Skip absurdly large files — a real cert is a few KB; anything past this is a
# bundle or unrelated blob and not worth parsing per the bounded-work rule.
_MAX_BYTES = 1 << 20  # 1 MiB

# Classical (quantum-vulnerable) public-key primitives. PQC keys (ML-DSA /
# ML-KEM / SLH-DSA) never deserialise into one of these types.
_CLASSICAL = (
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    dsa.DSAPublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
)


class FsCertRevocation(Probe):
    """Inspect leaf X.509 certs for revocation / transparency infrastructure."""
    id = "fs.cert.revocation"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/ssl"), Path("/etc/pki")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not (path.is_file() and path.suffix.lower() in _EXTS):
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                self._scan_one(path, emit)

    def _scan_one(self, path: Path, emit: Emitter) -> None:
        try:
            if path.stat().st_size > _MAX_BYTES:
                return
            data = path.read_bytes()
        except OSError:
            return
        cert = _load_cert(data)
        if cert is None:
            return
        # Skip CA certs: the system trust bundle is full of long-lived CA certs
        # that are the distro's / a CA's scope, not the operator's leaf scope.
        if _is_ca(cert):
            return
        # Only classical-keyed leaves carry the harvest / fast-revocation risk.
        if not isinstance(cert.public_key(), _CLASSICAL):
            return

        ocsp_urls = _ocsp_urls(cert)
        crl_urls = _crl_urls(cert)
        must_staple = _must_staple(cert)
        sct_present = _sct_present(cert)
        evidence = {
            "path": str(path),
            "subject": cert.subject.rfc4514_string(),
            "ocsp_urls": ocsp_urls,
            "crl_urls": crl_urls,
            "must_staple": must_staple,
            "sct_present": sct_present,
        }

        if not ocsp_urls and not crl_urls:
            emit(Finding(
                probe_id=self.id,
                algorithm=_key_algorithm(cert.public_key()),
                classification=Classification.SEDERHANA,
                severity=_sev(Classification.SEDERHANA),
                title=f"{path.name}: classical cert has no revocation path (no OCSP, no CRL)",
                evidence=evidence,
                remediation={
                    "snippet": "# No revocation path — a compromised classical cert cannot be "
                               "quickly revoked during PQC migration. Re-issue with an OCSP "
                               "responder (AIA) or CRL distribution point, and prefer "
                               "OCSP must-staple.",
                },
            ))
            return

        emit(Finding(
            probe_id=self.id,
            algorithm=_key_algorithm(cert.public_key()),
            classification=Classification.INFO,
            severity=_sev(Classification.INFO),
            title=f"{path.name}: revocation endpoints "
                  f"(OCSP={len(ocsp_urls)}, CRL={len(crl_urls)})",
            evidence=evidence,
        ))


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(bc.value.ca)


def _load_cert(data: bytes) -> x509.Certificate | None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError:
            try:
                return x509.load_der_x509_certificate(data)
            except ValueError:
                return None


def _ocsp_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
    except x509.ExtensionNotFound:
        return []
    urls: list[str] = []
    for desc in aia:
        # Only URI GeneralNames carry a str .value; DirectoryName/OtherName
        # values are non-str objects that break JSON evidence serialization.
        if desc.access_method == AuthorityInformationAccessOID.OCSP and isinstance(
            desc.access_location, x509.UniformResourceIdentifier
        ):
            urls.append(desc.access_location.value)
    return urls


def _crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        cdp = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
    except x509.ExtensionNotFound:
        return []
    urls: list[str] = []
    for point in cdp:
        for name in point.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


def _must_staple(cert: x509.Certificate) -> bool:
    try:
        feature = cert.extensions.get_extension_for_class(x509.TLSFeature).value
    except x509.ExtensionNotFound:
        return False
    return x509.TLSFeatureType.status_request in feature


def _sct_present(cert: x509.Certificate) -> bool:
    try:
        scts = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        ).value
    except x509.ExtensionNotFound:
        return False
    return len(list(scts)) > 0


def _key_algorithm(pk: object) -> str:
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

"""fs.cert.chain — assemble X.509 chains from on-disk certs and report the
weakest link, plus SPKI key-reuse detection. No network access.

Loads all certs under `roots` (*.pem/*.crt/*.cer, PEM or DER), builds an
AuthorityKeyIdentifier->SubjectKeyIdentifier index (falling back to issuer/
subject DN match), walks each leaf up to its root, and emits a finding for
the WEAKEST link in that chain (lowest-strength public key or weakest
signature hash across every cert) — a weak intermediate/root undermines all
leaves beneath it. Separately detects the same SPKI bytes reused across 2+
distinct certs.
"""
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXTS = (".pem", ".crt", ".cer")

# Lower numeric severity == weaker link. Used to pick the weakest cert.
_RANK = {
    Classification.SANGAT_TINGGI: 0,
    Classification.TINGGI: 1,
    Classification.SEDERHANA: 2,
    Classification.RENDAH: 3,
    Classification.PQC_READY: 4,
    Classification.INFO: 5,
    Classification.ERROR: 5,
}


def _load_cert(path: Path) -> x509.Certificate | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return None


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


def _sig_hash_alg(cert: x509.Certificate) -> str | None:
    """Return a classify()-friendly signature hash name, e.g. SHA-1, SHA-256."""
    try:
        h = cert.signature_hash_algorithm
    except Exception:
        return None
    if h is None:
        return None
    name = h.name.upper()  # "sha1", "sha256", "sha512", ...
    if name.startswith("SHA") and not name.startswith("SHA-"):
        digits = name[3:]
        if digits.isdigit():
            return f"SHA-{digits}"
    return name


def _ski(cert: x509.Certificate) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        return None
    return ext.value.digest


def _aki(cert: x509.Certificate) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    except x509.ExtensionNotFound:
        return None
    return ext.value.key_identifier


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(bc.value.ca)


def _is_self_issued(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def _spki_bytes(cert: x509.Certificate) -> bytes | None:
    try:
        return cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return None


def _chain_classifications(cert: x509.Certificate) -> list[tuple[str, Classification]]:
    """Public-key and signature-hash (alg, classification) pairs for one cert."""
    out: list[tuple[str, Classification]] = []
    pk_alg = _key_algorithm(cert.public_key())
    out.append((pk_alg, classify(pk_alg)))
    sig = _sig_hash_alg(cert)
    if sig is not None:
        out.append((sig, classify(sig)))
    return out


class FsCertChain(Probe):
    id = "fs.cert.chain"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc"), Path("/usr/local/etc")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        certs: list[tuple[Path, x509.Certificate]] = []
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not (path.is_file() and path.suffix.lower() in _EXTS):
                    continue
                cert = _load_cert(path)
                if cert is not None:
                    certs.append((path, cert))

        if len(certs) < 2:
            return

        self._emit_chains(certs, emit)
        self._emit_key_reuse(certs, emit)

    # ---- chain assembly -------------------------------------------------

    def _emit_chains(
        self,
        certs: list[tuple[Path, x509.Certificate]],
        emit: Emitter,
    ) -> None:
        # Index issuers by SubjectKeyIdentifier and by subject DN so we can
        # walk a leaf up to its root.
        by_ski: dict[bytes, tuple[Path, x509.Certificate]] = {}
        by_subject: dict[str, tuple[Path, x509.Certificate]] = {}
        issued_subjects: set[str] = set()  # subject DNs that issue another cert
        for path, cert in certs:
            ski = _ski(cert)
            if ski is not None:
                by_ski.setdefault(ski, (path, cert))
            subj = cert.subject.rfc4514_string()
            by_subject.setdefault(subj, (path, cert))

        for _, cert in certs:
            issuer_dn = cert.issuer.rfc4514_string()
            if issuer_dn != cert.subject.rfc4514_string():
                issued_subjects.add(issuer_dn)

        for path, cert in certs:
            subj = cert.subject.rfc4514_string()
            # A leaf issues nothing, or is a non-CA end-entity.
            if subj in issued_subjects and _is_ca(cert):
                continue
            self._walk_and_emit(path, cert, by_ski, by_subject, emit)

    def _walk_and_emit(
        self,
        leaf_path: Path,
        leaf: x509.Certificate,
        by_ski: dict[bytes, tuple[Path, x509.Certificate]],
        by_subject: dict[str, tuple[Path, x509.Certificate]],
        emit: Emitter,
    ) -> None:
        chain: list[tuple[Path, x509.Certificate]] = [(leaf_path, leaf)]
        seen: set[str] = {leaf.subject.rfc4514_string()}
        cur = leaf
        while not _is_self_issued(cur):
            parent: tuple[Path, x509.Certificate] | None = None
            aki = _aki(cur)
            if aki is not None and aki in by_ski:
                parent = by_ski[aki]
            else:
                issuer_dn = cur.issuer.rfc4514_string()
                parent = by_subject.get(issuer_dn)
            if parent is None:
                break
            parent_subj = parent[1].subject.rfc4514_string()
            if parent_subj in seen:
                break  # cycle / loop guard
            seen.add(parent_subj)
            chain.append(parent)
            cur = parent[1]

        # Find the weakest link across every cert in the assembled chain.
        weakest_alg = ""
        weakest_cls = Classification.PQC_READY
        weakest_path = leaf_path
        for cpath, ccert in chain:
            for alg, cls in _chain_classifications(ccert):
                if _RANK[cls] < _RANK[weakest_cls]:
                    weakest_cls = cls
                    weakest_alg = alg
                    weakest_path = cpath

        if not weakest_alg:
            return

        emit(Finding(
            probe_id=self.id,
            algorithm=weakest_alg,
            classification=weakest_cls,
            severity=_sev(weakest_cls),
            title=f"chain weakest link: {weakest_alg} ({weakest_path.name})",
            evidence={
                "leaf": str(leaf_path),
                "leaf_subject": leaf.subject.rfc4514_string(),
                "chain_length": len(chain),
                "chain": [str(p) for p, _ in chain],
                "weakest_link": str(weakest_path),
                "weakest_algorithm": weakest_alg,
            },
        ))

    # ---- key reuse ------------------------------------------------------

    def _emit_key_reuse(
        self,
        certs: list[tuple[Path, x509.Certificate]],
        emit: Emitter,
    ) -> None:
        groups: dict[bytes, list[tuple[Path, x509.Certificate]]] = {}
        for path, cert in certs:
            spki = _spki_bytes(cert)
            if spki is None:
                continue
            groups.setdefault(spki, []).append((path, cert))

        for spki, members in groups.items():
            if len(members) < 2:
                continue
            paths = [str(p) for p, _ in members]
            subjects = sorted({c.subject.rfc4514_string() for _, c in members})
            if len(subjects) < 2:
                continue  # same logical cert duplicated, not true reuse
            alg = _key_algorithm(members[0][1].public_key())
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=f"public-key reuse across {len(members)} certs ({alg})",
                evidence={
                    "algorithm": alg,
                    "count": len(members),
                    "paths": sorted(paths),
                    "subjects": subjects,
                    "spki_sha_prefix": spki[:16].hex(),
                },
                remediation={
                    "snippet": "# Issue a fresh, unique key pair per certificate",
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

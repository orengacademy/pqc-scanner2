from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_chain import FsCertChain, _sig_hash_alg


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _build(
    *,
    subject: str,
    issuer_name: x509.Name,
    issuer_key,
    subject_key,
    ca: bool,
    hash_alg=None,
    add_ski: bool = True,
    add_aki: bool = True,
) -> x509.Certificate:
    hash_alg = hash_alg or hashes.SHA256()
    subj = _name(subject)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if add_ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
    if add_aki:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    return builder.sign(issuer_key, hash_alg)


def _write(path: Path, cert: x509.Certificate, encoding: str = "pem") -> None:
    enc = Encoding.PEM if encoding == "pem" else Encoding.DER
    path.write_bytes(cert.public_bytes(enc))


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsCertChain(roots=roots)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    return found


def _make_chain(tmp_path: Path, *, weak_intermediate: bool = True) -> dict:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    inter_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048 if weak_intermediate else 4096,
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    root = _build(
        subject="Root CA", issuer_name=_name("Root CA"),
        issuer_key=root_key, subject_key=root_key, ca=True,
    )
    inter = _build(
        subject="Intermediate CA", issuer_name=_name("Root CA"),
        issuer_key=root_key, subject_key=inter_key, ca=True,
    )
    leaf = _build(
        subject="leaf.example.com", issuer_name=_name("Intermediate CA"),
        issuer_key=inter_key, subject_key=leaf_key, ca=False,
    )
    _write(tmp_path / "root.pem", root)
    _write(tmp_path / "inter.pem", inter)
    _write(tmp_path / "leaf.pem", leaf)
    return {"root_key": root_key, "inter_key": inter_key, "leaf_key": leaf_key}


@pytest.mark.asyncio
async def test_fewer_than_two_certs_emits_nothing(tmp_path: Path):
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    leaf = _build(
        subject="only", issuer_name=_name("only"),
        issuer_key=leaf_key, subject_key=leaf_key, ca=False,
    )
    _write(tmp_path / "only.pem", leaf)
    assert await _run([tmp_path]) == []


@pytest.mark.asyncio
async def test_weakest_link_is_rsa2048_intermediate(tmp_path: Path):
    _make_chain(tmp_path, weak_intermediate=True)
    found = await _run([tmp_path])
    chain_findings = [f for f in found if f.evidence.get("leaf", "").endswith("leaf.pem")]
    assert len(chain_findings) == 1
    f = chain_findings[0]
    # RSA-2048 -> SANGAT_TINGGI (below 3072) is the weakest link.
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.algorithm == "RSA-2048"
    assert f.evidence["chain_length"] == 3
    assert f.evidence["weakest_link"].endswith("inter.pem")
    assert f.probe_id == "fs.cert.chain"


def test_sig_hash_alg_normalises_sha_names():
    # _sig_hash_alg() must turn cryptography's "sha256" into classify()-ready
    # "SHA-256" so a weak signature hash can drive the weakest-link logic.
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    cert = _build(
        subject="Root", issuer_name=_name("Root"),
        issuer_key=root_key, subject_key=root_key, ca=True,
    )
    assert _sig_hash_alg(cert) == "SHA-256"


@pytest.mark.asyncio
async def test_strong_rsa_chain_reports_rsa_key_as_weakest(tmp_path: Path):
    # All keys RSA-4096 (TINGGI), signed with SHA-512 (RENDAH). The classical
    # RSA key (TINGGI) outranks the strong hash, so the RSA key is the weakest
    # link reported — confirming both keys AND signatures feed the comparison.
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    root = _build(
        subject="Root", issuer_name=_name("Root"),
        issuer_key=root_key, subject_key=root_key, ca=True,
        hash_alg=hashes.SHA512(),
    )
    leaf = _build(
        subject="leaf", issuer_name=_name("Root"),
        issuer_key=root_key, subject_key=leaf_key, ca=False,
        hash_alg=hashes.SHA512(),
    )
    _write(tmp_path / "root.pem", root)
    _write(tmp_path / "leaf.pem", leaf)
    found = await _run([tmp_path])
    leaf_f = [f for f in found if f.evidence.get("leaf", "").endswith("leaf.pem")]
    assert len(leaf_f) == 1
    assert leaf_f[0].classification is Classification.TINGGI
    assert leaf_f[0].algorithm == "RSA-4096"
    assert leaf_f[0].evidence["chain_length"] == 2


@pytest.mark.asyncio
async def test_dn_fallback_when_no_ski_aki(tmp_path: Path):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    root = _build(
        subject="Root DN", issuer_name=_name("Root DN"),
        issuer_key=root_key, subject_key=root_key, ca=True,
        add_ski=False, add_aki=False,
    )
    leaf = _build(
        subject="leaf-dn", issuer_name=_name("Root DN"),
        issuer_key=root_key, subject_key=leaf_key, ca=False,
        add_ski=False, add_aki=False,
    )
    _write(tmp_path / "root.pem", root)
    _write(tmp_path / "leaf.pem", leaf)
    found = await _run([tmp_path])
    leaf_f = [f for f in found if f.evidence.get("leaf", "").endswith("leaf.pem")]
    assert len(leaf_f) == 1
    # Walked up to root via DN match; root RSA-2048 is weakest.
    assert leaf_f[0].evidence["chain_length"] == 2
    assert leaf_f[0].algorithm == "RSA-2048"
    assert leaf_f[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_key_reuse_detected(tmp_path: Path):
    shared = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    c1 = _build(
        subject="host-a", issuer_name=_name("host-a"),
        issuer_key=shared, subject_key=shared, ca=False,
    )
    c2 = _build(
        subject="host-b", issuer_name=_name("host-b"),
        issuer_key=shared, subject_key=shared, ca=False,
    )
    _write(tmp_path / "a.pem", c1)
    _write(tmp_path / "b.pem", c2)
    found = await _run([tmp_path])
    reuse = [f for f in found if "reuse" in f.title]
    assert len(reuse) == 1
    f = reuse[0]
    assert f.classification is Classification.SEDERHANA
    assert f.severity is Severity.MED
    assert f.evidence["count"] == 2
    assert sorted(f.evidence["subjects"]) == ["CN=host-a", "CN=host-b"]


@pytest.mark.asyncio
async def test_no_key_reuse_for_distinct_keys(tmp_path: Path):
    _make_chain(tmp_path)
    found = await _run([tmp_path])
    assert [f for f in found if "reuse" in f.title] == []


@pytest.mark.asyncio
async def test_der_encoded_cert_parsed(tmp_path: Path):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root = _build(
        subject="Root", issuer_name=_name("Root"),
        issuer_key=root_key, subject_key=root_key, ca=True,
    )
    leaf = _build(
        subject="leaf", issuer_name=_name("Root"),
        issuer_key=root_key, subject_key=leaf_key, ca=False,
    )
    _write(tmp_path / "root.cer", root, encoding="der")
    _write(tmp_path / "leaf.cer", leaf, encoding="der")
    found = await _run([tmp_path])
    leaf_f = [f for f in found if f.evidence.get("leaf", "").endswith("leaf.cer")]
    assert len(leaf_f) == 1
    # RSA-2048 root weaker than ECDSA leaf.
    assert leaf_f[0].algorithm == "RSA-2048"


@pytest.mark.asyncio
async def test_malformed_file_skipped(tmp_path: Path):
    (tmp_path / "junk.pem").write_bytes(b"not a certificate")
    _make_chain(tmp_path)
    found = await _run([tmp_path])
    # The junk file is silently skipped; chain still assembled.
    assert any(f.evidence.get("leaf", "").endswith("leaf.pem") for f in found)


@pytest.mark.asyncio
async def test_non_cert_extension_ignored(tmp_path: Path):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    root = _build(
        subject="Root", issuer_name=_name("Root"),
        issuer_key=root_key, subject_key=root_key, ca=True,
    )
    leaf = _build(
        subject="leaf", issuer_name=_name("Root"),
        issuer_key=root_key, subject_key=leaf_key, ca=False,
    )
    _write(tmp_path / "root.txt", root)  # wrong extension -> not loaded
    _write(tmp_path / "leaf.pem", leaf)
    # Only one cert with a scanned extension -> fewer than 2 -> nothing.
    assert await _run([tmp_path]) == []


@pytest.mark.asyncio
async def test_applies_true_when_root_exists(tmp_path: Path):
    probe = FsCertChain(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await probe.applies(ctx) is True


@pytest.mark.asyncio
async def test_applies_false_when_no_root(tmp_path: Path):
    probe = FsCertChain(roots=[tmp_path / "nope"])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await probe.applies(ctx) is False


def test_default_roots():
    probe = FsCertChain()
    assert Path("/etc") in probe.roots
    assert Path("/usr/local/etc") in probe.roots

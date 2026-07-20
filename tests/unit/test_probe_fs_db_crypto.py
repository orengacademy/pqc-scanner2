"""Tests for fs.db.crypto (crypto material stored in database columns)."""
from __future__ import annotations

import datetime
import sqlite3
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_db_crypto import FsDbCrypto

# --- in-test crypto fixtures (stdlib sqlite3 + cryptography) ----------------


def _rsa_2048() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _self_signed_cert_pem(key: rsa.RSAPrivateKey) -> str:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "db-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _private_key_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _make_sqlite(path: Path, table: str, column: str, value: str) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute(f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY, "{column}" TEXT)')
        con.execute(f'INSERT INTO "{table}" ("{column}") VALUES (?)', (value,))
        con.commit()
    finally:
        con.close()


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsDbCrypto(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


# --- tests -----------------------------------------------------------------


async def test_cert_in_sqlite_column_is_found(tmp_path: Path):
    key = _rsa_2048()
    db = tmp_path / "app.db"
    _make_sqlite(db, "certs", "pem", _self_signed_cert_pem(key))

    found = await _run([tmp_path])
    certs = [f for f in found if f.evidence.get("key_type") == "certificate"]
    assert len(certs) == 1
    f = certs[0]
    assert f.algorithm == "RSA-2048"
    assert f.classification is Classification.SANGAT_TINGGI  # RSA-2048 < 3072
    assert f.evidence["table"] == "certs"
    assert f.evidence["column"] == "pem"
    assert f.probe_id == "fs.db.crypto"


async def test_private_key_is_crit_and_redacted(tmp_path: Path):
    key = _rsa_2048()
    pem = _private_key_pem(key)
    db = tmp_path / "secrets.db"
    _make_sqlite(db, "secrets", "priv", pem)

    found = await _run([tmp_path])
    privs = [f for f in found if f.evidence.get("key_type") == "RSA"]
    assert len(privs) == 1
    f = privs[0]
    assert f.severity is Severity.CRIT
    assert f.classification is Classification.SANGAT_TINGGI

    # REDACTION: no key material anywhere in the finding.
    assert set(f.evidence.keys()) == {"path", "table", "column", "key_type"}
    blob = repr(f.evidence) + f.title + f.algorithm
    assert "PRIVATE KEY" not in blob
    assert "-----BEGIN" not in blob
    # a chunk of the actual base64 body must not have leaked
    body = pem.splitlines()[1]
    assert body not in blob


async def test_sql_dump_text_file_cert(tmp_path: Path):
    key = _rsa_2048()
    cert_pem = _self_signed_cert_pem(key)
    dump = tmp_path / "backup.sql"
    dump.write_text(
        "INSERT INTO certs (id, pem) VALUES (1, '" + cert_pem + "');\n"
    )

    found = await _run([tmp_path])
    certs = [f for f in found if f.evidence.get("key_type") == "certificate"]
    assert len(certs) == 1
    assert certs[0].algorithm == "RSA-2048"
    assert certs[0].evidence["path"].endswith("backup.sql")


async def test_db_without_crypto_yields_nothing(tmp_path: Path):
    db = tmp_path / "plain.db"
    _make_sqlite(db, "users", "name", "just a normal string value")
    found = await _run([tmp_path])
    assert found == []


async def test_random_non_db_file_is_skipped(tmp_path: Path):
    junk = tmp_path / "random.bin"
    junk.write_bytes(b"\x00\x01\x02not a database at all\xff\xfe")
    text = tmp_path / "notes.txt"
    text.write_text("hello world, no crypto here")
    found = await _run([tmp_path])
    assert found == []  # no crash, no findings


async def test_applies_true_with_scan_paths():
    probe = FsDbCrypto()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set(),
                      scan_paths=[Path("/tmp")])
    assert await probe.applies(ctx) is True


async def test_applies_false_without_scan_paths():
    probe = FsDbCrypto()
    assert await probe.applies(_ctx()) is False

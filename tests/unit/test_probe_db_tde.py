"""Tests for Plan G batch 1 — DB-TDE probes (deferred per spec §13.1)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.db_mongo_encrypted_storage import DbMongoEncryptedStorage
from pqcscan.probes.db_mssql_tde import DbMssqlTde
from pqcscan.probes.db_mysql_keyring import DbMysqlKeyring
from pqcscan.probes.db_pg_pgcrypto import DbPgPgcrypto


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (DbPgPgcrypto,             "db.pg.pgcrypto"),
        (DbMysqlKeyring,           "db.mysql.keyring"),
        (DbMssqlTde,               "db.mssql.tde"),
        (DbMongoEncryptedStorage,  "db.mongo.encrypted_storage"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.STORAGE
    assert any("db-tde" in tag for tag in p.framework_tags)


@pytest.mark.asyncio
async def test_pgcrypto_detects_preload_and_md5(tmp_path: Path):
    cfg = tmp_path / "postgresql.conf"
    cfg.write_text(
        "shared_preload_libraries = 'pgcrypto'\n"
        "password_encryption = md5\n"
    )
    found: list = []
    p = DbPgPgcrypto(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "pgcrypto" for f in found)
    assert any(f.algorithm == "MD5"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_mysql_keyring_detects_plugin_and_innodb(tmp_path: Path):
    cfg = tmp_path / "my.cnf"
    cfg.write_text(
        "[mysqld]\n"
        "early-plugin-load = keyring_file.so\n"
        "keyring_file_data = /var/lib/mysql-keyring/keyring\n"
        "innodb_encrypt_tables = ON\n"
        "innodb_redo_log_encrypt = OFF\n"
    )
    found: list = []
    p = DbMysqlKeyring(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    titles = " ".join(f.title for f in found)
    assert "keyring_file.so" in titles
    assert "keyring_file_data" in titles
    assert "innodb_encrypt_tables" in titles
    # innodb_redo_log_encrypt = OFF must NOT be reported.
    assert "innodb_redo_log_encrypt" not in titles


@pytest.mark.asyncio
async def test_mssql_tde_flags_tls10_and_force_off(tmp_path: Path):
    cfg = tmp_path / "mssql.conf"
    cfg.write_text(
        "[network]\n"
        "tlsprotocols = 1.0,1.2\n"
        "forceencryption = 0\n"
    )
    found: list = []
    p = DbMssqlTde(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "TLSv1.0"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)
    assert not any(f.algorithm == "TLSv1.2" for f in found)
    assert any("forceencryption=0" in f.algorithm
               and f.classification is Classification.TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_mongo_encrypted_storage_flags_cbc(tmp_path: Path):
    cfg = tmp_path / "mongod.conf"
    cfg.write_text(
        "security:\n"
        "  encryption:\n"
        "    encryptionKeyFile: /etc/mongo/keyfile\n"
        "    encryptionCipherMode: AES256-CBC\n"
    )
    found: list = []
    p = DbMongoEncryptedStorage(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "WiredTiger-keyfile" for f in found)
    cbc = [f for f in found if "CBC" in f.algorithm]
    assert cbc and cbc[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_mongo_encrypted_storage_gcm_is_info(tmp_path: Path):
    cfg = tmp_path / "mongod.conf"
    cfg.write_text(
        "security:\n"
        "  encryption:\n"
        "    encryptionCipherMode: AES256-GCM\n"
    )
    found: list = []
    p = DbMongoEncryptedStorage(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification is Classification.INFO for f in found)


def test_registry_includes_db_tde_probes():
    from pqcscan.probes._registry import default_registry
    reg = default_registry()
    ids = set(reg.ids())
    expected = {
        "db.pg.pgcrypto", "db.mysql.keyring",
        "db.mssql.tde", "db.mongo.encrypted_storage",
    }
    assert expected <= ids

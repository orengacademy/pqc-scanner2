"""fs.conf.ibmi_sysval — IBM i QSSLPCL / QSSLCSL export parsing."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_ibmi_sysval import FsConfIbmiSysval, _to_iana

_SPOOL = """\
 System value . . . . . :   QSSLPCL
 Description  . . . . . :   Secure sockets layer protocols
 Protocol . . . . . . . :   *TLSV1.2
                            *TLSV1
                            *SSLV3

 System value . . . . . :   QSSLCSL
 Cipher . . . . . . . . :   *ECDHE_ECDSA_AES_256_GCM_SHA384
                            *RSA_AES_128_CBC_SHA
                            *RSA_RC4_128_SHA
                            *AES_128_GCM_SHA256
"""


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(root: Path) -> list:
    found: list = []
    await FsConfIbmiSysval(roots=[root]).run(_ctx(), emit=found.append)
    return found


def test_to_iana():
    assert _to_iana("ECDHE_RSA_AES_128_GCM_SHA256") == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert _to_iana("RSA_3DES_EDE_CBC_SHA") == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert _to_iana("AES_128_GCM_SHA256") == "TLS_AES_128_GCM_SHA256"


@pytest.mark.asyncio
async def test_spool_export_is_graded(tmp_path: Path):
    (tmp_path / "QSSL.txt").write_text(_SPOOL)
    found = await _run(tmp_path)
    by_alg = {f.algorithm: f for f in found}
    assert by_alg["TLSV1"].classification is Classification.SANGAT_TINGGI
    assert by_alg["SSLV3"].severity is Severity.CRIT
    assert "TLSV1.2" not in by_alg                      # modern protocol → no weak row
    assert by_alg["TLS_RSA_WITH_RC4_128_SHA"].classification is Classification.SANGAT_TINGGI
    assert by_alg["TLS_RSA_WITH_AES_128_CBC_SHA"].classification is Classification.SANGAT_TINGGI
    assert by_alg["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"].classification is Classification.TINGGI
    assert by_alg["TLS_AES_128_GCM_SHA256"].classification is Classification.SEDERHANA
    inv = by_alg["N/A"]
    assert inv.classification is Classification.INFO and inv.evidence["suites"][0].startswith("*")


@pytest.mark.asyncio
async def test_opsys_default_is_flagged_medium(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("QSSLPCL *OPSYS\nQSSLCSLCTL *OPSYS\n")
    found = await _run(tmp_path)
    assert any(f.algorithm == "QSSLPCL=*OPSYS" and f.classification is Classification.SEDERHANA for f in found)


@pytest.mark.asyncio
async def test_unrelated_files_ignored_and_applies_gate(tmp_path: Path):
    (tmp_path / "readme.txt").write_text("nothing about ibm i here\n")
    assert await _run(tmp_path) == []
    assert await FsConfIbmiSysval().applies(_ctx()) is False          # no default roots
    assert await FsConfIbmiSysval(roots=[tmp_path]).applies(_ctx()) is True

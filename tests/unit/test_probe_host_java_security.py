"""Tests for host.java.security (JVM java.security disabledAlgorithms posture)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_java_security import HostJavaSecurity

# A hardened policy: disables TLS 1.0/1.1, RC4/3DES/MD5, and RSA/DH keySize
# floors at 2048 plus EC at 224.
_HARDENED = (
    "# JDK security policy\n"
    "security.provider.1=SUN\n"
    "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5, \\\n"
    "    3DES_EDE_CBC, anon, NULL, \\\n"
    "    RSA keySize < 2048, DH keySize < 2048, EC keySize < 224\n"
    "jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer\n"
    "jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024\n"
)

# A weak policy: no protocol constraints, no keySize floors.
_WEAK = (
    "# minimal policy\n"
    "jdk.tls.disabledAlgorithms=SSLv3\n"
)


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = HostJavaSecurity(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "java.security"
    p.write_text(text)
    return p


@pytest.mark.asyncio
async def test_inventory_finding_emitted(tmp_path: Path):
    cfg = _write(tmp_path, _HARDENED)
    found = await _run([cfg])
    inv = [f for f in found if f.algorithm == "jvm-crypto-policy"]
    assert len(inv) == 1
    assert inv[0].classification is Classification.INFO
    assert inv[0].severity is Severity.INFO
    ev = inv[0].evidence
    assert "TLSv1" in ev["disabled_tls"]
    assert "RC4" in ev["disabled_tls"]
    # certpath + jar captured separately.
    assert any("SHA1" in t for t in ev["disabled_certpath"])
    assert ev["disabled_jar"]


@pytest.mark.asyncio
async def test_hardened_policy_has_no_gap_findings(tmp_path: Path):
    cfg = _write(tmp_path, _HARDENED)
    found = await _run([cfg])
    titles = " ".join(f.title for f in found)
    assert "not disabled" not in titles
    assert "keySize floor" not in titles
    assert "No RSA keySize floor" not in titles
    # Only the inventory + the quantum reminder remain.
    algs = {f.algorithm for f in found}
    assert algs == {"jvm-crypto-policy", "classical-kex-quantum"}


@pytest.mark.asyncio
async def test_weak_policy_flags_tls_protocol_gaps(tmp_path: Path):
    cfg = _write(tmp_path, _WEAK)
    found = await _run([cfg])
    tls10 = [f for f in found if f.algorithm == "TLSv1.0"]
    tls11 = [f for f in found if f.algorithm == "TLSv1.1"]
    assert len(tls10) == 1
    assert len(tls11) == 1
    assert tls10[0].classification is Classification.TINGGI
    assert tls10[0].severity is Severity.HIGH
    assert "not disabled" in tls10[0].title


@pytest.mark.asyncio
async def test_weak_policy_flags_weak_ciphers_and_keysize(tmp_path: Path):
    cfg = _write(tmp_path, _WEAK)
    found = await _run([cfg])
    algs = {f.algorithm for f in found}
    # Weak primitives not disabled.
    assert {"RC4", "3DES", "MD5"}.issubset(algs)
    rc4 = next(f for f in found if f.algorithm == "RC4")
    assert rc4.classification is Classification.SANGAT_TINGGI
    assert rc4.severity is Severity.CRIT
    # Missing keySize floors -> SEDERHANA notes with medium confidence.
    for fam in ("RSA", "DH", "EC"):
        gap = next(f for f in found if f.algorithm == fam)
        assert gap.classification is Classification.SEDERHANA
        assert gap.severity is Severity.MED
        assert gap.evidence["confidence"] == "medium"


@pytest.mark.asyncio
async def test_keysize_floor_too_low_flagged(tmp_path: Path):
    cfg = _write(
        tmp_path,
        "jdk.tls.disabledAlgorithms=TLSv1, TLSv1.1, RC4, 3DES, MD5, \\\n"
        "    RSA keySize < 1024, DH keySize < 2048, EC keySize < 224\n",
    )
    found = await _run([cfg])
    rsa = next(f for f in found if f.algorithm == "RSA")
    assert rsa.classification is Classification.TINGGI
    assert rsa.severity is Severity.HIGH
    assert "too low" in rsa.title
    # DH/EC floors are adequate -> no gap for them.
    assert not any(f.algorithm == "DH" for f in found)
    assert not any(f.algorithm == "EC" for f in found)


@pytest.mark.asyncio
async def test_line_continuation_captures_full_value(tmp_path: Path):
    cfg = _write(tmp_path, _HARDENED)
    found = await _run([cfg])
    inv = next(f for f in found if f.algorithm == "jvm-crypto-policy")
    tls = inv.evidence["disabled_tls"]
    # Tokens from the 1st, 2nd AND 3rd continued physical lines all present.
    assert "TLSv1" in tls              # line 1
    assert "3DES_EDE_CBC" in tls       # line 2 (continuation)
    assert "RSA keySize < 2048" in tls  # line 3 (continuation)
    assert "EC keySize < 224" in tls


@pytest.mark.asyncio
async def test_quantum_reminder_emitted_once(tmp_path: Path):
    cfg = _write(tmp_path, _HARDENED)
    found = await _run([cfg])
    reminders = [f for f in found if f.algorithm == "classical-kex-quantum"]
    assert len(reminders) == 1
    assert reminders[0].classification is Classification.INFO


@pytest.mark.asyncio
async def test_applies_true_and_false(tmp_path: Path):
    cfg = _write(tmp_path, _WEAK)
    assert await HostJavaSecurity(roots=[cfg]).applies(_ctx()) is True
    assert await HostJavaSecurity(roots=[tmp_path / "absent"]).applies(_ctx()) is False


@pytest.mark.asyncio
async def test_directory_root_is_walked(tmp_path: Path):
    # Simulate $JAVA_HOME/conf/security/java.security under a /usr/lib/jvm-style dir.
    nested = tmp_path / "jvm" / "jdk-21" / "conf" / "security"
    nested.mkdir(parents=True)
    (nested / "java.security").write_text(_WEAK)
    found = await _run([tmp_path / "jvm"])
    assert any(f.algorithm == "jvm-crypto-policy" for f in found)

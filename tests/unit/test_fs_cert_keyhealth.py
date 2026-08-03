from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_x509 import FsCertX509


def _ctx() -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        scan_paths=[], server_target=None, ot_targets=[], sniff=None,
    )


# cryptography refuses to *generate* sub-1024-bit keys, which is exactly why
# a scanner must still flag ones found in the wild — this one is a throwaway
# test fixture, never used for real crypto.
_WEAK_512_BIT_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA67EFZoOgyGQflQKL
fN5OvJdyMYJoCTzdY7lkCHnol8IrTDvbeVWTgeq8Eh2t3ahJW9NbQcXSMS7XLGmV
xT/qUQIDAQABAkEAlhh93/MjiXp5wmOEgVjxu5iW2IC70GY6dy+xTNSWE04Tb7W/
8l2mrocoM5S0F0KSvSPtW3sE2mlAjqzmipiTgQIhAPk6BPl3vjTu+57PvpEjRC88
8x0apOW8OdBVnr7sV1/lAiEA8hjU5DazPCZnWC0Lf5Sdc/hdKRr09F9514khK8qJ
Qf0CIQCFJR3rOLGBDfuXCF1CpJiUs/cdoVJe+YPZbSR100WKkQIgAcQImXmEqSWm
j1AUy2NsGpJvK4OU0ct4egf4A/fANIkCIEQQVz6VWpwKPy3UVBEtXuSdSwRTWXv4
cLziS05eljx/
-----END PRIVATE KEY-----
"""


def _write_selfsigned(tmp_path, key_size: int) -> None:
    if key_size < 1024:
        key = serialization.load_pem_private_key(_WEAK_512_BIT_KEY_PEM, password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "keyhealth-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1))
        .not_valid_after(datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )


async def test_sub_1024_bit_rsa_cert_gets_keyhealth_finding(tmp_path):
    _write_selfsigned(tmp_path, key_size=512)
    findings = []
    await FsCertX509(roots=[tmp_path]).run(_ctx(), findings.append)
    health = [f for f in findings if "keyhealth" in f.evidence]
    assert health, "expected a keyhealth finding for a 512-bit RSA modulus"
    assert health[0].classification.value == "sangat-tinggi"
    assert "512 bits" in health[0].evidence["keyhealth"]


async def test_healthy_rsa_cert_has_no_keyhealth_finding(tmp_path):
    _write_selfsigned(tmp_path, key_size=2048)
    findings = []
    await FsCertX509(roots=[tmp_path]).run(_ctx(), findings.append)
    assert not [f for f in findings if "keyhealth" in f.evidence]
    assert findings  # the ordinary inventory finding is still emitted

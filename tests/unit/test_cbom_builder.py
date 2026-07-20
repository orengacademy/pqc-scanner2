from pqcscan.cbom.builder import build_cbom
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.repo import Repo


def test_build_cbom_minimal_shape(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.https",
        algorithm="RSA-2048",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="server cert uses RSA-2048",
        evidence={"endpoint": "127.0.0.1:443"},
    ))
    repo.finish_scan(scan_id, status="done")

    cbom = build_cbom(repo, scan_id)

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.7"
    assert cbom["$schema"] == "http://cyclonedx.org/schema/bom-1.7.schema.json"
    assert "metadata" in cbom and "tools" in cbom["metadata"]
    assert any(c.get("type") == "cryptographic-asset" for c in cbom["components"])
    names = [c["name"] for c in cbom["components"]]
    assert any("RSA-2048" in n for n in names)


def test_build_cbom_skips_na_algorithm(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    repo.record_finding(scan_id, Finding(
        probe_id="aux.clock.cert_validity",
        algorithm="N/A",
        classification=Classification.INFO,
        severity=Severity.INFO,
        title="clock at scan",
    ))
    repo.finish_scan(scan_id, status="done")
    cbom = build_cbom(repo, scan_id)
    assert cbom["components"] == []


def test_build_cbom_includes_pqc_ready(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.https",
        algorithm="ML-KEM-768",
        classification=Classification.PQC_READY,
        severity=Severity.INFO,
        title="hybrid PQC kex",
    ))
    repo.finish_scan(scan_id, status="done")
    cbom = build_cbom(repo, scan_id)
    levels = [
        c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
        for c in cbom["components"]
    ]
    assert max(levels) >= 3


# CycloneDX 1.7 `primitive` enum
# (cryptography-defs is separate; primitive lives in bom-1.7.schema.json).
_PRIMITIVE_ENUM = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
    "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap",
    "other", "unknown",
}


def _one_finding_cbom(tmp_db_path, *, algorithm, classification, evidence=None):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(scan_id, Finding(
        probe_id="fs.cert.x509",
        algorithm=algorithm,
        classification=classification,
        severity=Severity.HIGH,
        title=f"{algorithm} in cert",
        evidence=evidence or {},
    ))
    repo.finish_scan(scan_id, status="done")
    cbom = build_cbom(repo, scan_id)
    return cbom["components"][0]["cryptoProperties"]["algorithmProperties"]


def test_cbom_curve_p256_maps_to_1_7_enum(tmp_db_path):
    props = _one_finding_cbom(
        tmp_db_path, algorithm="ECDSA-P256", classification=Classification.TINGGI
    )
    assert props["ellipticCurve"] == "nist/P-256"
    assert props["algorithmFamily"] == "ECDSA"
    assert props["primitive"] == "signature"


def test_cbom_curve_mapping_variants(tmp_db_path):
    cases = {
        "ECDSA-P384": "nist/P-384",
        "secp256k1": "secg/secp256k1",
        "prime256v1": "x962/prime256v1",
        "Ed25519": "other/Ed25519",
        "X25519": "other/Curve25519",
    }
    for algorithm, expected in cases.items():
        props = _one_finding_cbom(
            tmp_db_path, algorithm=algorithm, classification=Classification.TINGGI
        )
        assert props["ellipticCurve"] == expected, algorithm


def test_cbom_curve_from_evidence_crv(tmp_db_path):
    props = _one_finding_cbom(
        tmp_db_path,
        algorithm="EC",
        classification=Classification.TINGGI,
        evidence={"crv": "P-521"},
    )
    assert props["ellipticCurve"] == "nist/P-521"


def test_cbom_no_curve_field_for_non_ec(tmp_db_path):
    props = _one_finding_cbom(
        tmp_db_path, algorithm="RSA-2048", classification=Classification.TINGGI
    )
    assert "ellipticCurve" not in props
    # RSA has no unambiguous 1.7 algorithmFamily member -> omitted, not faked.
    assert "algorithmFamily" not in props


def test_cbom_primitive_values_are_valid_1_7_enum(tmp_db_path):
    for algorithm in ["RSA-2048", "AES-256", "ChaCha20", "ML-KEM-768",
                      "X25519", "ECDH-P256", "SHA-256", "Ed25519"]:
        props = _one_finding_cbom(
            tmp_db_path, algorithm=algorithm, classification=Classification.TINGGI
        )
        assert props["primitive"] in _PRIMITIVE_ENUM, algorithm
    # spot-check the corrected mappings (were "cipher"/"key-agreement" in 1.6)
    assert _one_finding_cbom(
        tmp_db_path, algorithm="AES-256", classification=Classification.TINGGI
    )["primitive"] == "block-cipher"
    assert _one_finding_cbom(
        tmp_db_path, algorithm="ML-KEM-768", classification=Classification.PQC_READY
    )["primitive"] == "kem"

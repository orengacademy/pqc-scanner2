"""Bake-off normalisers, run against saved raw output of each tool (benchmark/bakeoff/samples/).

The samples are real: one scan per tool, trimmed only by choosing small targets. No scan, docker or network here.
"""
import json
import sys
from pathlib import Path

import pytest

BAKEOFF = Path(__file__).resolve().parents[2] / "benchmark" / "bakeoff"
sys.path.insert(0, str(BAKEOFF))
import normalise as nm  # noqa: E402

pytestmark = pytest.mark.benchmark

SCHEMA = {"target", "surface", "algorithm", "strength_bits", "pq_safe", "detail", "source_tool"}


def sample(name: str):
    return json.loads((BAKEOFF / "samples" / name).read_text(encoding="utf-8"))


def by_canon(rows):
    return {nm.canonical(r["algorithm"]): r for r in rows}


def test_rows_follow_the_schema_for_every_tool():
    rows = (nm.normalise_pqcscan(sample("pqcscan-tls13-hybrid-ed25519.json"), "ep")
            + nm.normalise_anvil(sample("anvil-tls13-hybrid-ed25519.json"), "ep")
            + nm.normalise_quantaseek(sample("quantaseek-noverify-tls13-hybrid-mldsa65.json"), "ep")
            + nm.normalise_cryptoscan(sample("cryptoscan-code.json"))
            + nm.normalise_cryptoscan(sample("cryptoscan-certs.json"), "cert"))
    assert rows
    for r in rows:
        assert set(r) == SCHEMA
        assert r["surface"] in nm.SURFACES
        assert r["pq_safe"] in (True, False, None)
        assert r["strength_bits"] is None or isinstance(r["strength_bits"], int)


def test_pqcscan_drops_markers_and_absences_and_maps_classification():
    raw = sample("pqcscan-tls13-hybrid-ed25519.json")
    rows = by_canon(nm.normalise_pqcscan(raw, "ep"))
    assert rows["x25519mlkem768"]["pq_safe"] is True           # classification pqc-ready
    assert rows["ed25519"]["pq_safe"] is False                 # classical signature key
    assert rows["tls1.3"]["pq_safe"] is None                   # classification info
    assert all(r["target"] == "ep" and r["surface"] == "tls" for r in rows.values())
    absent = [{"probe_id": "net.tls.versions", "algorithm": "TLS 1.3", "classification": "sederhana",
               "severity": "MED", "title": "h:1 does not support TLS 1.3 - no PQC-capable transport", "evidence": {}},
              {"probe_id": "net.tls.pqc_handshake", "algorithm": "N/A", "classification": "info", "severity": "INFO",
               "title": "no negotiated group", "evidence": {}}]
    assert nm.normalise_pqcscan(absent, "ep") == []


def test_pqcscan_file_findings_take_target_from_evidence_path():
    raw = [{"probe_id": "code.ts.java", "algorithm": "MD5", "classification": "sangat-tinggi", "severity": "CRIT",
            "title": "MessageDigest MD5", "evidence": {"path": "java-md5-real/A.java", "line": 5}}]
    (row,) = nm.normalise_pqcscan(raw)
    assert (row["target"], row["surface"], row["pq_safe"]) == ("java-md5-real/A.java", "code", False)


def test_anvil_reports_groups_with_the_right_pq_flag():
    rows = by_canon(nm.normalise_anvil(sample("anvil-tls13-hybrid-ed25519.json"), "ep"))
    assert rows["x25519mlkem768"]["pq_safe"] is True
    assert rows["x25519"]["pq_safe"] is False
    assert rows["ffdhe2048"]["pq_safe"] is False


def test_anvil_is_silent_on_a_legacy_server():
    assert nm.normalise_anvil(sample("anvil-tls10-only.json"), "ep") == []   # no TLS 1.3 key share, no rows


def test_quantaseek_failed_handshake_yields_nothing():
    assert nm.normalise_quantaseek(sample("quantaseek-stock-failed.json"), "ep") == []


def test_quantaseek_reads_serverhello_group_certificate_and_resolves_oids():
    rows = by_canon(nm.normalise_quantaseek(sample("quantaseek-noverify-tls13-hybrid-mldsa65.json"), "ep"))
    assert rows["tls1.3"]["algorithm"] == "TLS 1.3"
    assert rows["x25519mlkem768"]["pq_safe"] is True
    assert rows["ml-dsa-65"]["pq_safe"] is True               # reported as OID(2.16.840.1.101.3.4.3.18)
    assert rows["tls13-aes256-gcm-sha384"]["algorithm"] == "TLS13_AES_256_GCM_SHA384"


def test_quantaseek_does_not_report_a_suite_it_cannot_name():
    rows = nm.normalise_quantaseek(sample("quantaseek-noverify-tls12-ecdhe.json"), "ep")
    assert not any(r["algorithm"].startswith("Unknown") for r in rows)
    assert "rsa" in by_canon(rows)


def test_cryptoscan_code_hit_is_relative_to_the_scanned_tree_and_rated_vulnerable():
    (row,) = nm.normalise_cryptoscan(sample("cryptoscan-code.json"))
    assert nm.canonical(row["algorithm"]) == "md5"
    assert (row["surface"], row["pq_safe"], row["target"]) == ("code", False, "java-md5-real/A.java")


def test_cryptoscan_on_certificates_names_the_artefact_not_the_key():
    rows = nm.normalise_cryptoscan(sample("cryptoscan-certs.json"), "cert")
    assert {r["surface"] for r in rows} == {"cert"}
    assert {nm.canonical(r["algorithm"]) for r in rows} == {"x509certificate"}   # no RSA / ECDSA: it reads no key
    assert {r["pq_safe"] for r in rows} == {None}


@pytest.mark.parametrize(("a", "b"), [
    ("X25519MLKEM768", "x25519_kyber768"), ("X25519MLKEM768", "X25519ML-KEM-768"),
    ("X25519MLKEM768", "X25519Kyber768Draft00"), ("SecP256r1MLKEM768", "secp256r1mlkem768"),
    ("RSA-2048", "RSA"), ("ECDSA-secp256r1", "ECC"), ("MLDSA65PublicKey", "ML-DSA-65"),
    ("TLS_AES_256_GCM_SHA384", "TLS13_AES_256_GCM_SHA384"), ("TLS 1.2", "TLSv1.2"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    ("AES256-GCM-SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384"), ("SHA-1", "SHA1"), ("3DES", "TRIPLEDES"),
])
def test_canonical_folds_naming_differences(a, b):
    assert nm.canonical(a) == nm.canonical(b)


@pytest.mark.parametrize(("a", "b"), [
    ("TLS_AES_256_GCM_SHA384", "AES256-GCM-SHA384"),        # TLS 1.3 suite vs the TLS 1.2 RSA-kex suite
    ("ECDSA-secp256r1", "SECP256R1"),                        # an EC key vs a key-exchange group
    ("ECDSA-SHA256", "ECDSA-secp256r1"), ("RSA-SHA256", "RSA-2048"),   # signature scheme vs key
    ("x25519", "X25519MLKEM768"), ("DES", "3DES"), ("MD5", "SHA-1"),
])
def test_canonical_keeps_different_things_apart(a, b):
    assert nm.canonical(a) != nm.canonical(b)


@pytest.mark.parametrize(("name", "bits"), [("RSA-2048", 2048), ("secp384r1", 384), ("AES-256-GCM", 256),
                                            ("SHA-256", 256), ("Ed25519", None), ("RSA-SHA256", None)])
def test_strength_bits(name, bits):
    assert nm.strength_bits(name) == bits


def test_diff_sets_splits_on_target_surface_and_canonical_algorithm():
    ours = nm.normalise_pqcscan(sample("pqcscan-tls13-hybrid-ed25519.json"), "ep")
    theirs = nm.normalise_anvil(sample("anvil-tls13-hybrid-ed25519.json"), "ep")
    d = nm.diff_sets(ours, theirs)
    assert ("ep", "tls", "x25519mlkem768") in d["both"]
    assert ("ep", "tls", "ed25519") in d["pqcscan_only"]       # anvil never looks at the certificate
    assert ("ep", "tls", "ffdhe2048") in d["tool_only"]        # accepted groups pqcscan does not enumerate
    assert not set(d["both"]) & set(d["tool_only"])

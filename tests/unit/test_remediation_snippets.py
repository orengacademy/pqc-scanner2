from __future__ import annotations

from pqcscan.core.remediation import enrich
from pqcscan.core.remediation_snippets import snippet_for
from pqcscan.core.types import Classification, Finding, Severity


def _finding(
    alg: str,
    probe_id: str = "net.tls.kex",
    classif: Classification = Classification.SANGAT_TINGGI,
    remediation: dict | None = None,
) -> Finding:
    return Finding(
        probe_id=probe_id,
        algorithm=alg,
        classification=classif,
        severity=Severity.HIGH,
        title="t",
        remediation=remediation or {},
    )


# --- snippet_for -----------------------------------------------------------

def test_md5_python_before_md5_after_sha256():
    s = snippet_for("MD5", "python")
    assert s is not None
    assert s["language"] == "python"
    assert "md5" in s["before"].lower()
    assert "sha256" in s["after"].lower()


def test_sha1_maps_to_weak_hash_family():
    s = snippet_for("SHA-1", "go")
    assert s is not None
    assert "sha256" in s["after"].lower()


def test_rsa_java_mentions_pqc_or_bouncycastle():
    s = snippet_for("RSA-2048", "java")
    assert s is not None
    blob = (s["after"] + s["note"]).upper()
    assert "ML-DSA" in blob or "ML-KEM" in blob or "BOUNCYCASTLE" in blob or "BCPQC" in blob


def test_rsa_generic_not_none():
    s = snippet_for("RSA-2048", None)
    assert s is not None
    assert s["language"] == "generic"
    assert "ML-DSA" in (s["after"] + s["note"]).upper()


def test_ecdsa_maps_to_signature_family():
    s = snippet_for("ECDSA-SHA256", "python")
    assert s is not None
    assert "ML-DSA" in s["note"].upper()


def test_des_python_moves_to_aes_gcm():
    s = snippet_for("3DES-CBC", "python")
    assert s is not None
    assert "AESGCM" in s["after"] or "AES-256" in s["note"]


def test_rc4_generic():
    s = snippet_for("RC4", None)
    assert s is not None
    assert "AES" in s["after"].upper()


def test_dh_generic_is_ml_kem():
    s = snippet_for("DH-2048", None)
    assert s is not None
    assert "ML-KEM" in (s["after"] + s["note"]).upper()


def test_weak_tls_generic():
    s = snippet_for("TLSv1.0", None)
    assert s is not None
    assert "TLS" in s["after"].upper()


def test_language_without_specific_snippet_falls_back_to_generic():
    # weak-tls has only a generic entry; a language request still resolves.
    s = snippet_for("TLSv1.1", "python")
    assert s is not None
    assert s["language"] == "generic"


def test_unknown_algorithm_returns_none():
    assert snippet_for("FOOBAR-9000", "python") is None
    assert snippet_for("N/A", None) is None
    assert snippet_for("", "python") is None


def test_snippet_shape_has_all_keys():
    s = snippet_for("MD5", "javascript")
    assert s is not None
    assert set(s) == {"language", "before", "after", "note"}
    assert all(isinstance(v, str) and v for v in s.values())


# --- enrich integration ----------------------------------------------------

def test_enrich_populates_snippet_for_python_md5_code_finding():
    f = _finding(
        "MD5",
        probe_id="code.ts.python",
        classif=Classification.TINGGI,
    )
    enrich(f)
    snip = f.remediation.get("snippet")
    assert isinstance(snip, dict)
    assert snip["language"] == "python"
    assert "md5" in snip["before"].lower()
    assert "sha256" in snip["after"].lower()


def test_enrich_snippet_is_generic_for_cert_finding():
    f = _finding(
        "RSA-2048",
        probe_id="fs.cert.x509",
        classif=Classification.SANGAT_TINGGI,
    )
    enrich(f)
    snip = f.remediation.get("snippet")
    assert isinstance(snip, dict)
    assert snip["language"] == "generic"


def test_enrich_infers_java_from_probe_id():
    f = _finding("RSA-2048", probe_id="code.ts.java", classif=Classification.TINGGI)
    enrich(f)
    assert f.remediation["snippet"]["language"] == "java"


def test_enrich_does_not_overwrite_probe_snippet():
    f = _finding(
        "MD5",
        probe_id="code.ts.python",
        classif=Classification.TINGGI,
        remediation={"snippet": "do X"},
    )
    enrich(f)
    assert f.remediation["snippet"] == "do X"


def test_enrich_attaches_snippet_even_when_probe_set_replacement():
    f = _finding(
        "MD5",
        probe_id="code.ts.python",
        classif=Classification.TINGGI,
        remediation={"replacement": "custom"},
    )
    enrich(f)
    assert f.remediation["replacement"] == "custom"
    assert isinstance(f.remediation.get("snippet"), dict)


def test_enrich_no_snippet_for_unknown_algorithm():
    f = _finding("AES-256-GCM", probe_id="code.ts.python", classif=Classification.RENDAH)
    enrich(f)
    assert "snippet" not in f.remediation

"""Tests for fs.zeek.logs — ingest crypto observations from Zeek / Suricata IDS logs.

Fixtures are written as real Zeek TSV logs (a genuine ``#separator``/``#fields``/
``#types`` header block followed by tab-separated rows) or JSON-lines, dropped into a
tmp roots dir the probe is pointed at.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_zeek_logs import FsZeekLogs

# --- fixture builders ----------------------------------------------------

_SSL_FIELDS = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "version", "cipher", "curve", "server_name"]
_SSL_TYPES = ["time", "addr", "addr", "port", "string", "string", "string", "string"]
_X509_FIELDS = [
    "ts", "certificate.sig_alg", "certificate.key_alg", "certificate.key_type",
    "certificate.key_length", "certificate.curve", "san.dns",
]
_X509_TYPES = ["time", "string", "string", "string", "count", "string", "vector[string]"]


def _zeek_tsv(path_name: str, fields: list[str], types: list[str], rows: list[list[str]]) -> str:
    tab = "\t"
    lines = [
        r"#separator \x09",
        "#set_separator" + tab + ",",
        "#empty_field" + tab + "(empty)",
        "#unset_field" + tab + "-",
        "#path" + tab + path_name,
        "#open" + tab + "2026-07-20-00-00-00",
        "#fields" + tab + tab.join(fields),
        "#types" + tab + tab.join(types),
    ]
    for row in rows:
        lines.append(tab.join(row))
    lines.append("#close" + tab + "2026-07-20-01-00-00")
    return "\n".join(lines) + "\n"


def _write(roots: Path, name: str, content: str) -> Path:
    p = roots / name
    p.write_text(content)
    return p


def _make_context() -> ScanContext:
    return ScanContext(scan_id=1, mode="root", available_capabilities=set())


def _run(roots: Path) -> list:
    probe = FsZeekLogs(roots=[roots])
    findings: list = []
    asyncio.run(probe.run(_make_context(), findings.append))
    return findings


# --- tests ---------------------------------------------------------------


def test_ssl_legacy_version_and_rc4_are_critical(tmp_path: Path) -> None:
    rows = [
        ["1.0", "10.0.0.1", "10.0.0.2", "443", "TLSv10",
         "TLS_RSA_WITH_RC4_128_SHA", "secp256r1", "legacy.example"],
    ]
    _write(tmp_path, "ssl.log", _zeek_tsv("ssl", _SSL_FIELDS, _SSL_TYPES, rows))
    findings = _run(tmp_path)
    crit = [f for f in findings if f.classification is Classification.SANGAT_TINGGI]
    algs = {f.algorithm for f in crit}
    assert any("TLSv10" in a for a in algs)
    assert any("RC4" in a for a in algs)
    assert all(f.severity is Severity.CRIT for f in crit)
    assert all(f.confidence == "medium" for f in crit)
    assert all(f.evidence.get("confidence") == "medium" for f in crit)


def test_ssl_pqc_hybrid_group_is_pqc_ready_no_weak_finding(tmp_path: Path) -> None:
    rows = [
        ["1.0", "10.0.0.1", "10.0.0.2", "443", "TLSv13",
         "TLS_AES_256_GCM_SHA384", "x25519mlkem768", "modern.example"],
    ]
    _write(tmp_path, "ssl.log", _zeek_tsv("ssl", _SSL_FIELDS, _SSL_TYPES, rows))
    findings = [f for f in _run(tmp_path) if f.classification is not Classification.INFO]
    assert findings, "expected at least the PQC observation"
    assert all(f.classification is Classification.PQC_READY for f in findings)
    assert any("mlkem" in f.algorithm.lower() for f in findings)
    # No weak/critical findings for a fully modern handshake.
    assert not [f for f in findings if f.classification in
                (Classification.TINGGI, Classification.SANGAT_TINGGI)]


def test_ssl_classical_group_and_cipher_are_tinggi(tmp_path: Path) -> None:
    rows = [
        ["1.0", "10.0.0.1", "10.0.0.2", "443", "TLSv12",
         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "x25519", "classic.example"],
    ]
    _write(tmp_path, "ssl.log", _zeek_tsv("ssl", _SSL_FIELDS, _SSL_TYPES, rows))
    tinggi = [f for f in _run(tmp_path) if f.classification is Classification.TINGGI]
    algs = {f.algorithm for f in tinggi}
    assert any("ECDHE" in a for a in algs)  # classical KEX cipher
    assert "x25519" in algs                 # classical curve
    assert all(f.severity is Severity.HIGH for f in tinggi)


def test_x509_sha256_with_rsa_is_rsa_tinggi(tmp_path: Path) -> None:
    rows = [
        ["1.0", "sha256WithRSAEncryption", "rsaEncryption", "rsa", "4096", "-", "rsa.example"],
    ]
    _write(tmp_path, "x509.log", _zeek_tsv("x509", _X509_FIELDS, _X509_TYPES, rows))
    findings = _run(tmp_path)
    sig = [f for f in findings if f.algorithm == "RSA-SHA256"]
    assert sig, "expected sha256WithRSAEncryption -> RSA-SHA256"
    assert sig[0].classification is Classification.TINGGI
    assert sig[0].evidence["observed"] == "sha256WithRSAEncryption"
    assert sig[0].evidence["source"] == "zeek:x509.log"


def test_json_format_ssl_log_parses(tmp_path: Path) -> None:
    obj = {
        "ts": 1.0, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "id.resp_p": 443,
        "version": "TLSv12", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "curve": "secp256r1", "server_name": "json.example",
    }
    _write(tmp_path, "ssl.log", json.dumps(obj) + "\n")
    findings = [f for f in _run(tmp_path) if f.classification is Classification.TINGGI]
    assert findings, "JSON-format ssl.log should classify like TSV"
    assert any(f.evidence.get("server_name") == "json.example" for f in findings)
    assert all(f.evidence["source"] == "zeek:ssl.log" for f in findings)


def test_suricata_eve_json_tls_event(tmp_path: Path) -> None:
    lines = [
        json.dumps({"event_type": "flow"}),  # ignored non-tls event
        json.dumps({
            "event_type": "tls", "dest_ip": "10.0.0.9", "dest_port": 443,
            "tls": {"version": "TLS 1.0", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                    "sni": "suri.example"},
        }),
    ]
    _write(tmp_path, "eve.json", "\n".join(lines) + "\n")
    findings = _run(tmp_path)
    crit = [f for f in findings if f.classification is Classification.SANGAT_TINGGI]
    algs = {f.algorithm for f in crit}
    assert any("3DES" in a or "TLS 1.0" in a for a in algs)
    assert all(f.evidence["source"] == "suricata:eve.json" for f in crit)
    assert any(f.evidence.get("sni") == "suri.example" for f in crit)


def test_dedup_collapses_repeated_identical_rows(tmp_path: Path) -> None:
    row = ["1.0", "10.0.0.1", "10.0.0.2", "443", "TLSv12",
           "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "secp256r1", "busy.example"]
    rows = [row for _ in range(500)]
    _write(tmp_path, "ssl.log", _zeek_tsv("ssl", _SSL_FIELDS, _SSL_TYPES, rows))
    findings = _run(tmp_path)
    weak = [f for f in findings if f.classification is not Classification.INFO]
    # cipher + curve = two distinct algorithms, deduped across 500 identical rows.
    assert len(weak) == 2
    summary = [f for f in findings if f.classification is Classification.INFO]
    assert summary and summary[0].evidence["rows"] == 500


def test_fields_header_drives_column_mapping(tmp_path: Path) -> None:
    # Reorder columns: server_name first, version/cipher shuffled. Mapping is by name.
    fields = ["server_name", "cipher", "version", "id.resp_h", "id.resp_p", "id.orig_h", "curve", "ts"]
    types = ["string", "string", "string", "addr", "port", "addr", "string", "time"]
    rows = [["shuffled.example", "TLS_RSA_WITH_RC4_128_SHA", "SSLv3",
             "10.0.0.2", "443", "10.0.0.1", "secp256r1", "1.0"]]
    _write(tmp_path, "ssl.log", _zeek_tsv("ssl", fields, types, rows))
    findings = _run(tmp_path)
    crit = [f for f in findings if f.classification is Classification.SANGAT_TINGGI]
    assert any("RC4" in f.algorithm for f in crit)
    assert any("SSLv3" in f.algorithm for f in crit)
    assert any(f.evidence.get("server_name") == "shuffled.example" for f in findings)


def test_applies_false_when_no_log_dirs(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    probe = FsZeekLogs(roots=[missing])
    assert asyncio.run(probe.applies(_make_context())) is False


def test_applies_true_when_root_exists(tmp_path: Path) -> None:
    probe = FsZeekLogs(roots=[tmp_path])
    assert asyncio.run(probe.applies(_make_context())) is True

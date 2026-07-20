"""Multi-axis exposure register (core.exposure) + its report-context wiring."""
from __future__ import annotations

from pqcscan.core.exposure import ExposureRow, build_register, tier_counts
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.renderers._report_context import build_report_context
from pqcscan.store.repo import Repo


def _f(
    probe_id: str,
    algorithm: str,
    classification: Classification,
    severity: Severity,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        probe_id=probe_id,
        algorithm=algorithm,
        classification=classification,
        severity=severity,
        title="t",
        evidence=evidence or {},
    )


def test_crit_cert_is_critical_tier() -> None:
    f = _f("fs.cert.sniff", "RSA-2048", Classification.SANGAT_TINGGI, Severity.CRIT,
           {"path": "/etc/ssl/server.pem"})
    rows = build_register([f])
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, ExposureRow)
    # crit(3) * cert-longevity(3) * cert-feasibility(2) = 18 -> CRITICAL.
    assert (row.criticality, row.longevity, row.feasibility) == (3, 3, 2)
    assert row.exposure == 18
    assert row.tier == "CRITICAL"
    assert row.finding_ref == "fs.cert.sniff@/etc/ssl/server.pem"


def test_low_config_is_low_tier() -> None:
    f = _f("fs.conf.haproxy", "ECDSA-P256", Classification.TINGGI, Severity.LOW,
           {"path": "/etc/haproxy.cfg"})
    rows = build_register([f])
    # low(1) * config-longevity(2) * config-feasibility(1) = 2 -> LOW.
    assert rows[0].exposure == 2
    assert rows[0].tier == "LOW"


def test_register_sorted_desc_and_tier_thresholds() -> None:
    findings = [
        _f("fs.conf.haproxy", "RSA-2048", Classification.TINGGI, Severity.LOW),          # 2  LOW
        _f("fs.cert.sniff", "RSA-2048", Classification.SANGAT_TINGGI, Severity.CRIT),    # 18 CRITICAL
        _f("net.tls.kex", "ECDSA-P256", Classification.TINGGI, Severity.HIGH),           # high2*tls2*net1=4 MEDIUM
        _f("code.crypto", "RSA-2048", Classification.SANGAT_TINGGI, Severity.HIGH),      # 2*1*3=6 MEDIUM
    ]
    rows = build_register(findings)
    exposures = [r.exposure for r in rows]
    assert exposures == sorted(exposures, reverse=True)
    assert exposures[0] == 18 and rows[0].tier == "CRITICAL"
    counts = tier_counts(rows)
    assert counts["CRITICAL"] == 1
    assert counts["LOW"] == 1
    assert sum(counts.values()) == len(rows)


def test_hybrid_and_nonvulnerable_excluded() -> None:
    findings = [
        _f("net.tls.kex", "X25519MLKEM768", Classification.SANGAT_TINGGI, Severity.CRIT),  # hybrid name
        _f("net.tls.kex", "ML-KEM-768", Classification.PQC_READY, Severity.INFO),          # safe
        _f("fs.crypto", "AES-128", Classification.SEDERHANA, Severity.MED),                # weakened only
        _f("x.y", "N/A", Classification.INFO, Severity.INFO),                              # info
    ]
    rows = build_register(findings)
    assert rows == []


def _seed(repo: Repo) -> int:
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(scan_id, _f(
        "fs.cert.sniff", "RSA-2048", Classification.SANGAT_TINGGI, Severity.CRIT,
        {"path": "/etc/ssl/server.pem"},
    ))
    repo.record_finding(scan_id, _f(
        "net.tls.kex", "ML-KEM-768", Classification.PQC_READY, Severity.INFO,
    ))
    repo.finish_scan(scan_id, status="done")
    return scan_id


def test_report_context_has_migration_and_exposure_keys(tmp_db_path) -> None:
    repo = Repo(tmp_db_path)
    repo.init_schema()
    ctx = build_report_context(repo, _seed(repo), lang="en")

    assert "migration_readiness" in ctx
    mr = ctx["migration_readiness"]
    assert mr["total"] == 2 and mr["safe"] == 1 and mr["vulnerable"] == 1
    assert mr["score"] == 50.0 and mr["band"] == "MODERATE"

    assert "exposure" in ctx
    exp = ctx["exposure"]
    assert exp["total"] == 1                       # only the vulnerable cert
    assert exp["rows"][0]["tier"] == "CRITICAL"
    assert exp["tier_counts"]["CRITICAL"] == 1

from datetime import datetime

from pqcscan.core.types import (
    Capability,
    Classification,
    Component,
    Finding,
    ProbeFamily,
    Severity,
)


def test_capability_values():
    assert Capability.ROOT.value == "root"
    assert Capability.NET_RAW.value == "net_raw"
    assert Capability.DAC_READ_SEARCH.value == "dac_read_search"
    assert Capability.KUBECTL.value == "kubectl"
    assert Capability.CONTAINER_RT.value == "container_rt"


def test_probe_family_includes_v1_families():
    expected = {
        "host", "sbom", "network", "filesystem", "code",
        "vpn", "storage", "container", "app", "sign",
        "dns_email", "pqc_meta", "aux", "secrets", "ot",
    }
    actual = {f.value for f in ProbeFamily}
    assert actual == expected


def test_classification_includes_malay_terms():
    expected = {
        "sangat-tinggi", "tinggi", "sederhana", "rendah",
        "pqc-ready", "info", "error",
    }
    actual = {c.value for c in Classification}
    assert actual == expected


def test_severity_ordering():
    assert Severity.CRIT.numeric > Severity.HIGH.numeric
    assert Severity.HIGH.numeric > Severity.MED.numeric
    assert Severity.MED.numeric > Severity.LOW.numeric
    assert Severity.LOW.numeric > Severity.INFO.numeric


def test_component_purl_round_trip():
    c = Component(
        purl="pkg:deb/debian/openssl@3.0.2-1ubuntu1.10",
        type="os-pkg",
        name="openssl",
        version="3.0.2-1ubuntu1.10",
        location="/usr/bin/openssl",
        discovered_by="sbom.os.dpkg",
    )
    assert c.purl.startswith("pkg:deb/")
    assert c.attributes == {}


def test_finding_minimal():
    f = Finding(
        probe_id="host.openssl.config",
        algorithm="RSA-2048",
        classification=Classification.TINGGI,
        severity=Severity.HIGH,
        title="RSA-2048 in default cipher list",
    )
    assert f.evidence == {}
    assert f.remediation == {}
    assert f.created_at <= datetime.utcnow()


def test_finding_with_component_purl():
    f = Finding(
        probe_id="fs.cert.x509",
        algorithm="sha1WithRSAEncryption",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="SHA-1 signature on cert",
        component_purl="pkg:file/etc/ssl/certs/legacy.pem",
    )
    assert f.component_purl is not None

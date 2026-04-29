from pqcscan.probes._registry import default_registry


def test_default_registry_has_seven_probes():
    reg = default_registry()
    ids = set(reg.ids())
    expected = {
        "host.openssl.config", "sbom.os.dpkg", "net.tls.https",
        "fs.cert.x509", "code.ts.python", "pqc.alg.normaliser",
        "aux.clock.cert_validity",
    }
    assert expected.issubset(ids)

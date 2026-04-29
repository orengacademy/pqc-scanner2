from __future__ import annotations

from collections.abc import Iterator

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Probe


class Registry:
    def __init__(self) -> None:
        self._probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        if not probe.id:
            raise ValueError(f"probe {type(probe).__name__} has empty id")
        if probe.id in self._probes:
            raise ValueError(f"duplicate probe id: {probe.id}")
        self._probes[probe.id] = probe

    def get(self, probe_id: str) -> Probe:
        return self._probes[probe_id]

    def ids(self) -> list[str]:
        return list(self._probes.keys())

    def all(self) -> Iterator[Probe]:
        return iter(self._probes.values())

    def by_family(self, family: ProbeFamily) -> Iterator[Probe]:
        return (p for p in self._probes.values() if p.family is family)


def default_registry() -> Registry:
    """Built-in probe set for v1 MVP — 7 representative probes (one per family)."""
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    from pqcscan.probes.code_ts_python import CodeTsPython
    from pqcscan.probes.fs_cert_x509 import FsCertX509
    from pqcscan.probes.host_openssl_config import HostOpenSSLConfig
    from pqcscan.probes.net_tls_https import NetTlsHttps
    from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser
    from pqcscan.probes.sbom_os_dpkg import SbomOsDpkg

    reg = Registry()
    reg.register(HostOpenSSLConfig())
    reg.register(SbomOsDpkg())
    reg.register(NetTlsHttps())
    reg.register(FsCertX509())
    reg.register(CodeTsPython())
    reg.register(PqcAlgNormaliser())
    reg.register(AuxClockCertValidity())
    return reg

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
    """Built-in probe set — Plan A MVP (7) + Plan B batch 1 (5) = 12 probes."""
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    from pqcscan.probes.code_ts_python import CodeTsPython
    from pqcscan.probes.fs_cert_privkey import FsCertPrivkey
    from pqcscan.probes.fs_cert_x509 import FsCertX509
    from pqcscan.probes.fs_conf_apache import FsConfApache
    from pqcscan.probes.fs_conf_nginx import FsConfNginx
    from pqcscan.probes.host_gnupg_config import HostGnupgConfig
    from pqcscan.probes.host_openssl_config import HostOpenSSLConfig
    from pqcscan.probes.host_ssh_server_config import HostSshServerConfig
    from pqcscan.probes.net_tls_https import NetTlsHttps
    from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser
    from pqcscan.probes.sbom_os_dpkg import SbomOsDpkg

    reg = Registry()
    # Plan A — MVP foundation (one probe per family).
    reg.register(HostOpenSSLConfig())
    reg.register(SbomOsDpkg())
    reg.register(NetTlsHttps())
    reg.register(FsCertX509())
    reg.register(CodeTsPython())
    reg.register(PqcAlgNormaliser())
    reg.register(AuxClockCertValidity())
    # Plan B batch 1 — extended host + filesystem coverage.
    reg.register(HostSshServerConfig())
    reg.register(HostGnupgConfig())
    reg.register(FsCertPrivkey())
    reg.register(FsConfNginx())
    reg.register(FsConfApache())
    return reg

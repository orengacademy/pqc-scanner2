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
    """Built-in probe set — Plan A (7) + Plan B batches 1-9 (44) = 51 probes."""
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    from pqcscan.probes.code_ts_python import CodeTsPython
    from pqcscan.probes.container_image_sbom import ContainerImageSbom
    from pqcscan.probes.container_runtime_detect import ContainerRuntimeDetect
    from pqcscan.probes.k8s_helm_releases import K8sHelmReleases
    from pqcscan.probes.k8s_ingress_tls import K8sIngressTls
    from pqcscan.probes.k8s_mesh_mtls import K8sMeshMtls
    from pqcscan.probes.k8s_secrets_types import K8sSecretsTypes
    from pqcscan.probes.fs_cert_privkey import FsCertPrivkey
    from pqcscan.probes.fs_cert_x509 import FsCertX509
    from pqcscan.probes.fs_conf_apache import FsConfApache
    from pqcscan.probes.fs_conf_nginx import FsConfNginx
    from pqcscan.probes.fs_conf_openssl_cnf import FsConfOpensslCnf
    from pqcscan.probes.fs_conf_sshd import FsConfSshd
    from pqcscan.probes.host_gnupg_config import HostGnupgConfig
    from pqcscan.probes.host_openssl_ciphers import HostOpenSSLCiphers
    from pqcscan.probes.host_openssl_config import HostOpenSSLConfig
    from pqcscan.probes.host_openssl_engines import HostOpenSSLEngines
    from pqcscan.probes.host_ssh_client_config import HostSshClientConfig
    from pqcscan.probes.host_ssh_server_config import HostSshServerConfig
    from pqcscan.probes.net_db_mongo_tls import NetDbMongoTls
    from pqcscan.probes.net_db_mysql_tls import NetDbMysqlTls
    from pqcscan.probes.net_db_postgres_tls import NetDbPostgresTls
    from pqcscan.probes.net_db_redis_tls import NetDbRedisTls
    from pqcscan.probes.net_ports_tcp import NetPortsTcp
    from pqcscan.probes.net_starttls_ftp import NetStarttlsFtp
    from pqcscan.probes.net_starttls_imap import NetStarttlsImap
    from pqcscan.probes.net_starttls_ldap import NetStarttlsLdap
    from pqcscan.probes.net_starttls_pop3 import NetStarttlsPop3
    from pqcscan.probes.net_starttls_smtp import NetStarttlsSmtp
    from pqcscan.probes.net_tls_https import NetTlsHttps
    from pqcscan.probes.net_tls_imaps import NetTlsImaps
    from pqcscan.probes.net_tls_ldaps import NetTlsLdaps
    from pqcscan.probes.net_tls_mqtts import NetTlsMqtts
    from pqcscan.probes.net_tls_pop3s import NetTlsPop3s
    from pqcscan.probes.net_tls_smtps import NetTlsSmtps
    from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser
    from pqcscan.probes.sbom_lang_gomod import SbomLangGomod
    from pqcscan.probes.sbom_lang_npm import SbomLangNpm
    from pqcscan.probes.sbom_lang_pip import SbomLangPip
    from pqcscan.probes.sbom_os_apk import SbomOsApk
    from pqcscan.probes.sbom_os_dpkg import SbomOsDpkg
    from pqcscan.probes.sbom_os_rpm import SbomOsRpm
    from pqcscan.probes.storage_bitlocker import StorageBitlocker
    from pqcscan.probes.storage_dmcrypt import StorageDmcrypt
    from pqcscan.probes.storage_fscrypt import StorageFscrypt
    from pqcscan.probes.storage_luks_headers import StorageLuksHeaders
    from pqcscan.probes.storage_zfs_encryption import StorageZfsEncryption
    from pqcscan.probes.vpn_openvpn_config import VpnOpenvpnConfig
    from pqcscan.probes.vpn_tailscale_state import VpnTailscaleState
    from pqcscan.probes.vpn_wireguard import VpnWireguard

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
    # Plan B batch 2 — SSH client config, OpenSSL CLI introspection,
    # filesystem mirrors of sshd_config / openssl.cnf.
    reg.register(HostSshClientConfig())
    reg.register(HostOpenSSLCiphers())
    reg.register(HostOpenSSLEngines())
    reg.register(FsConfSshd())
    reg.register(FsConfOpensslCnf())
    # Plan B batch 3 — TLS variants on alternative ports (mail, LDAP, MQTT).
    reg.register(NetTlsImaps())
    reg.register(NetTlsPop3s())
    reg.register(NetTlsSmtps())
    reg.register(NetTlsLdaps())
    reg.register(NetTlsMqtts())
    # Plan B batch 4 — STARTTLS family (text protocols + LDAP stub).
    reg.register(NetStarttlsSmtp())
    reg.register(NetStarttlsImap())
    reg.register(NetStarttlsPop3())
    reg.register(NetStarttlsFtp())
    reg.register(NetStarttlsLdap())
    # Plan B batch 5 — SBOM expansion (RHEL/Alpine OS + Python/JS/Go langs).
    reg.register(SbomOsRpm())
    reg.register(SbomOsApk())
    reg.register(SbomLangPip())
    reg.register(SbomLangNpm())
    reg.register(SbomLangGomod())
    # Plan B batch 6 — port discovery + database TLS.
    reg.register(NetPortsTcp())
    reg.register(NetDbPostgresTls())
    reg.register(NetDbMongoTls())
    reg.register(NetDbRedisTls())
    reg.register(NetDbMysqlTls())
    # Plan B batch 7 — VPN beyond IKE.
    reg.register(VpnWireguard())
    reg.register(VpnOpenvpnConfig())
    reg.register(VpnTailscaleState())
    # Plan B batch 8 — storage at-rest.
    reg.register(StorageLuksHeaders())
    reg.register(StorageBitlocker())
    reg.register(StorageZfsEncryption())
    reg.register(StorageDmcrypt())
    reg.register(StorageFscrypt())
    # Plan B batch 9 — container + Kubernetes coverage.
    reg.register(ContainerRuntimeDetect())
    reg.register(ContainerImageSbom())
    reg.register(K8sIngressTls())
    reg.register(K8sSecretsTypes())
    reg.register(K8sHelmReleases())
    reg.register(K8sMeshMtls())
    return reg

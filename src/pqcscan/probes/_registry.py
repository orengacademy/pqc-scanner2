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
    """Built-in probe set — 98 probes (Plan B batches 1-15 + FOSS-tools add-on)."""
    from pqcscan.probes.app_dotenv_secrets import AppDotenvSecrets
    from pqcscan.probes.app_jwt_env_alg import AppJwtEnvAlg
    from pqcscan.probes.app_nginx_jwt_validation import AppNginxJwtValidation
    from pqcscan.probes.app_oauth_jwks import AppOauthJwks
    from pqcscan.probes.app_spring_properties import AppSpringProperties
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    from pqcscan.probes.code_bandit import CodeBandit
    from pqcscan.probes.code_semgrep_pqc import CodeSemgrepPqc
    from pqcscan.probes.code_ts_go import CodeTsGo
    from pqcscan.probes.code_ts_java import CodeTsJava
    from pqcscan.probes.code_ts_javascript import CodeTsJavascript
    from pqcscan.probes.code_ts_php import CodeTsPhp
    from pqcscan.probes.code_ts_python import CodeTsPython
    from pqcscan.probes.code_ts_rust import CodeTsRust
    from pqcscan.probes.container_image_sbom import ContainerImageSbom
    from pqcscan.probes.cve_cargo_audit import CveCargoAudit
    from pqcscan.probes.cve_govulncheck import CveGovulncheck
    from pqcscan.probes.cve_grype import CveGrype
    from pqcscan.probes.cve_npm_audit import CveNpmAudit
    from pqcscan.probes.cve_osv_offline import CveOsvOffline
    from pqcscan.probes.cve_pip_audit import CvePipAudit
    from pqcscan.probes.cve_trivy_fs import CveTrivyFs
    from pqcscan.probes.dns_dnssec_zones import DnsDnssecZones
    from pqcscan.probes.email_dkim_selectors import EmailDkimSelectors
    from pqcscan.probes.email_smime_certs import EmailSmimeCerts
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
    from pqcscan.probes.host_lynis import HostLynis
    from pqcscan.probes.host_openssl_ciphers import HostOpenSSLCiphers
    from pqcscan.probes.host_openssl_config import HostOpenSSLConfig
    from pqcscan.probes.host_openssl_engines import HostOpenSSLEngines
    from pqcscan.probes.host_ssh_client_config import HostSshClientConfig
    from pqcscan.probes.host_ssh_server_config import HostSshServerConfig
    from pqcscan.probes.net_db_mongo_tls import NetDbMongoTls
    from pqcscan.probes.net_db_mysql_tls import NetDbMysqlTls
    from pqcscan.probes.net_db_postgres_tls import NetDbPostgresTls
    from pqcscan.probes.net_db_redis_tls import NetDbRedisTls
    from pqcscan.probes.net_ike_v1v2 import NetIkeV1V2
    from pqcscan.probes.net_kerberos_asreq import NetKerberosAsreq
    from pqcscan.probes.net_ports_tcp import NetPortsTcp
    from pqcscan.probes.net_rdp_negotiation import NetRdpNegotiation
    from pqcscan.probes.net_smb_dialect import NetSmbDialect
    from pqcscan.probes.net_snmp_version import NetSnmpVersion
    from pqcscan.probes.net_ssh_handshake import NetSshHandshake
    from pqcscan.probes.net_starttls_ftp import NetStarttlsFtp
    from pqcscan.probes.net_starttls_imap import NetStarttlsImap
    from pqcscan.probes.net_starttls_ldap import NetStarttlsLdap
    from pqcscan.probes.net_starttls_pop3 import NetStarttlsPop3
    from pqcscan.probes.net_starttls_smtp import NetStarttlsSmtp
    from pqcscan.probes.net_tls_https import NetTlsHttps
    from pqcscan.probes.net_tls_imaps import NetTlsImaps
    from pqcscan.probes.net_tls_ldaps import NetTlsLdaps
    from pqcscan.probes.net_tls_mqtts import NetTlsMqtts
    from pqcscan.probes.net_tls_nmap_ssl import NetTlsNmapSsl
    from pqcscan.probes.net_tls_pop3s import NetTlsPop3s
    from pqcscan.probes.net_tls_smtps import NetTlsSmtps
    from pqcscan.probes.net_tls_sslyze import NetTlsSslyze
    from pqcscan.probes.net_tls_testssl import NetTlsTestssl
    from pqcscan.probes.secrets_gitleaks import SecretsGitleaks
    from pqcscan.probes.sign_code_authenticode import SignCodeAuthenticode
    from pqcscan.probes.sign_git_signing_keys import SignGitSigningKeys
    from pqcscan.probes.sign_gpg_keyrings import SignGpgKeyrings
    from pqcscan.probes.sign_image_cosign import SignImageCosign
    from pqcscan.probes.sign_repo_aptdnf_keys import SignRepoAptdnfKeys
    from pqcscan.probes.trust_system_roots import TrustSystemRoots
    from pqcscan.probes.web_webauthn_config import WebWebauthnConfig
    from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser
    from pqcscan.probes.sbom_lang_cargo import SbomLangCargo
    from pqcscan.probes.sbom_lang_composer import SbomLangComposer
    from pqcscan.probes.sbom_lang_gomod import SbomLangGomod
    from pqcscan.probes.sbom_lang_maven import SbomLangMaven
    from pqcscan.probes.sbom_lang_npm import SbomLangNpm
    from pqcscan.probes.sbom_lang_pip import SbomLangPip
    from pqcscan.probes.sbom_os_apk import SbomOsApk
    from pqcscan.probes.sbom_os_brew import SbomOsBrew
    from pqcscan.probes.sbom_os_dpkg import SbomOsDpkg
    from pqcscan.probes.sbom_os_pacman import SbomOsPacman
    from pqcscan.probes.sbom_os_rpm import SbomOsRpm
    from pqcscan.probes.sbom_os_windows import SbomOsWindows
    from pqcscan.probes.sbom_syft import SbomSyft
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
    # FOSS-tools add-on — Syft + Grype + Semgrep + OSV stub.
    reg.register(SbomSyft())
    reg.register(CveGrype())
    reg.register(CveOsvOffline())
    reg.register(CodeSemgrepPqc())
    # FOSS VA suite — TLS-specialised + per-language VA + system audit
    # + Python SAST + secrets. Each auto-skips when its tool isn't on PATH.
    reg.register(NetTlsTestssl())
    reg.register(NetTlsSslyze())
    reg.register(NetTlsNmapSsl())
    reg.register(CvePipAudit())
    reg.register(CveNpmAudit())
    reg.register(CveGovulncheck())
    reg.register(CveCargoAudit())
    reg.register(CveTrivyFs())
    reg.register(HostLynis())
    reg.register(CodeBandit())
    reg.register(SecretsGitleaks())
    # Plan B batch 10 — app-config crypto.
    reg.register(AppJwtEnvAlg())
    reg.register(AppOauthJwks())
    reg.register(AppDotenvSecrets())
    reg.register(AppSpringProperties())
    reg.register(AppNginxJwtValidation())
    # Plan B batch 11 — signing & integrity.
    reg.register(SignGpgKeyrings())
    reg.register(SignRepoAptdnfKeys())
    reg.register(SignCodeAuthenticode())
    reg.register(SignGitSigningKeys())
    reg.register(SignImageCosign())
    # Plan B batch 12 — DNS, email, web auth.
    reg.register(DnsDnssecZones())
    reg.register(EmailDkimSelectors())
    reg.register(EmailSmimeCerts())
    reg.register(WebWebauthnConfig())
    reg.register(TrustSystemRoots())
    # Plan B batch 13 — language SBOM expansion.
    reg.register(SbomOsPacman())
    reg.register(SbomOsBrew())
    reg.register(SbomOsWindows())
    reg.register(SbomLangCargo())
    reg.register(SbomLangMaven())
    reg.register(SbomLangComposer())
    # Plan B batch 14 — source-code probes for JS/Go/Java/PHP/Rust.
    reg.register(CodeTsJavascript())
    reg.register(CodeTsGo())
    reg.register(CodeTsJava())
    reg.register(CodeTsPhp())
    reg.register(CodeTsRust())
    # Plan B batch 15 — binary-protocol probes (live network handshakes).
    reg.register(NetSshHandshake())
    reg.register(NetIkeV1V2())
    reg.register(NetRdpNegotiation())
    reg.register(NetSmbDialect())
    reg.register(NetSnmpVersion())
    reg.register(NetKerberosAsreq())
    return reg

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
    """Built-in probe set — 122 probes (Plan H + Plan I.7 + Plan I.2 minimal)."""
    from pqcscan.probes.app_crypto_lib_pqc_support import AppCryptoLibPqcSupport
    from pqcscan.probes.app_jwt_env_alg import AppJwtEnvAlg
    from pqcscan.probes.app_nginx_jwt_validation import AppNginxJwtValidation
    from pqcscan.probes.app_oauth_jwks import AppOauthJwks
    from pqcscan.probes.app_spring_properties import AppSpringProperties
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    from pqcscan.probes.code_semgrep_pqc import CodeSemgrepPqc
    from pqcscan.probes.code_ts_go import CodeTsGo
    from pqcscan.probes.code_ts_java import CodeTsJava
    from pqcscan.probes.code_ts_javascript import CodeTsJavascript
    from pqcscan.probes.code_ts_php import CodeTsPhp
    from pqcscan.probes.code_ts_python import CodeTsPython
    from pqcscan.probes.code_ts_rust import CodeTsRust
    from pqcscan.probes.container_image_sbom import ContainerImageSbom
    from pqcscan.probes.container_runtime_detect import ContainerRuntimeDetect
    from pqcscan.probes.db_mongo_encrypted_storage import DbMongoEncryptedStorage
    from pqcscan.probes.db_mssql_tde import DbMssqlTde
    from pqcscan.probes.db_mysql_keyring import DbMysqlKeyring
    from pqcscan.probes.db_pg_pgcrypto import DbPgPgcrypto
    from pqcscan.probes.dns_dnssec_zones import DnsDnssecZones
    from pqcscan.probes.email_dkim_selectors import EmailDkimSelectors
    from pqcscan.probes.email_smime_certs import EmailSmimeCerts
    from pqcscan.probes.fs_cert_chain import FsCertChain
    from pqcscan.probes.fs_cert_csr import FsCertCsr
    from pqcscan.probes.fs_cert_expiry_horizon import FsCertExpiryHorizon
    from pqcscan.probes.fs_cert_pkcs7 import FsCertPkcs7
    from pqcscan.probes.fs_cert_pqc_x509 import FsCertPqcX509
    from pqcscan.probes.fs_cert_privkey import FsCertPrivkey
    from pqcscan.probes.fs_cert_privkey_encrypted import FsCertPrivkeyEncrypted
    from pqcscan.probes.fs_cert_revocation import FsCertRevocation
    from pqcscan.probes.fs_cert_sniff import FsCertSniff
    from pqcscan.probes.fs_cert_x509 import FsCertX509
    from pqcscan.probes.fs_conf_apache import FsConfApache
    from pqcscan.probes.fs_conf_caddy import FsConfCaddy
    from pqcscan.probes.fs_conf_envoy import FsConfEnvoy
    from pqcscan.probes.fs_conf_haproxy import FsConfHaproxy
    from pqcscan.probes.fs_conf_nginx import FsConfNginx
    from pqcscan.probes.fs_conf_openssl_cnf import FsConfOpensslCnf
    from pqcscan.probes.fs_conf_sshd import FsConfSshd
    from pqcscan.probes.fs_conf_traefik import FsConfTraefik
    from pqcscan.probes.fs_keyref_cloud import FsKeyrefCloud
    from pqcscan.probes.fs_keystore_jks import FsKeystoreJks
    from pqcscan.probes.fs_keystore_pkcs12 import FsKeystorePkcs12
    from pqcscan.probes.fs_ssh_host_keys import FsSshHostKeys
    from pqcscan.probes.host_crypto_policies import HostCryptoPolicies
    from pqcscan.probes.host_gnupg_config import HostGnupgConfig
    from pqcscan.probes.host_gnutls_config import HostGnutlsConfig
    from pqcscan.probes.host_kernel_crypto_registry import HostKernelCryptoRegistry
    from pqcscan.probes.host_krb5_config import HostKrb5Config
    from pqcscan.probes.host_libcrypto_pqc_features import HostLibcryptoPqcFeatures
    from pqcscan.probes.host_nss_policy import HostNssPolicy
    from pqcscan.probes.host_openssl_ciphers import HostOpenSSLCiphers
    from pqcscan.probes.host_openssl_config import HostOpenSSLConfig
    from pqcscan.probes.host_openssl_engines import HostOpenSSLEngines
    from pqcscan.probes.host_openssl_fips_state import HostOpenSSLFipsState
    from pqcscan.probes.host_openssl_groups import HostOpenSSLGroups
    from pqcscan.probes.host_openssl_oqs_provider import HostOpenSSLOqsProvider
    from pqcscan.probes.host_openssl_version import HostOpenSSLVersion
    from pqcscan.probes.host_pam_hashing import HostPamHashing
    from pqcscan.probes.host_rng_config import HostRngConfig
    from pqcscan.probes.host_ssh_binary_caps import HostSshBinaryCaps
    from pqcscan.probes.host_ssh_client_config import HostSshClientConfig
    from pqcscan.probes.host_ssh_moduli import HostSshModuli
    from pqcscan.probes.host_ssh_server_config import HostSshServerConfig
    from pqcscan.probes.host_tpm_sealed_keys import HostTpmSealedKeys
    from pqcscan.probes.hw_pkcs11_modules import HwPkcs11Modules
    from pqcscan.probes.hw_smartcard_readers import HwSmartcardReaders
    from pqcscan.probes.hw_tpm_algorithms import HwTpmAlgorithms
    from pqcscan.probes.k8s_helm_releases import K8sHelmReleases
    from pqcscan.probes.k8s_ingress_tls import K8sIngressTls
    from pqcscan.probes.k8s_mesh_mtls import K8sMeshMtls
    from pqcscan.probes.k8s_mesh_policy import K8sMeshPolicy
    from pqcscan.probes.k8s_secrets_types import K8sSecretsTypes
    from pqcscan.probes.mq_kafka_tls import MqKafkaTls
    from pqcscan.probes.mq_mqtt_broker import MqMqttBroker
    from pqcscan.probes.mq_nats_tls import MqNatsTls
    from pqcscan.probes.mq_rabbitmq_tls import MqRabbitmqTls
    from pqcscan.probes.net_db_mongo_tls import NetDbMongoTls
    from pqcscan.probes.net_db_mysql_tls import NetDbMysqlTls
    from pqcscan.probes.net_db_postgres_tls import NetDbPostgresTls
    from pqcscan.probes.net_db_redis_tls import NetDbRedisTls
    from pqcscan.probes.net_ike_v1v2 import NetIkeV1V2
    from pqcscan.probes.net_kerberos_asreq import NetKerberosAsreq
    from pqcscan.probes.net_ports_tcp import NetPortsTcp
    from pqcscan.probes.net_ports_udp import NetPortsUDP
    from pqcscan.probes.net_rdp_negotiation import NetRdpNegotiation
    from pqcscan.probes.net_smb_dialect import NetSmbDialect
    from pqcscan.probes.net_snmp_version import NetSnmpVersion
    from pqcscan.probes.net_ssh_handshake import NetSshHandshake
    from pqcscan.probes.net_starttls_ftp import NetStarttlsFtp
    from pqcscan.probes.net_starttls_imap import NetStarttlsImap
    from pqcscan.probes.net_starttls_ldap import NetStarttlsLdap
    from pqcscan.probes.net_starttls_pop3 import NetStarttlsPop3
    from pqcscan.probes.net_starttls_smtp import NetStarttlsSmtp
    from pqcscan.probes.net_tls_cert_chain import NetTlsCertChain
    from pqcscan.probes.net_tls_https import NetTlsHttps
    from pqcscan.probes.net_tls_imaps import NetTlsImaps
    from pqcscan.probes.net_tls_kex_groups import NetTlsKexGroups
    from pqcscan.probes.net_tls_ldaps import NetTlsLdaps
    from pqcscan.probes.net_tls_mqtts import NetTlsMqtts
    from pqcscan.probes.net_tls_nmap_ssl import NetTlsNmapSsl
    from pqcscan.probes.net_tls_pop3s import NetTlsPop3s
    from pqcscan.probes.net_tls_pqc_handshake import NetTlsPqcHandshake
    from pqcscan.probes.net_tls_smtps import NetTlsSmtps
    from pqcscan.probes.net_tls_sslyze import NetTlsSslyze
    from pqcscan.probes.net_tls_testssl import NetTlsTestssl
    from pqcscan.probes.net_tls_versions import NetTlsVersions
    from pqcscan.probes.ot_bacnet import OTBacnet
    from pqcscan.probes.ot_bacnet_sc import OTBacnetSc
    from pqcscan.probes.ot_cip_security import OTCipSecurity
    from pqcscan.probes.ot_coap_dtls import OTCoapDtls
    from pqcscan.probes.ot_dicom_tls import OTDicomTls
    from pqcscan.probes.ot_dnp3_tcp import OTDnp3Tcp
    from pqcscan.probes.ot_ethernet_ip import OTEthernetIp
    from pqcscan.probes.ot_gtp import OTGtp
    from pqcscan.probes.ot_hl7_tls import OTHl7Tls
    from pqcscan.probes.ot_iec_104 import OTIec104
    from pqcscan.probes.ot_iec_61850_mms import OTIec61850Mms
    from pqcscan.probes.ot_modbus_secure import OTModbusSecure
    from pqcscan.probes.ot_modbus_tcp import OTModbusTcp
    from pqcscan.probes.ot_opc_ua import OTOpcUa
    from pqcscan.probes.ot_s7comm import OTS7comm
    from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser
    from pqcscan.probes.pqc_kat_fips import PqcKatFips
    from pqcscan.probes.pqc_meta_nacsa_phase import PqcMetaNacsaPhase
    from pqcscan.probes.pqc_meta_oqs_status import PqcMetaOqsStatus
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
    from pqcscan.probes.sign_code_authenticode import SignCodeAuthenticode
    from pqcscan.probes.sign_git_signing_keys import SignGitSigningKeys
    from pqcscan.probes.sign_gpg_keyrings import SignGpgKeyrings
    from pqcscan.probes.sign_image_cosign import SignImageCosign
    from pqcscan.probes.sign_repo_aptdnf_keys import SignRepoAptdnfKeys
    from pqcscan.probes.storage_bitlocker import StorageBitlocker
    from pqcscan.probes.storage_dmcrypt import StorageDmcrypt
    from pqcscan.probes.storage_fscrypt import StorageFscrypt
    from pqcscan.probes.storage_luks_headers import StorageLuksHeaders
    from pqcscan.probes.storage_zfs_encryption import StorageZfsEncryption
    from pqcscan.probes.trust_system_roots import TrustSystemRoots
    from pqcscan.probes.vpn_openvpn_config import VpnOpenvpnConfig
    from pqcscan.probes.vpn_tailscale_state import VpnTailscaleState
    from pqcscan.probes.vpn_wireguard import VpnWireguard
    from pqcscan.probes.web_webauthn_config import WebWebauthnConfig

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
    reg.register(NetPortsUDP())  # Plan H.2 — UDP scan
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
    # FOSS-tools add-on — Syft + Semgrep (Plan H.1 dropped Grype + OSV).
    reg.register(SbomSyft())
    reg.register(CodeSemgrepPqc())
    # FOSS VA suite — TLS-specialised. Each auto-skips when its tool isn't on PATH.
    # (Plan H.1 dropped pip-audit, npm-audit, govulncheck, cargo-audit, trivy,
    # lynis, bandit, gitleaks — out of PQC scope.)
    reg.register(NetTlsTestssl())
    reg.register(NetTlsSslyze())
    reg.register(NetTlsNmapSsl())
    # Plan B batch 10 — app-config crypto (Plan H.1 dropped dotenv-secrets).
    reg.register(AppJwtEnvAlg())
    reg.register(AppOauthJwks())
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
    # Plan G batch 1 — DB at-rest TDE config (deferred per spec §13.1).
    reg.register(DbPgPgcrypto())
    reg.register(DbMysqlKeyring())
    reg.register(DbMssqlTde())
    reg.register(DbMongoEncryptedStorage())
    # Plan G batch 2 — message-queue brokers (deferred per spec §13.1).
    reg.register(MqKafkaTls())
    reg.register(MqRabbitmqTls())
    reg.register(MqNatsTls())
    reg.register(MqMqttBroker())
    # Plan G batch 3 — hardware crypto (deferred per spec §13.1).
    reg.register(HwTpmAlgorithms())
    reg.register(HwPkcs11Modules())
    reg.register(HwSmartcardReaders())
    # Plan H.3a — OT/ICS TCP binary parsers.
    reg.register(OTModbusTcp())
    reg.register(OTModbusSecure())
    reg.register(OTS7comm())
    reg.register(OTDnp3Tcp())
    reg.register(OTIec104())
    reg.register(OTIec61850Mms())
    reg.register(OTEthernetIp())
    # Plan H.3b — OT/ICS TLS-wrapped + OPC UA + BACnet.
    reg.register(OTOpcUa())
    reg.register(OTCipSecurity())
    reg.register(OTBacnet())
    reg.register(OTBacnetSc())
    # Plan H.3c — OT telco / health / IoT.
    reg.register(OTGtp())
    reg.register(OTDicomTls())
    reg.register(OTHl7Tls())
    reg.register(OTCoapDtls())
    # Plan I.7.a — OQS active validation foundation.
    reg.register(HostOpenSSLOqsProvider())
    reg.register(PqcMetaOqsStatus())
    # Plan I.7.b — active hybrid-KEX TLS probe.
    reg.register(NetTlsPqcHandshake())
    # Plan I.7.c — X.509 PQC cert profile probe.
    reg.register(FsCertPqcX509())
    # Plan I.7.d — local crypto stack PQC inventory.
    reg.register(AppCryptoLibPqcSupport())
    reg.register(HostLibcryptoPqcFeatures())
    # Plan I.7.e — NIST FIPS 203/204/205 KAT runner.
    reg.register(PqcKatFips())
    # Plan I.2 (minimal) — NACSA Arahan #9 Fasa state.
    reg.register(PqcMetaNacsaPhase())
    # Coverage roadmap Phase 0 — system-wide crypto policy (RHEL/Fedora).
    reg.register(HostCryptoPolicies())
    # Coverage roadmap Phase 0 — OpenSSH PQC-KEX binary capability.
    reg.register(HostSshBinaryCaps())
    # Coverage roadmap Phase 0 — Kerberos krb5.conf weak enctypes + PKINIT.
    reg.register(HostKrb5Config())
    # Coverage roadmap Phase 0 — OpenSSL library version & PQC tier.
    reg.register(HostOpenSSLVersion())
    # Coverage roadmap Phase 0 — on-disk SSH public key inventory.
    reg.register(FsSshHostKeys())
    # Coverage roadmap Phase 1 — cloud KMS / Key Vault / PKCS#11 key references.
    reg.register(FsKeyrefCloud())
    # Coverage roadmap Phase 1 — cert/keystore parsers (PKCS#12, CSR, PKCS#7, expiry-HNDL).
    reg.register(FsKeystorePkcs12())
    reg.register(FsCertCsr())
    reg.register(FsCertPkcs7())
    reg.register(FsCertExpiryHorizon())
    # Coverage roadmap Phase 1 — encrypted private keys + Java keystores.
    reg.register(FsCertPrivkeyEncrypted())
    reg.register(FsKeystoreJks())
    # Coverage roadmap Phase 2 — raw-TLS handshake engine: KEX + served chain.
    reg.register(NetTlsKexGroups())
    reg.register(NetTlsCertChain())
    # Coverage roadmap Phase 2/3 — TLS version sweep, OpenSSL group policy,
    # service-mesh policy, cert-chain assembly.
    reg.register(NetTlsVersions())
    reg.register(HostOpenSSLGroups())
    reg.register(K8sMeshPolicy())
    reg.register(FsCertChain())
    # Coverage roadmap Phase 3 — host crypto-policy backends (FIPS/kernel/GnuTLS/NSS).
    reg.register(HostOpenSSLFipsState())
    reg.register(HostKernelCryptoRegistry())
    reg.register(HostGnutlsConfig())
    reg.register(HostNssPolicy())
    # Coverage roadmap Phase 3/4 — mislabeled certs, revocation path, TPM-sealed keys.
    reg.register(FsCertSniff())
    reg.register(FsCertRevocation())
    reg.register(HostTpmSealedKeys())
    # Coverage wave — reverse-proxy / mesh TLS config + long-tail host posture.
    reg.register(FsConfHaproxy())
    reg.register(FsConfEnvoy())
    reg.register(FsConfTraefik())
    reg.register(FsConfCaddy())
    reg.register(HostRngConfig())
    reg.register(HostPamHashing())
    reg.register(HostSshModuli())
    return reg

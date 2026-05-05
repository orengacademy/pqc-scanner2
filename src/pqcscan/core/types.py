from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Capability(StrEnum):
    ROOT = "root"
    NET_RAW = "net_raw"
    DAC_READ_SEARCH = "dac_read_search"
    KUBECTL = "kubectl"
    CONTAINER_RT = "container_rt"


class ProbeFamily(StrEnum):
    HOST = "host"
    SBOM = "sbom"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    CODE = "code"
    VPN = "vpn"
    STORAGE = "storage"
    CONTAINER = "container"
    APP = "app"
    SIGN = "sign"
    DNS_EMAIL = "dns_email"
    PQC_META = "pqc_meta"
    AUX = "aux"
    SECRETS = "secrets"


class Classification(StrEnum):
    SANGAT_TINGGI = "sangat-tinggi"
    TINGGI = "tinggi"
    SEDERHANA = "sederhana"
    RENDAH = "rendah"
    PQC_READY = "pqc-ready"
    INFO = "info"
    ERROR = "error"


class Severity(StrEnum):
    CRIT = "crit"
    HIGH = "high"
    MED = "med"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> int:
        return {"info": 0, "low": 1, "med": 2, "high": 3, "crit": 4}[self.value]


@dataclass(slots=True)
class Component:
    purl: str
    type: str  # os-pkg | lib | service | cert | key | file | app | container
    name: str
    version: str | None = None
    location: str = ""
    discovered_by: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    probe_id: str
    algorithm: str
    classification: Classification
    severity: Severity
    title: str
    component_purl: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

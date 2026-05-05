"""net.ports.tcp — async TCP open-port scanner against localhost.

Scans a configurable list of common server ports; emits one INFO finding
per open port. Downstream probes (TLS / SSH / DB) typically run on a
fixed port regardless of this scan, but the discovery output is useful
context for the dashboard and future probe-routing logic.
"""
from __future__ import annotations

import asyncio
from collections.abc import Iterable

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_PORTS: tuple[int, ...] = (
    21,    # FTP
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # rpcbind
    143,   # IMAP
    389,   # LDAP
    443,   # HTTPS
    445,   # SMB
    465,   # SMTPS
    514,   # syslog
    587,   # SMTP submission
    636,   # LDAPS
    873,   # rsync
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1521,  # Oracle
    1883,  # MQTT
    2049,  # NFS
    2375,  # docker (insecure)
    2376,  # docker (TLS)
    3000,  # node/dev
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5672,  # RabbitMQ AMQP
    5984,  # CouchDB
    6379,  # Redis
    6443,  # K8s API
    8080,  # http-alt
    8443,  # https-alt
    8883,  # MQTTS
    9092,  # Kafka
    9200,  # Elasticsearch
    11211, # Memcached
    27017, # MongoDB
)


class NetPortsTcp(Probe):
    id = "net.ports.tcp"
    family = ProbeFamily.NETWORK
    framework_tags = ("bukukerja:net", "mykripto:net")

    def __init__(
        self,
        host: str = "127.0.0.1",
        ports: Iterable[int] | None = None,
        connect_timeout_s: float = 0.4,
        max_concurrent: int = 64,
    ):
        self.host = host
        self.ports: tuple[int, ...] = tuple(ports) if ports is not None else _DEFAULT_PORTS
        self.connect_timeout_s = connect_timeout_s
        self.max_concurrent = max_concurrent

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        sem = asyncio.Semaphore(self.max_concurrent)

        async def check(port: int) -> tuple[int, bool]:
            async with sem:
                try:
                    _, w = await asyncio.wait_for(
                        asyncio.open_connection(self.host, port),
                        timeout=self.connect_timeout_s,
                    )
                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception:
                        pass
                    return port, True
                except (TimeoutError, OSError):
                    return port, False

        results = await asyncio.gather(*(check(p) for p in self.ports))
        open_ports = [p for p, is_open in results if is_open]
        for p in open_ports:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"open TCP port {self.host}:{p}",
                evidence={"host": self.host, "port": p},
            ))

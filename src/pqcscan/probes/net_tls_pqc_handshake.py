"""net.tls.pqc_handshake — active hybrid-KEX TLS probe (Plan I.7.b).

Shells out to `openssl s_client -groups <pqc-hybrid> -connect host:port`,
captures the TLS 1.3 negotiated group, and classifies whether the remote
endpoint completed a PQC hybrid handshake.

Requires:
- openssl 3.5+ with native ML-KEM support, OR
- oqs-provider loaded in openssl 3.0-3.4 (see host.openssl.oqs_provider).

Without either, openssl rejects the hybrid group list and the probe
emits an INFO finding noting absence of PQC support locally.

Default groups list (priority order): X25519MLKEM768, SecP256r1MLKEM768,
X25519Kyber768Draft00 (legacy oqs-provider), then classical fallbacks
X25519, secp256r1.
"""
from __future__ import annotations

import asyncio
import re
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_HYBRID_GROUPS = (
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "X25519Kyber768Draft00",
    "X25519",
    "secp256r1",
)

_GROUP_RE = re.compile(
    r"(?:Negotiated TLS\s*[\d.]+\s*group|Server Temp Key)\s*:\s*([A-Za-z0-9_]+)",
    re.IGNORECASE,
)
_PROTO_RE = re.compile(r"^\s*Protocol\s*:\s*(\S+)", re.MULTILINE)


def _is_pqc_group(group: str) -> bool:
    g = group.lower()
    return "mlkem" in g or "ml-kem" in g or "kyber" in g or "ml_kem" in g


class NetTlsPqcHandshake(Probe):
    id = "net.tls.pqc_handshake"
    family = ProbeFamily.NETWORK
    framework_tags = (
        "nist-ir-8547:tls", "cnsa2:tls", "bukukerja:tls",
        "mykripto:tls", "nacsa-9:pqc-readiness",
    )

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 443,
        groups: tuple[str, ...] = _DEFAULT_HYBRID_GROUPS,
        timeout_s: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.groups = groups
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which("openssl") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        host = ctx.server_target.split(":")[0] if ctx.server_target else self.host
        port = self.port
        if ctx.server_target and ":" in ctx.server_target:
            try:
                port = int(ctx.server_target.split(":")[1])
            except (IndexError, ValueError):
                port = self.port

        groups_str = ":".join(self.groups)
        args = [
            "openssl", "s_client",
            "-tls1_3",
            "-groups", groups_str,
            "-connect", f"{host}:{port}",
            "-servername", host,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=b"\n"), timeout=self.timeout_s,
            )
        except (TimeoutError, OSError) as e:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"PQC hybrid handshake failed at {host}:{port}: {e}",
                evidence={"endpoint": f"tcp://{host}:{port}", "error": repr(e)},
            ))
            return

        text = (
            stdout_b.decode("utf-8", errors="replace")
            + "\n"
            + stderr_b.decode("utf-8", errors="replace")
        )

        text_lc = text.lower()
        if "unknown option" in text_lc or "unsupported" in text_lc or "unknown group" in text_lc:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title="local openssl does not support PQC hybrid groups",
                evidence={
                    "endpoint": f"tcp://{host}:{port}",
                    "groups_offered": list(self.groups),
                    "remediation": "Install openssl 3.5+ or load oqs-provider; see host.openssl.oqs_provider.",
                    "raw_head": text[:400],
                },
            ))
            return

        proto_m = _PROTO_RE.search(text)
        group_m = _GROUP_RE.search(text)
        proto = proto_m.group(1) if proto_m else None
        group = group_m.group(1) if group_m else None

        if not group:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"PQC hybrid handshake produced no negotiated group at {host}:{port}",
                evidence={
                    "endpoint": f"tcp://{host}:{port}",
                    "protocol": proto,
                    "groups_offered": list(self.groups),
                    "raw_head": text[:400],
                },
            ))
            return

        if _is_pqc_group(group):
            emit(Finding(
                probe_id=self.id,
                algorithm=group,
                classification=Classification.PQC_READY,
                severity=Severity.INFO,
                title=f"PQC hybrid handshake succeeded at {host}:{port} — {group}",
                evidence={
                    "endpoint": f"tcp://{host}:{port}",
                    "protocol": proto,
                    "negotiated_group": group,
                    "groups_offered": list(self.groups),
                },
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm=group,
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title=f"server fell back to classical group {group} at {host}:{port}",
                evidence={
                    "endpoint": f"tcp://{host}:{port}",
                    "protocol": proto,
                    "negotiated_group": group,
                    "groups_offered": list(self.groups),
                    "remediation": (
                        "Server does not support PQC hybrid KEX. "
                        "Upgrade to openssl 3.5 / load oqs-provider on remote."
                    ),
                },
            ))

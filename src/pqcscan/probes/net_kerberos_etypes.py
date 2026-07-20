"""net.kerberos.etypes — enumerate a Kerberos KDC's supported encryption types.

Complementary to net.kerberos.asreq (which only confirms the KDC is listening):
this probe builds a real ASN.1 KRB_AS_REQ that offers the full etype list and
reads the KDC's reply. A KRB-ERROR (typically KDC_ERR_PREAUTH_REQUIRED or
KDC_ERR_C_PRINCIPAL_UNKNOWN) or an AS-REP both confirm the KDC parsed our
request; where the reply echoes etypes (AS-REP enc-part.etype, or an
ETYPE-INFO2 in a preauth error's e-data) we emit a finding per supported etype.

Weak etypes are the quantum/legacy risk here: single-DES and RC4 are already
classically broken (SANGAT_TINGGI), 3DES is quantum-weak (TINGGI), while AES
buys headroom (AES-128 → SEDERHANA, AES-256 → RENDAH). If the KDC only errors
without echoing etypes we still emit an INFO recording reachability and the
etypes we OFFERED, so the operator sees the client-side exposure.

The ASN.1 builder/parser live in ``_krb_asn1`` and are pure functions, so the
wire format is unit-testable without a live KDC.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._krb_asn1 import build_as_req, parse_kdc_reply

__all__ = ["ETYPE_NAMES", "NetKerberosEtypes", "build_as_req", "classify_etype", "parse_kdc_reply"]

# etype number -> canonical name (RFC 3961/4120 + the Windows set).
ETYPE_NAMES: dict[int, str] = {
    1: "des-cbc-crc",
    2: "des-cbc-md4",
    3: "des-cbc-md5",
    16: "des3-cbc-sha1",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
}

# DES (1-3), export RC4 (24) and RC4 (23) are classically broken; 3DES (16) is
# quantum-weak; AES-128 variants are Grover-weakened; AES-256 variants keep
# headroom.
_SANGAT_TINGGI_ETYPES = frozenset({1, 2, 3, 23, 24})
_TINGGI_ETYPES = frozenset({16})
_SEDERHANA_ETYPES = frozenset({17, 19})
_RENDAH_ETYPES = frozenset({18, 20})

# Offered in the AS-REQ (strong first, but the KDC's own preference decides).
_OFFERED_ETYPES: tuple[int, ...] = (18, 20, 17, 19, 16, 23, 3, 2, 1, 24)

_SEVERITY_FOR: dict[Classification, Severity] = {
    Classification.SANGAT_TINGGI: Severity.CRIT,
    Classification.TINGGI: Severity.HIGH,
    Classification.SEDERHANA: Severity.MED,
    Classification.RENDAH: Severity.LOW,
    Classification.INFO: Severity.INFO,
}


def classify_etype(etype: int) -> Classification:
    """Map a Kerberos etype number to a pqcscan threat classification."""
    if etype in _SANGAT_TINGGI_ETYPES:
        return Classification.SANGAT_TINGGI
    if etype in _TINGGI_ETYPES:
        return Classification.TINGGI
    if etype in _SEDERHANA_ETYPES:
        return Classification.SEDERHANA
    if etype in _RENDAH_ETYPES:
        return Classification.RENDAH
    return Classification.INFO


def _etype_name(etype: int) -> str:
    return ETYPE_NAMES.get(etype, f"etype-{etype}")


class NetKerberosEtypes(Probe):
    """Enumerate a KDC's supported encryption types via a crafted AS-REQ."""

    id = "net.kerberos.etypes"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:kerberos", "mykripto:kerberos")

    def __init__(
        self,
        target: str | None = None,
        *,
        realm: str | None = None,
        principal: str = "pqcscan-probe",
        timeout: float = 6.0,
    ):
        self.target = target
        self.realm = realm
        self.principal = principal
        self.timeout = timeout

    def _resolve_target(self, ctx: ScanContext) -> tuple[str, int] | None:
        raw = self.target or ctx.server_target
        if not raw:
            return None
        host, _, port = raw.partition(":")
        if not host:
            return None
        if not port:
            return host, 88
        try:
            return host, int(port)
        except ValueError:
            return None

    async def applies(self, ctx: ScanContext) -> bool:
        return self._resolve_target(ctx) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        tgt = self._resolve_target(ctx)
        if tgt is None:
            return
        host, port = tgt
        realm = self.realm or host.upper()
        reply = await self._query(host, port, realm, self.principal)
        if reply is None:
            return  # clean failure (unreachable / parse gave nothing) -> emit nothing

        supported = [e for e in reply.get("etypes", []) if e is not None]
        if supported:
            for etype in supported:
                classification = classify_etype(etype)
                name = _etype_name(etype)
                emit(Finding(
                    probe_id=self.id,
                    algorithm=f"kerberos-etype/{name}",
                    classification=classification,
                    severity=_SEVERITY_FOR.get(classification, Severity.INFO),
                    title=f"{host}:{port} Kerberos KDC supports etype {etype} ({name})",
                    evidence={
                        "host": host,
                        "port": port,
                        "realm": realm,
                        "etype": etype,
                        "etype_name": name,
                        "msg_type": reply.get("msg_type"),
                        "source": "as-rep/etype-info2",
                    },
                ))
            return

        # Reachable, but the KDC errored without echoing etypes: record the
        # client-side exposure (which weak etypes we were willing to accept).
        offered = [
            {"etype": e, "name": _etype_name(e), "classification": classify_etype(e).value}
            for e in _OFFERED_ETYPES
        ]
        emit(Finding(
            probe_id=self.id,
            algorithm="Kerberos",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=(f"{host}:{port} Kerberos KDC reachable "
                   f"(error_code={reply.get('error_code')}); etypes offered but not echoed"),
            evidence={
                "host": host,
                "port": port,
                "realm": realm,
                "msg_type": reply.get("msg_type"),
                "error_code": reply.get("error_code"),
                "etypes_offered": offered,
                "note": ("KDC parsed the AS-REQ but did not return an ETYPE-INFO2 "
                         "(unknown principal or no pre-auth data); the offered list "
                         "shows which weak etypes this client would accept."),
            },
        ))

    async def _query(self, host: str, port: int, realm: str, principal: str) -> dict | None:
        """Send the AS-REQ over TCP/88 and parse the reply. Returns the parsed
        dict, or None on any socket/timeout failure (never raises)."""
        msg = build_as_req(realm, principal, list(_OFFERED_ETYPES))
        framed = struct.pack(">I", len(msg)) + msg
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout)
        except (OSError, TimeoutError):
            return None
        try:
            writer.write(framed)
            await writer.drain()
            header = await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)
            rlen = struct.unpack(">I", header)[0]
            body = await asyncio.wait_for(
                reader.readexactly(min(rlen, 1 << 20)), timeout=self.timeout)
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            return None
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await writer.wait_closed()
        return parse_kdc_reply(body)

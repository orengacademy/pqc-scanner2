"""UDP probe payloads — one per well-known UDP service."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UDPPayload:
    port: int
    name: str
    payload: bytes
    expect_response: bool = True


def _ntp_client() -> bytes:
    return b"\x23" + b"\x00" * 47


def _snmp_v2c_get_sysdescr() -> bytes:
    return bytes.fromhex(
        "302902010104067075626c6963a01c0204"
        "1234567802010002010030103e0e060a2b"
        "06010201010100050000"
    )


def _ike_isakmp_init() -> bytes:
    initiator_spi = b"\x11" * 8
    responder_spi = b"\x00" * 8
    return initiator_spi + responder_spi + b"\x00\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x1c"


def _dns_root_query() -> bytes:
    return bytes.fromhex("1234010000010000000000000000010001")


def _bacnet_who_is() -> bytes:
    bvlc = b"\x81\x0b\x00\x0c"
    npdu = b"\x01\x20"
    apdu = b"\x10\x08"
    return bvlc + npdu + apdu


def _dnp3_link_status() -> bytes:
    return b"\x05\x64\x05\x09\x01\x00\x00\x00\x00\x00"


def _gtpv2c_echo() -> bytes:
    return bytes.fromhex("4801000400000001")


def _coap_get_well_known_core() -> bytes:
    header = b"\x40\x01\xbe\xef"
    opt1 = b"\xbb" + b".well-known"
    opt2 = b"\x04" + b"core"
    return header + opt1 + opt2


def _coaps_dtls_clienthello() -> bytes:
    return bytes.fromhex(
        "16fefd0000000000000000003a010000"
        "2e0000000000000000fefd0000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000200140100"
    )


DEFAULT_UDP_PORTS: tuple[UDPPayload, ...] = (
    UDPPayload(53,    "DNS",         _dns_root_query()),
    UDPPayload(123,   "NTP",         _ntp_client()),
    UDPPayload(161,   "SNMP",        _snmp_v2c_get_sysdescr()),
    UDPPayload(500,   "IKEv1/2",     _ike_isakmp_init()),
    UDPPayload(514,   "syslog",      b"", expect_response=False),
    UDPPayload(1812,  "RADIUS",      b"\x01\x01\x00\x14" + b"\x00" * 16),
    UDPPayload(1813,  "RADIUS-acct", b"", expect_response=False),
    UDPPayload(4500,  "IKE-NAT-T",   b"\x00\x00\x00\x00" + _ike_isakmp_init()),
    UDPPayload(4789,  "VXLAN",       b"", expect_response=False),
    UDPPayload(5060,  "SIP",         b"OPTIONS sip:probe@127.0.0.1 SIP/2.0\r\n\r\n"),
    UDPPayload(5353,  "mDNS",        _dns_root_query()),
    UDPPayload(5683,  "CoAP",        _coap_get_well_known_core()),
    UDPPayload(5684,  "CoAPS-DTLS",  _coaps_dtls_clienthello()),
    UDPPayload(6343,  "sFlow",       b"", expect_response=False),
    UDPPayload(20000, "DNP3",        _dnp3_link_status()),
    UDPPayload(2123,  "GTP-C",       _gtpv2c_echo()),
    UDPPayload(2152,  "GTP-U",       _gtpv2c_echo()),
    UDPPayload(47808, "BACnet",      _bacnet_who_is()),
)

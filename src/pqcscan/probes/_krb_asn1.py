"""Minimal, dependency-free Kerberos ASN.1 DER for net.kerberos.etypes.

We hand-roll just enough BER/DER to (a) build a valid KRB_AS_REQ that offers a
list of encryption types and (b) parse a KRB-ERROR or AS-REP reply far enough to
recover the KDC's error code and any encryption types it echoes (AS-REP
enc-part.etype or an ETYPE-INFO2 carried in a preauth error). No third-party
asn1 dependency — every tag/length/value is explicit so the encoding is
reviewable and the parser stays defensive (it never raises on garbage input).

References: RFC 4120 (Kerberos v5 messages) and RFC 3961/4120 etype numbers.
"""
from __future__ import annotations

import struct

# --- Kerberos constants --------------------------------------------------
KRB_PVNO = 5
MSG_TYPE_AS_REQ = 10
MSG_TYPE_AS_REP = 11
MSG_TYPE_KRB_ERROR = 30

# ASN.1 tags we emit / expect.
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_SEQUENCE = 0x30
_TAG_GENERAL_STRING = 0x1B  # KerberosString / Realm
_TAG_GENERALIZED_TIME = 0x18  # KerberosTime
_TAG_APP_AS_REQ = 0x6A  # [APPLICATION 10]
_TAG_APP_AS_REP = 0x6B  # [APPLICATION 11]
_TAG_APP_KRB_ERROR = 0x7E  # [APPLICATION 30]

# PA-DATA padata-type values that carry an ETYPE-INFO(2) list.
_PA_ETYPE_INFO = 11
_PA_ETYPE_INFO2 = 19

# name-type values (RFC 4120 §6.2).
_NT_PRINCIPAL = 1
_NT_SRV_INST = 2

# A far-future "till" so the KDC never rejects on an expired request window.
_DEFAULT_TILL = "20370913024805Z"
_DEFAULT_NONCE = 0x51455343  # arbitrary, deterministic ("QESC")


# --- DER encoders --------------------------------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    body = b""
    while n:
        body = bytes((n & 0xFF,)) + body
        n >>= 8
    return bytes((0x80 | len(body),)) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(value)) + value


def _der_int(n: int) -> bytes:
    if n == 0:
        return _tlv(_TAG_INTEGER, b"\x00")
    body = b""
    v = n
    while v:
        body = bytes((v & 0xFF,)) + body
        v >>= 8
    if body[0] & 0x80:  # keep it positive
        body = b"\x00" + body
    return _tlv(_TAG_INTEGER, body)


def _der_gstr(s: str) -> bytes:
    return _tlv(_TAG_GENERAL_STRING, s.encode("ascii"))


def _seq(*items: bytes) -> bytes:
    return _tlv(_TAG_SEQUENCE, b"".join(items))


def _ctx(n: int, value: bytes) -> bytes:
    """Context-specific, constructed tag [n]."""
    return _tlv(0xA0 | n, value)


def _kdc_options(flags: int = 0x00000000) -> bytes:
    # KDCOptions is a 32-bit KerberosFlags BIT STRING: 0 unused bits + 4 bytes.
    return _tlv(_TAG_BIT_STRING, b"\x00" + struct.pack(">I", flags))


def _principal_name(name_type: int, components: list[str]) -> bytes:
    return _seq(
        _ctx(0, _der_int(name_type)),
        _ctx(1, _seq(*[_der_gstr(c) for c in components])),
    )


def build_as_req(realm: str, principal: str, etypes: list[int]) -> bytes:
    """Build a minimal KRB_AS_REQ (ASN.1 DER) requesting a TGT for
    ``principal@realm`` and offering ``etypes``.

    Returns the bare ASN.1 message; the caller adds the 4-byte TCP length
    prefix required by Kerberos-over-TCP.
    """
    req_body = _seq(
        _ctx(0, _kdc_options()),
        _ctx(1, _principal_name(_NT_PRINCIPAL, [principal])),
        _ctx(2, _der_gstr(realm)),
        _ctx(3, _principal_name(_NT_SRV_INST, ["krbtgt", realm])),
        _ctx(5, _tlv(_TAG_GENERALIZED_TIME, _DEFAULT_TILL.encode("ascii"))),
        _ctx(7, _der_int(_DEFAULT_NONCE)),
        _ctx(8, _seq(*[_der_int(e) for e in etypes])),
    )
    kdc_req = _seq(
        _ctx(1, _der_int(KRB_PVNO)),
        _ctx(2, _der_int(MSG_TYPE_AS_REQ)),
        _ctx(4, req_body),
    )
    return _tlv(_TAG_APP_AS_REQ, kdc_req)


# --- DER decoders --------------------------------------------------------
def _read_tlv(data: bytes, off: int) -> tuple[int, bytes, int]:
    """Return (tag, value, next_offset). Raises IndexError/ValueError on a
    truncated buffer; callers wrap in try/except."""
    tag = data[off]
    off += 1
    first = data[off]
    off += 1
    if first & 0x80:
        num = first & 0x7F
        length = int.from_bytes(data[off:off + num], "big")
        off += num
    else:
        length = first
    value = data[off:off + length]
    if len(value) != length:
        raise ValueError("truncated TLV")
    return tag, value, off + length


def _context_fields(seq_body: bytes) -> dict[int, bytes]:
    """Map each [n] context-tagged field of a SEQUENCE body to its value."""
    fields: dict[int, bytes] = {}
    off = 0
    while off < len(seq_body):
        tag, value, off = _read_tlv(seq_body, off)
        if 0xA0 <= tag <= 0xBF:  # context-specific, constructed
            fields[tag & 0x1F] = value
    return fields


def _decode_int(tlv_bytes: bytes) -> int:
    _tag, value, _ = _read_tlv(tlv_bytes, 0)
    return int.from_bytes(value, "big", signed=True)


def _etypes_from_info(info_der: bytes) -> list[int]:
    """Pull etypes from an ETYPE-INFO/ETYPE-INFO2 (SEQUENCE OF entries, each
    with the etype in context tag [0])."""
    out: list[int] = []
    _tag, body, _ = _read_tlv(info_der, 0)
    off = 0
    while off < len(body):
        _etag, entry, off = _read_tlv(body, off)
        ef = _context_fields(entry)
        if 0 in ef:
            out.append(_decode_int(ef[0]))
    return out


def _etypes_from_methoddata(methoddata_der: bytes) -> list[int]:
    """Walk a METHOD-DATA (SEQUENCE OF PA-DATA) and collect etypes from any
    ETYPE-INFO/ETYPE-INFO2 padata entries."""
    out: list[int] = []
    _tag, body, _ = _read_tlv(methoddata_der, 0)
    off = 0
    while off < len(body):
        _ptag, pa, off = _read_tlv(body, off)
        pf = _context_fields(pa)
        if 1 in pf and 2 in pf and _decode_int(pf[1]) in (_PA_ETYPE_INFO, _PA_ETYPE_INFO2):
            _otag, pval, _ = _read_tlv(pf[2], 0)  # padata-value OCTET STRING
            out.extend(_etypes_from_info(pval))
    return out


def _dedupe(items: list[int]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def parse_kdc_reply(data: bytes) -> dict:
    """Parse a KRB-ERROR or AS-REP reply (bare ASN.1, TCP length prefix
    already stripped).

    Returns ``{"msg_type": int|None, "etypes": list[int], "error_code":
    int|None}``. Never raises: on any malformed input the fields it could not
    recover stay at their defaults.
    """
    result: dict = {"msg_type": None, "etypes": [], "error_code": None}
    try:
        tag, body, _ = _read_tlv(data, 0)
        _stag, seq_body, _ = _read_tlv(body, 0)
        fields = _context_fields(seq_body)
    except (IndexError, ValueError):
        return result

    try:
        if tag == _TAG_APP_KRB_ERROR:
            result["msg_type"] = MSG_TYPE_KRB_ERROR
            if 6 in fields:  # error-code
                result["error_code"] = _decode_int(fields[6])
            if 12 in fields:  # e-data OCTET STRING -> METHOD-DATA
                _otag, edata, _ = _read_tlv(fields[12], 0)
                result["etypes"] = _dedupe(_etypes_from_methoddata(edata))
        elif tag == _TAG_APP_AS_REP:
            result["msg_type"] = MSG_TYPE_AS_REP
            etypes: list[int] = []
            if 2 in fields:  # padata may carry ETYPE-INFO2
                etypes.extend(_etypes_from_methoddata(fields[2]))
            if 6 in fields:  # enc-part EncryptedData -> [0] etype
                _etag, enc, _ = _read_tlv(fields[6], 0)
                ef = _context_fields(enc)
                if 0 in ef:
                    etypes.append(_decode_int(ef[0]))
            result["etypes"] = _dedupe(etypes)
    except (IndexError, ValueError):
        pass
    return result

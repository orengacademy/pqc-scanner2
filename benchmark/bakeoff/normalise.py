"""Map each scanner's REAL output to one row schema and diff the results.

Row schema (one dict per observed algorithm / parameter)::

    {target, surface: tls|cert|code, algorithm, strength_bits: int|None,
     pq_safe: bool|None, detail, source_tool}

``target`` is an endpoint name for ``tls`` and a path relative to the staged tree for ``cert`` / ``code``.
``pq_safe`` is the tool's own verdict: True quantum-safe or hybrid, False quantum-vulnerable, None not stated.

The diff compares ``(target, surface, canonical(algorithm))`` where ``canonical`` folds naming differences
(``X25519MLKEM768`` / ``x25519_kyber768``, ``RSA-2048`` / ``RSA``, OpenSSL vs IANA suite names) into one key.
Nothing here imports pqcscan: the normalisers read saved raw files, so they test without a scan.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

SURFACES = ("tls", "cert", "code")
Row = dict[str, Any]


# --------------------------------------------------------------------------------------------------
# canonical algorithm key
# --------------------------------------------------------------------------------------------------

_HASHES = {"md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256", "sha384": "sha384",
           "sha512": "sha512", "sha2": "sha2", "sha3": "sha3"}


def _suite(name: str) -> str | None:
    """Fold OpenSSL (ECDHE-RSA-AES128-GCM-SHA256) and IANA / rustls (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) suite
    names into one lower-case key. TLS 1.3 suites (TLS_AES_256_GCM_SHA384, TLS13_...) get a ``tls13-`` prefix so
    they never collide with the TLS 1.2 RSA-key-exchange suite of the same tail (OpenSSL AES256-GCM-SHA384)."""
    s = name.upper().replace("_", "-")
    if not re.search(r"(AES|CHACHA|NULL|DES|RC4|CAMELLIA|ARIA)", s) or not re.search(r"(SHA|POLY1305)", s):
        return None
    tls13 = bool(re.match(r"^TLS(?:13)?-(?:AES|CHACHA)", s)) and "-WITH-" not in s
    s = re.sub(r"^TLS(?:13)?-", "", s)
    if "-WITH-" in s:
        kex, s = s.split("-WITH-", 1)
        s = s if kex == "RSA" else f"{kex}-{s}"
    s = re.sub(r"AES-(\d{3})", r"AES\1", s)
    return ("tls13-" if tls13 else "") + s.lower()


def canonical(algorithm: str) -> str:
    """Case-fold and alias-fold an algorithm name so two tools' spellings of one thing compare equal."""
    raw = algorithm.strip()
    low = raw.lower()
    flat = re.sub(r"[\s_\-/.]", "", low)

    # post-quantum and hybrid groups: X25519MLKEM768 == x25519_kyber768 == X25519Kyber768Draft00
    pq = flat.replace("kyber", "mlkem").replace("draft00", "")
    if "mlkem" in pq:
        return pq
    if re.fullmatch(r"(mldsa|dilithium)\d*(publickey)?", flat) or flat.startswith(("mldsa", "slhdsa", "falcon")):
        digits = re.search(r"\d+", flat)
        return "ml-dsa-" + digits.group(0) if digits and "mldsa" in flat else flat.replace("publickey", "")

    ver = re.fullmatch(r"(?:tls|ssl)v?(\d(?:\.\d)?)", low.replace(" ", ""))
    if ver:
        return "tls" + ver.group(1)
    if flat.startswith("chacha20"):  # the bare primitive, before _suite() mistakes ChaCha20-Poly1305 for a TLS suite
        return "chacha20"
    suite = _suite(raw)
    if suite:
        return suite

    if flat.startswith("rsa"):
        return flat if re.search(r"sha\d", flat) else "rsa"  # RSA-SHA256 is a signature scheme, not the key
    if flat in {"x25519", "x448", "ed25519", "ed448"}:
        return flat
    if flat.startswith(("secp", "prime")):
        return flat  # a bare named group (a key-exchange group), distinct from an EC key / signature
    if flat.startswith(("ecdsa", "ecdh", "ecc", "p256", "p384", "p521", "ec")) and flat != "ecb":
        return flat if re.search(r"sha\d", flat) else "ec"  # ECDSA-SHA256 is a signature scheme, not the key
    if flat.startswith("ffdhe"):
        return flat
    if flat.startswith(("dh", "dsa")):
        return flat.rstrip("0123456789")
    if flat in {"3des", "tripledes", "desede"}:
        return "3des"
    if flat.startswith("des"):
        return "des"
    if flat.startswith("aesecb"):
        return "aes-ecb"  # a weakness in its own right, kept apart from the AES family
    if flat.startswith("aes"):
        return "aes"
    if flat in {"postquantumcryptolibrary", "liboqspqcrypto", "liboqs", "pqcrypto"}:
        return "pqc-library"  # cryptoscan "Post-Quantum Cryptography Library" == pqcscan "liboqs / pqcrypto" import
    if flat in _HASHES:
        return _HASHES[flat]
    return flat


def strength_bits(algorithm: str) -> int | None:
    """Key / parameter size in bits when the algorithm name states one (RSA-2048, secp384r1, AES-256)."""
    low = algorithm.lower()
    for pattern in (r"^(?:rsa|dh|dsa|ffdhe)[-_ ]?(\d{3,5})", r"secp(\d{3})", r"^(?:p|prime)-?(\d{3})",
                    r"aes[-_ ]?(\d{3})", r"^sha[-_]?(\d{3})"):
        m = re.search(pattern, low)
        if m:
            return int(m.group(1))
    return None


def _row(target: str, surface: str, algorithm: str, pq_safe: bool | None, detail: str, tool: str) -> Row:
    return {"target": target, "surface": surface, "algorithm": algorithm.strip(),
            "strength_bits": strength_bits(algorithm), "pq_safe": pq_safe, "detail": detail, "source_tool": tool}


# --------------------------------------------------------------------------------------------------
# pqcscan  (raw = list of finding dicts: probe_id, algorithm, classification, severity, title, evidence)
# --------------------------------------------------------------------------------------------------

def _pqcscan_surface(probe_id: str) -> str:
    return "tls" if probe_id.startswith("net.tls.") else "code" if probe_id.startswith("code.") else "cert"


def normalise_pqcscan(raw: list[dict[str, Any]], target: str | None = None) -> list[Row]:
    """``target`` names a TLS endpoint; file findings take their path from ``evidence.path`` / ``evidence.file``."""
    rows: list[Row] = []
    for f in raw:
        alg = str(f.get("algorithm") or "")
        if alg in {"", "N/A", "UNKNOWN", "PKCS12-ENCRYPTED"}:
            continue  # probe markers ("could not connect", "encrypted keystore", "signature UNKNOWN") name no algorithm
        if f["probe_id"] == "net.tls.versions" and "does not support" in f["title"]:
            continue  # absence of TLS 1.3, not an observed algorithm; no competitor reports absences
        cls = f.get("classification")
        pq_safe = True if cls == "pqc-ready" else None if cls == "info" else False
        surface = _pqcscan_surface(f["probe_id"])
        ev = f.get("evidence") or {}
        where = target if surface == "tls" else str(ev.get("path") or ev.get("file") or "")
        rows.append(_row(where or "?", surface, alg, pq_safe, f"{f['probe_id']}: {f['title']}", "pqcscan"))
    return rows


# --------------------------------------------------------------------------------------------------
# anvilsecure/pqcscan  (raw = its tls-scan JSON; advertised key-exchange groups only)
# --------------------------------------------------------------------------------------------------

def normalise_anvil(raw: dict[str, Any], target: str) -> list[Row]:
    rows: list[Row] = []
    for item in raw.get("results", []):
        tls = item.get("Tls")
        if not tls or tls.get("error"):
            continue
        for key, pq_safe in (("pqc_algos", True), ("hybrid_algos", True), ("nonpqc_algos", False)):
            for alg in tls.get(key) or []:
                rows.append(_row(target, "tls", alg, pq_safe, f"anvil {key}: key-exchange group accepted", "anvil"))
    return rows


# --------------------------------------------------------------------------------------------------
# Mehrn0ush/QuantaSeek  (raw = its JSON on stdout; a ServerHello-parsing active TLS scanner)
# --------------------------------------------------------------------------------------------------

_OIDS = {"1.3.101.112": "Ed25519", "1.3.101.113": "Ed448", "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
         "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}


def _qs_name(name: str) -> str:
    """QuantaSeek prints `OID(1.3.101.112)` for key / signature algorithms it cannot name; resolve the known ones."""
    m = re.fullmatch(r"OID\((.+)\)", name)
    return _OIDS.get(m.group(1), name) if m else name


def normalise_quantaseek(raw: dict[str, Any], target: str, tool: str = "quantaseek") -> list[Row]:
    if not raw.get("handshake_complete"):
        return []  # a failed handshake carries no observation, only a warning
    rows = [_row(target, "tls", f"TLS {raw['tls_version']}", None, "quantaseek tls_version", tool)]
    suite = str(raw.get("cipher_suite") or "")
    if suite and not suite.startswith("Unknown"):  # it cannot name TLS 1.2 suites: "Unknown(0xc02f)"
        rows.append(_row(target, "tls", suite, None, "quantaseek cipher_suite", tool))
    for group in raw.get("key_exchange") or []:
        rows.append(_row(target, "tls", group, "mlkem" in canonical(group), "quantaseek key_exchange", tool))
    cert = raw.get("certificate") or {}
    pq_sigs = {_qs_name(a) for a in (raw.get("analysis") or {}).get("pqc_signature_algorithms") or []}
    for field in ("public_key_algorithm", "signature_algorithm"):
        if cert.get(field):
            alg = _qs_name(str(cert[field]))
            rows.append(_row(target, "tls", alg, canonical(alg).startswith("ml-dsa") or alg in pq_sigs,
                             f"quantaseek certificate.{field}", tool))
    return rows


# --------------------------------------------------------------------------------------------------
# csnp/cryptoscan  (raw = its --format json; regex hits in files)
# --------------------------------------------------------------------------------------------------

_CS_RISK = {"SAFE": True, "HYBRID": True, "VULNERABLE": False}  # PARTIAL / UNKNOWN / other -> None


def _cs_algorithm(f: dict[str, Any]) -> str | None:
    alg = f.get("algorithm")
    match = str(f.get("match") or "").lower()
    if not alg:
        # certificate / key-material findings carry a type, not an algorithm: record the artefact kind
        return str(f["type"]) if f.get("type") else None
    if alg == "ECC":  # one bucket for every curve; the matched text says which one
        for named in ("ed25519", "x25519"):
            if named in match:
                return named.capitalize() if named == "ed25519" else "X25519"
    if alg == "SHA-2":
        m = re.search(r"sha-?(\d{3})", match)
        if m:
            return f"SHA-{m.group(1)}"
    return str(alg)


def normalise_cryptoscan(raw: dict[str, Any], surface: str = "code", root: str = "/t/") -> list[Row]:
    """``surface`` is the kind of tree that was scanned: cryptoscan matches text in any file, so a certificate
    directory yields hits on the PEM header or on a name inside a DER blob, not on a parsed key."""
    rows: list[Row] = []
    for f in raw.get("findings") or []:
        alg = _cs_algorithm(f)
        if not alg or f.get("findingType") == "config":
            continue
        path = str(f.get("file") or "")
        path = path[len(root):] if path.startswith(root) else path
        detail = f"{f.get('id')}: {f.get('type')} (line {f.get('line')}, {f.get('quantumRisk')})"
        rows.append(_row(path, surface, alg, _CS_RISK.get(str(f.get("quantumRisk"))), detail, "cryptoscan"))
    return rows


# --------------------------------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------------------------------

def key_of(row: Row) -> tuple[str, str, str]:
    return row["target"], row["surface"], canonical(row["algorithm"])


def diff_sets(base: Iterable[Row], other: Iterable[Row]) -> dict[str, list[tuple[str, str, str]]]:
    """Set diff on (target, surface, canonical algorithm): ``base`` is pqcscan, ``other`` a competitor."""
    a, b = {key_of(r) for r in base}, {key_of(r) for r in other}
    return {"pqcscan_only": sorted(a - b), "tool_only": sorted(b - a), "both": sorted(a & b)}


NORMALISERS: dict[str, Callable[..., list[Row]]] = {
    "pqcscan": normalise_pqcscan, "anvil": normalise_anvil, "quantaseek": normalise_quantaseek,
    "quantaseek-noverify": lambda raw, target: normalise_quantaseek(raw, target, "quantaseek-noverify"),
    "cryptoscan": normalise_cryptoscan,
}
# usage: NORMALISERS[tool](raw, target)  (cryptoscan takes the tree's surface instead of a target)

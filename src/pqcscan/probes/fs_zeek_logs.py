"""fs.zeek.logs — ingest crypto observations from Zeek / Suricata IDS logs (offline).

Many organisations already run Zeek/Corelight (or Suricata) sensors that log every
TLS handshake and every X.509 certificate they see. This probe reads that existing
telemetry, fully offline, and inventories the post-quantum posture of the crypto that
was actually negotiated on the wire — no live tap, no raw socket, pure stdlib.

Formats parsed:

- **Zeek ``ssl.log``** — TSV with a ``#separator``/``#fields``/``#types`` header block,
  *or* one-JSON-object-per-line. Columns of interest: ``version`` (``TLSv12`` …),
  ``cipher`` (``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256``), ``curve`` (``secp256r1`` …),
  ``server_name``, ``id.resp_h``/``id.resp_p``.
- **Zeek ``x509.log``** — cert telemetry: ``certificate.sig_alg`` /
  ``certificate.key_alg`` / ``certificate.key_type`` / ``certificate.curve`` /
  ``san.dns``.
- **Suricata ``eve.json``** — JSON-lines; ``event_type == "tls"`` events carry
  ``tls.version`` / ``tls.cipher_suite`` / ``tls.sni``.

Column access is driven by the ``#fields`` header (name → value), so it is robust to
Zeek column-order changes across versions. Every observed version / cipher / curve /
cert algorithm that is quantum-vulnerable, broken, or PQC-ready is classified via the
shared ``classify()`` / ``_classify_suite`` tables.

Because these are observations lifted from someone else's logs (real, but second-hand
rather than a handshake we drove ourselves), findings are forced to ``confidence =
"medium"``. Findings are de-duplicated by (endpoint, algorithm, source) so a busy
sensor's millions of rows collapse, and the total is capped. All reads are guarded;
the probe never raises.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

# Reuse the pcap probe's cipher-suite classifier (RFC-name aware).
from pqcscan.probes.fs_pcap_crypto import _classify_suite

# Default sensor log locations. applies() = any of these exists.
_DEFAULT_ROOTS: tuple[Path, ...] = (
    Path("/opt/zeek/logs"),
    Path("/usr/local/zeek/logs"),
    Path("/var/log/zeek"),
    Path("/var/log/suricata"),
    Path("/nsm/zeek/logs"),
)

# Log-file discovery. Keyed by the source label we stamp on findings.
_LOG_GLOBS: tuple[tuple[str, str], ...] = (
    ("zeek:x509.log", "x509*.log"),
    ("zeek:ssl.log", "ssl*.log"),
    ("suricata:eve.json", "eve*.json"),
)

_MAX_LOG_FILES = 200
_MAX_LINES_PER_FILE = 500_000
_MAX_FINDINGS = 500

# TLS/SSL protocol versions that are broken transports regardless of the crypto
# negotiated on top of them. Tokens are normalised (lower-cased, spaces/dots/dashes
# and a leading "v" stripped) so "TLSv1.0", "TLS 1.0" and "tls10" all collapse here.
_WEAK_VERSION_TOKENS: frozenset[str] = frozenset({"ssl2", "ssl3", "tls10", "tls11"})

# Post-quantum fragments that mark a curve / group name as already migrated.
_PQC_CURVE_FRAGMENTS: tuple[str, ...] = ("mlkem", "ml-kem", "kyber", "frodo", "bike", "hqc", "sntrup")

# Only surface classifications that are quantum-vulnerable / broken, or explicitly
# PQC-ready. SEDERHANA/RENDAH/INFO observations are not weaknesses worth a finding.
_EMIT_CLASSES: frozenset[Classification] = frozenset(
    {Classification.SANGAT_TINGGI, Classification.TINGGI, Classification.PQC_READY}
)


def _should_emit(cls: Classification) -> bool:
    return cls in _EMIT_CLASSES


def _norm_version(v: str) -> str:
    return v.lower().replace(" ", "").replace(".", "").replace("-", "").replace("v", "")


def _classify_version(v: str) -> Classification | None:
    """Return SANGAT_TINGGI for a legacy protocol version, else None."""
    return Classification.SANGAT_TINGGI if _norm_version(v) in _WEAK_VERSION_TOKENS else None


def _classify_curve(name: str) -> Classification:
    """Classify a TLS group / EC curve name for PQC exposure."""
    low = name.lower()
    if any(frag in low for frag in _PQC_CURVE_FRAGMENTS):
        return Classification.PQC_READY
    direct = classify(name)
    if direct is not Classification.INFO:
        return direct
    if "25519" in low or "448" in low:  # X25519 / X448 — Shor-broken ECDH
        return Classification.TINGGI
    return Classification.INFO


def _decode_separator(raw: str) -> str:
    """Decode a Zeek ``#separator`` value such as ``\\x09`` into a real tab."""
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return "\t"


def _cell(row: dict[str, Any], key: str) -> str | None:
    """Fetch a column by name, normalising Zeek's empty/unset placeholders to None."""
    val = row.get(key)
    if val is None:
        return None
    s = str(val).strip()
    if s in ("", "-", "(empty)"):
        return None
    return s


def _iter_rows(path: Path) -> Iterator[dict[str, Any]]:
    """Yield one dict per data row from a Zeek TSV/JSON or Suricata JSON log.

    TSV rows are keyed by the ``#fields`` header (robust to column reordering); JSON
    logs yield the parsed object directly. Malformed lines are skipped, not raised on.
    """
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with handle:
        mode: str | None = None
        sep = "\t"
        fields: list[str] | None = None
        for i, raw_line in enumerate(handle):
            if i >= _MAX_LINES_PER_FILE:
                break
            line = raw_line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            if mode is None:
                mode = "json" if line.lstrip().startswith("{") else "tsv"
            if mode == "json":
                try:
                    obj = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if isinstance(obj, dict):
                    yield obj
                continue
            # Zeek TSV.
            if line.startswith("#"):
                if line.startswith("#separator"):
                    parts = line.split(" ", 1)
                    if len(parts) == 2:
                        sep = _decode_separator(parts[1].strip())
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                continue
            if fields is None:
                continue
            cols = line.split(sep)
            yield dict(zip(fields, cols, strict=False))


# --- per-row analysis ----------------------------------------------------

# An observation: (algorithm, classification, raw observed value).
_Obs = tuple[str, Classification, str]


def _analyze_ssl(row: dict[str, Any]) -> Iterator[_Obs]:
    version = _cell(row, "version")
    if version is not None:
        cls = _classify_version(version)
        if cls is not None:
            yield version, cls, version
    cipher = _cell(row, "cipher")
    if cipher is not None:
        cls = _classify_suite(cipher)
        if _should_emit(cls):
            yield cipher, cls, cipher
    curve = _cell(row, "curve")
    if curve is not None:
        cls = _classify_curve(curve)
        if _should_emit(cls):
            yield curve, cls, curve


def _analyze_x509(row: dict[str, Any]) -> Iterator[_Obs]:
    sig = _cell(row, "certificate.sig_alg")
    if sig is not None:
        cls = classify(sig)
        if _should_emit(cls):
            yield normalise(sig), cls, sig
    key = _cell(row, "certificate.key_alg")
    if key is not None:
        cls = classify(key)
        if _should_emit(cls):
            yield normalise(key), cls, key
    curve = _cell(row, "certificate.curve")
    if curve is not None:
        cls = _classify_curve(curve)
        if _should_emit(cls):
            yield curve, cls, curve


def _analyze_suricata(obj: dict[str, Any]) -> Iterator[_Obs]:
    if obj.get("event_type") != "tls":
        return
    tls = obj.get("tls")
    if not isinstance(tls, dict):
        return
    version = _cell(tls, "version")
    if version is not None:
        cls = _classify_version(version)
        if cls is not None:
            yield version, cls, version
    cipher = _cell(tls, "cipher_suite")
    if cipher is not None:
        cls = _classify_suite(cipher)
        if _should_emit(cls):
            yield cipher, cls, cipher


def _context(source: str, row: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Return (server_name/sni, resp_h, resp_p) for a row, best-effort per source."""
    if source == "suricata:eve.json":
        raw = row.get("tls")
        tls: dict[str, Any] = raw if isinstance(raw, dict) else {}
        return _cell(tls, "sni"), _cell(row, "dest_ip"), _cell(row, "dest_port")
    if source == "zeek:x509.log":
        return _cell(row, "san.dns"), None, None
    return _cell(row, "server_name"), _cell(row, "id.resp_h"), _cell(row, "id.resp_p")


class FsZeekLogs(Probe):
    """Ingest negotiated TLS/cert crypto from offline Zeek / Suricata IDS logs."""

    id = "fs.zeek.logs"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots

    def _roots(self) -> list[Path]:
        return self.roots if self.roots is not None else list(_DEFAULT_ROOTS)

    async def applies(self, ctx: ScanContext) -> bool:
        for root in self._roots():
            try:
                if root.exists():
                    return True
            except OSError:
                continue
        return False

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[tuple[str, str, str]] = set()
        emitted = 0
        for source, path in _iter_log_files(self._roots()):
            emitted = self._scan_file(source, path, emit, seen, emitted)
            if emitted >= _MAX_FINDINGS:
                emit(_truncation_finding(self.id))
                return

    def _scan_file(
        self,
        source: str,
        path: Path,
        emit: Emitter,
        seen: set[tuple[str, str, str]],
        emitted: int,
    ) -> int:
        analyze = {
            "zeek:ssl.log": _analyze_ssl,
            "zeek:x509.log": _analyze_x509,
            "suricata:eve.json": _analyze_suricata,
        }[source]
        rows = 0
        endpoints: set[str] = set()
        try:
            for row in _iter_rows(path):
                rows += 1
                server, resp_h, resp_p = _context(source, row)
                endpoints.add(server or resp_h or "-")
                for alg, cls, observed in analyze(row):
                    ep = server or resp_h or "-"
                    key = (ep, alg, source)
                    if key in seen:
                        continue
                    seen.add(key)
                    if emitted >= _MAX_FINDINGS:
                        return emitted
                    emit(_finding(self.id, source, path, alg, cls, observed, server, resp_h, resp_p))
                    emitted += 1
        except OSError:
            return emitted
        if rows:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"{path.name}: ingested {rows} {source} rows, {len(endpoints)} distinct endpoints",
                evidence={"source": source, "path": str(path), "rows": rows, "endpoints": len(endpoints)},
                confidence="medium",
            ))
        return emitted


def _finding(
    probe_id: str,
    source: str,
    path: Path,
    alg: str,
    cls: Classification,
    observed: str,
    server: str | None,
    resp_h: str | None,
    resp_p: str | None,
) -> Finding:
    evidence: dict[str, Any] = {
        "source": source,
        "path": str(path),
        "observed": observed,
        "confidence": "medium",
    }
    if server is not None:
        evidence["server_name" if source != "suricata:eve.json" else "sni"] = server
    if resp_h is not None:
        evidence["resp_h"] = resp_h
    if resp_p is not None:
        evidence["resp_p"] = resp_p
    endpoint = server or resp_h or "unknown"
    return Finding(
        probe_id=probe_id,
        algorithm=alg,
        classification=cls,
        severity=sev_for(cls),
        title=f"{path.name}: {source} {alg} observed ({endpoint})",
        evidence=evidence,
        confidence="medium",
    )


def _truncation_finding(probe_id: str) -> Finding:
    return Finding(
        probe_id=probe_id,
        algorithm="N/A",
        classification=Classification.INFO,
        severity=Severity.INFO,
        title=f"finding cap ({_MAX_FINDINGS}) reached — output truncated",
        evidence={"cap": _MAX_FINDINGS, "confidence": "medium"},
        confidence="medium",
    )


def _iter_log_files(roots: list[Path]) -> Iterator[tuple[str, Path]]:
    """Yield (source, path) for each relevant log file under roots, capped."""
    count = 0
    for root in roots:
        try:
            if not root.is_dir():
                continue
        except OSError:
            continue
        for source, pattern in _LOG_GLOBS:
            try:
                matches = sorted(root.rglob(pattern))
            except OSError:
                continue
            for path in matches:
                try:
                    if not path.is_file():
                        continue
                except OSError:
                    continue
                yield source, path
                count += 1
                if count >= _MAX_LOG_FILES:
                    return

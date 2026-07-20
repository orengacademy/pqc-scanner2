"""fs.db.crypto — scan databases for crypto material stored in columns.

Closes the "certs in DB columns" surface that commercial PQC tools (PQ Crypta)
cover: certificates, private keys, and public/ssh keys that applications stash
inside database rows (a TEXT/BLOB column holding a PEM cert, a private key
pasted into an `secrets` table, an `authorized_keys` blob, ...). Those never
show up in a filesystem cert walk, yet they are exactly the long-lived,
quantum-exposed key material an inventory must account for.

Self-contained: the only database engine touched is SQLite, opened read-only
through the standard-library `sqlite3` module — no third-party DB drivers. SQL
dump files are scanned as text. Every cert/key found is classified with the
same `cryptography` + `classify()` pipeline the filesystem cert probes use.

What it walks (ctx.scan_paths):

- SQLite database files, detected by the 16-byte magic ``SQLite format 3\\x00``
  (regardless of extension). Opened ``mode=ro&immutable=1`` so the scan can
  never mutate or lock the file. Every table's TEXT/BLOB cells are scanned for
  embedded PEM / OpenSSH markers.
- ``*.db`` / ``*.sqlite`` / ``*.sqlite3`` — tried as SQLite even without magic.
- ``*.sql`` / ``*.dump`` text dumps — scanned as text (INSERT statements often
  embed a PEM cert inline).

Per found material:

- CERTIFICATE PEM → parsed, key/sig algorithm + fingerprint → ``classify()``.
- PRIVATE KEY (any flavour) → a SANGAT_TINGGI / CRIT finding: a private key in
  a DB column is both a crypto-posture and a data-exposure problem. The finding
  is REDACTED — evidence carries only ``{path, table, column, key_type}`` and
  the raw key bytes / PEM are never stored in the finding.
- PUBLIC KEY PEM / ssh public-key line → algorithm classified and emitted.

Everything is guarded: a corrupt, locked, encrypted, or huge database yields no
findings and never raises. Per-value scan size, per-table row count, and
per-database finding count are all capped; when the finding cap is hit a
truncation note is emitted. Findings are de-duplicated by
(path, table, column, cert-fingerprint-or-key-type).
"""
from __future__ import annotations

import contextlib
import re
import sqlite3
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_private_key,
)
from cryptography.utils import CryptographyDeprecationWarning

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_SQLITE_MAGIC = b"SQLite format 3\x00"  # 16 bytes

# Extensions we try to open as SQLite even if the magic check missed them.
_SQLITE_EXTS = frozenset({".db", ".sqlite", ".sqlite3"})
# Text SQL dumps scanned line-by-line for embedded PEM.
_SQL_TEXT_EXTS = frozenset({".sql", ".dump"})

# --- caps (a giant / hostile DB must never hang or flood the scan) --------
_MAX_FINDINGS_PER_DB = 200          # findings emitted per database/file
_MAX_VALUE_BYTES = 1 * 1024 * 1024  # bytes of any single cell/value scanned
_MAX_ROWS_PER_TABLE = 50_000        # rows read per SQLite table
_MAX_TABLES = 4096                  # tables enumerated per SQLite DB
_MAX_TEXT_BYTES = 64 * 1024 * 1024  # bytes read from a .sql/.dump text file

# Directories never worth walking.
_EXCLUDE_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache",
})

# Any PEM block: label captured, END label must match BEGIN label.
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+?)-----.*?-----END \1-----",
    re.DOTALL,
)
# ssh public-key / authorized_keys lines.
_SSH_KEY_RE = re.compile(
    r"\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-[a-z0-9-]+)\s+[A-Za-z0-9+/=]{20,}",
)

# PEM private-key label → coarse key-type label (never the key bytes).
_PRIV_LABEL_MAP: dict[str, str] = {
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "EC",
    "DSA PRIVATE KEY": "DSA",
    "ENCRYPTED PRIVATE KEY": "encrypted-PKCS8",
    "PRIVATE KEY": "PKCS8",
    "OPENSSH PRIVATE KEY": "OpenSSH",
}
# ssh public-key type token → algorithm family.
_SSH_ALG_MAP: dict[str, str] = {
    "ssh-rsa": "RSA",
    "ssh-ed25519": "Ed25519",
    "ssh-dss": "DSA",
}


@dataclass(slots=True)
class _Hit:
    kind: str            # "cert" | "private_key" | "public_key" | "ssh_key"
    algorithm: str
    classification: Classification
    key_type: str
    dedup: str           # cert fingerprint (cert) or key-type token (keys)
    fingerprint: str | None = None


# --- material extraction (operates on decoded text; no I/O) ----------------


def _scan_value(text: str) -> list[_Hit]:
    """Return crypto-material hits found in a single decoded cell/value."""
    window = text[:_MAX_VALUE_BYTES]
    hits: list[_Hit] = []
    for m in _PEM_BLOCK_RE.finditer(window):
        label = m.group(1).strip()
        block = m.group(0)
        hit: _Hit | None
        if label == "CERTIFICATE":
            hit = _cert_hit(block)
        elif label.endswith("PRIVATE KEY"):
            hit = _private_key_hit(label, block)
        elif label == "PUBLIC KEY":
            hit = _public_key_hit(block)
        else:
            hit = None
        if hit is not None:
            hits.append(hit)
    for m in _SSH_KEY_RE.finditer(window):
        hits.append(_ssh_hit(m.group(1)))
    return hits


def _cert_hit(block: str) -> _Hit | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            cert = x509.load_pem_x509_certificate(block.encode("latin-1"))
        alg = _key_algorithm(cert.public_key())
        fp = sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    except Exception:
        return None
    return _Hit(
        kind="cert",
        algorithm=alg,
        classification=classify(alg),
        key_type="certificate",
        dedup=f"cert:{fp}",
        fingerprint=fp,
    )


def _private_key_hit(label: str, block: str) -> _Hit:
    """A private key stored in a DB is always CRIT — REDACTED, never the bytes."""
    key_type = _PRIV_LABEL_MAP.get(label, "private-key")
    alg = _try_private_alg(block, key_type)
    return _Hit(
        kind="private_key",
        algorithm=alg,
        classification=Classification.SANGAT_TINGGI,
        key_type=key_type,
        dedup=f"privkey:{key_type}",
    )


def _try_private_alg(block: str, key_type: str) -> str:
    """Best-effort precise algorithm name; falls back to the coarse family.

    Parses only to read the key's algorithm/size — the parsed object and the
    input block are discarded, never placed in a finding.
    """
    raw = block.encode("latin-1")
    try:
        key: object
        if key_type == "OpenSSH":
            key = load_ssh_private_key(raw, password=None)
        else:
            key = load_pem_private_key(raw, password=None)
        return _key_algorithm(key)
    except Exception:
        return {"RSA": "RSA", "EC": "ECDSA", "DSA": "DSA"}.get(key_type, key_type)


def _public_key_hit(block: str) -> _Hit | None:
    try:
        pk = load_pem_public_key(block.encode("latin-1"))
        alg = _key_algorithm(pk)
    except Exception:
        return None
    return _Hit(
        kind="public_key",
        algorithm=alg,
        classification=classify(alg),
        key_type="public-key",
        dedup=f"pubkey:{alg}",
    )


def _ssh_hit(token: str) -> _Hit:
    alg = "ECDSA" if token.startswith("ecdsa-sha2-") else _SSH_ALG_MAP.get(token, token)
    return _Hit(
        kind="ssh_key",
        algorithm=alg,
        classification=classify(alg),
        key_type=f"ssh:{token}",
        dedup=f"sshkey:{token}",
    )


def _key_algorithm(key: object) -> str:
    if isinstance(key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey):
        return f"ECDSA-{key.curve.name}"
    if isinstance(key, dsa.DSAPublicKey | dsa.DSAPrivateKey):
        return f"DSA-{key.key_size}"
    if isinstance(key, ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey | ed448.Ed448PrivateKey):
        return "Ed448"
    return type(key).__name__


# --- source iterators (yield (table, column, hit)) -------------------------


def _iter_sqlite_hits(path: Path) -> Iterator[tuple[str | None, str | None, _Hit]]:
    """Open a SQLite DB read-only and yield hits from every TEXT/BLOB cell."""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    except Exception:
        return
    try:
        try:
            names = [
                r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
        except Exception:
            return
        for table in names[:_MAX_TABLES]:
            yield from _iter_table_hits(con, table)
    finally:
        with contextlib.suppress(Exception):
            con.close()


def _iter_table_hits(
    con: sqlite3.Connection, table: str
) -> Iterator[tuple[str | None, str | None, _Hit]]:
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        cur = con.execute(f"SELECT * FROM {quoted}")  # name from sqlite_master, quoted/escaped
    except Exception:
        return
    try:
        columns = [d[0] for d in cur.description] if cur.description else []
    except Exception:
        return
    for row_no, row in enumerate(cur):
        if row_no >= _MAX_ROWS_PER_TABLE:
            break
        for col_idx, value in enumerate(row):
            text = _cell_to_text(value)
            if text is None:
                continue
            column = columns[col_idx] if col_idx < len(columns) else f"col{col_idx}"
            for hit in _scan_value(text):
                yield table, column, hit


def _iter_text_hits(path: Path) -> Iterator[tuple[str | None, str | None, _Hit]]:
    try:
        with path.open("rb") as fh:
            raw = fh.read(_MAX_TEXT_BYTES)
    except OSError:
        return
    text = raw.decode("latin-1", "ignore")
    for hit in _scan_value(text):
        yield None, None, hit


def _cell_to_text(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).decode("latin-1", "ignore")
    return None


# --- probe -----------------------------------------------------------------


class FsDbCrypto(Probe):
    """Scan databases (SQLite files, SQL dumps) for crypto material in columns."""

    id = "fs.db.crypto"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:storage", "bukukerja:storage")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots

    async def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.scan_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        roots = self.roots if self.roots is not None else ctx.scan_paths
        for path in _iter_files(roots):
            try:
                self._scan_path(path, emit)
            except Exception:  # pragma: no cover — defensive backstop, never raise
                continue

    def _scan_path(self, path: Path, emit: Emitter) -> None:
        head = _read_head(path)
        if head is None:
            return
        if head == _SQLITE_MAGIC:
            self._emit_source(emit, path, _iter_sqlite_hits(path))
            return
        suffix = path.suffix.lower()
        if suffix in _SQLITE_EXTS:
            self._emit_source(emit, path, _iter_sqlite_hits(path))
            return
        if suffix in _SQL_TEXT_EXTS:
            self._emit_source(emit, path, _iter_text_hits(path))

    def _emit_source(
        self,
        emit: Emitter,
        path: Path,
        hits: Iterator[tuple[str | None, str | None, _Hit]],
    ) -> None:
        seen: set[tuple[str | None, str | None, str]] = set()
        count = 0
        capped = False
        for table, column, hit in hits:
            key = (table, column, hit.dedup)
            if key in seen:
                continue
            seen.add(key)
            if count >= _MAX_FINDINGS_PER_DB:
                capped = True
                break
            emit(_finding(self.id, path, table, column, hit))
            count += 1
        if capped:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=sev_for(Classification.INFO),
                title=f"finding cap ({_MAX_FINDINGS_PER_DB}) reached — DB crypto output truncated",
                evidence={"path": str(path), "cap": _MAX_FINDINGS_PER_DB},
            ))


def _finding(
    probe_id: str, path: Path, table: str | None, column: str | None, hit: _Hit
) -> Finding:
    loc = f"{table}.{column}" if table is not None else "(sql-dump)"
    # REDACTION: for private keys the evidence is exactly this four-key dict —
    # no PEM, no base64, no parsed-key bytes ever reach the finding.
    evidence: dict[str, object] = {
        "path": str(path),
        "table": table,
        "column": column,
        "key_type": hit.key_type,
    }
    if hit.kind == "private_key":
        title = f"private key material stored in DB column {loc} ({hit.key_type})"
    else:
        if hit.fingerprint is not None:
            evidence["fingerprint"] = hit.fingerprint
        title = f"{hit.kind} in DB column {loc}: {hit.algorithm}"
    return Finding(
        probe_id=probe_id,
        algorithm=hit.algorithm,
        classification=hit.classification,
        severity=sev_for(hit.classification),
        title=title,
        evidence=evidence,
    )


# --- filesystem helpers ----------------------------------------------------


def _read_head(path: Path, n: int = 16) -> bytes | None:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return None


def _iter_files(roots: list[Path]) -> Iterator[Path]:
    for root in roots:
        try:
            if root.is_file():
                yield root
                continue
            if not root.is_dir():
                continue
            for p in root.rglob("*"):
                try:
                    if any(part in _EXCLUDE_DIRS for part in p.parts):
                        continue
                    if p.is_symlink() or not p.is_file():
                        continue
                except OSError:
                    continue
                yield p
        except OSError:
            continue

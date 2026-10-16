"""ScanBundle — one finished scan as a self-contained gzip JSON document.

What a host sends to the fleet daemon (`scan --report-to`) and what `ingest`
stores. Carries the scan row, the host identity, every finding with its
compliance views, and probe-error rows. Never key bytes (probes redact).
"""
from __future__ import annotations

import gzip
import json
import zlib
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from pqcscan.store.repo import Repo
from pqcscan.store.schema import FindingRow, FrameworkView

BUNDLE_SCHEMA_VERSION = 1
MAX_GZIP_BYTES = 8 * 1024 * 1024
MAX_RAW_BYTES = 50 * 1024 * 1024


class BundleInvalid(ValueError):  # noqa: N818 - name fixed by the fleet interface
    """Not a bundle we can read (bad gzip/JSON, unknown schema, missing field)."""


class BundleTooLarge(ValueError):  # noqa: N818 - name fixed by the fleet interface
    """Over the wire or decompressed cap."""


@dataclass(slots=True, frozen=True)
class HostIdentity:
    machine_id: str
    hostname: str
    os: str
    labels: dict[str, str] = field(default_factory=dict)
    agent_version: str = ""


@dataclass(slots=True)
class ScanBundle:
    schema_version: int
    scan_uuid: str
    host: HostIdentity
    scan: dict[str, Any]          # started_at, finished_at (ISO or None), mode, status, probe_versions, tool_versions
    findings: list[dict[str, Any]]


def _iso(v: datetime | date | None) -> str | None:
    return v.isoformat() if v is not None else None


def dump_bundle(repo: Repo, scan_id: int, host: HostIdentity) -> bytes:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings: list[dict[str, Any]] = []
    with Session(repo.engine) as s:
        rows = s.execute(select(FindingRow).where(FindingRow.scan_id == scan_id)
                         .order_by(FindingRow.id)).scalars().all()
        for r in rows:
            views = s.execute(select(FrameworkView).where(FrameworkView.finding_id == r.id)).scalars().all()
            findings.append({
                "probe_id": r.probe_id, "algorithm": r.algorithm, "classification": r.classification,
                "severity": r.severity, "title": r.title, "evidence": r.evidence or {},
                "remediation": r.remediation or {}, "created_at": _iso(r.created_at),
                "views": [{"framework": v.framework, "clause": v.clause, "verdict": v.verdict,
                           "deadline": _iso(v.deadline)} for v in views],
            })
    doc = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "scan_uuid": scan.scan_uuid,
        "host": asdict(host),
        "scan": {
            "started_at": _iso(scan.started_at), "finished_at": _iso(scan.finished_at),
            "mode": scan.mode, "status": scan.status,
            "probe_versions": scan.probe_versions or {}, "tool_versions": scan.tool_versions or {},
        },
        "findings": findings,
    }
    raw = json.dumps(doc, separators=(",", ":"), default=str).encode()
    if len(raw) > MAX_RAW_BYTES:
        raise BundleTooLarge(f"bundle is {len(raw)} bytes raw; cap {MAX_RAW_BYTES}")
    return gzip.compress(raw, compresslevel=6)


def load_bundle(data: bytes) -> ScanBundle:
    if len(data) > MAX_GZIP_BYTES:
        raise BundleTooLarge(f"bundle is {len(data)} bytes gzip; cap {MAX_GZIP_BYTES}")
    # Stream-decompress so a gzip bomb cannot allocate past the raw cap.
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = d.decompress(data, MAX_RAW_BYTES + 1)
    except zlib.error as e:
        raise BundleInvalid(f"bad gzip: {e}") from e
    if len(raw) > MAX_RAW_BYTES or d.unconsumed_tail:
        raise BundleTooLarge(f"bundle decompresses past {MAX_RAW_BYTES} bytes")
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise BundleInvalid(f"bad json: {e}") from e
    if not isinstance(doc, dict) or doc.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise BundleInvalid("unsupported or missing schema_version")
    try:
        h = doc["host"]
        host = HostIdentity(machine_id=str(h["machine_id"]), hostname=str(h.get("hostname", "")),
                            os=str(h.get("os", "")), labels=dict(h.get("labels") or {}),
                            agent_version=str(h.get("agent_version", "")))
        return ScanBundle(schema_version=1, scan_uuid=str(doc["scan_uuid"]), host=host,
                          scan=dict(doc["scan"]), findings=list(doc.get("findings") or []))
    except (KeyError, TypeError) as e:
        raise BundleInvalid(f"missing field: {e}") from e

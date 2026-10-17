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
MAX_FINDINGS = 200_000
# Fleet attribution (evidence["_fleet"]) is set by the collector, never by the agent.
# evidence["host"] is the scan target (net probes) and stays.
_SERVER_EVIDENCE_KEYS = frozenset({"_fleet"})


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


def _req_str(d: dict[str, Any], key: str, *, nonempty: bool = False) -> str:
    """Identity field: must be a str (non-empty when `nonempty`); absent optional fields default to ''."""
    v = d.get(key) if nonempty else d.get(key, "")
    if not isinstance(v, str) or (nonempty and not v):
        raise BundleInvalid(f"{key} must be a {'non-empty ' if nonempty else ''}string")
    return v


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
    except (ValueError, RecursionError) as e:  # deeply nested input can exhaust the recursion limit
        raise BundleInvalid(f"bad json: {e}") from e
    if not isinstance(doc, dict) or doc.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise BundleInvalid("unsupported or missing schema_version")
    h, scan = doc.get("host"), doc.get("scan")
    findings = doc.get("findings")
    labels = h.get("labels") if isinstance(h, dict) else None
    findings = [] if findings is None else findings
    labels = {} if labels is None else labels
    if not (isinstance(h, dict) and isinstance(scan, dict) and isinstance(labels, dict)
            and isinstance(findings, list)):
        raise BundleInvalid("host, host.labels and scan must be objects and findings a list")
    if len(findings) > MAX_FINDINGS:
        raise BundleTooLarge(f"bundle has {len(findings)} findings; cap {MAX_FINDINGS}")
    if not all(isinstance(f, dict) for f in findings):
        raise BundleInvalid("every finding must be an object")
    for f in findings:
        ev = f.get("evidence")
        if isinstance(ev, dict):
            for k in _SERVER_EVIDENCE_KEYS:
                ev.pop(k, None)
    if not all(isinstance(v, str) for v in labels.values()):
        raise BundleInvalid("host.labels values must be strings")
    host = HostIdentity(machine_id=_req_str(h, "machine_id", nonempty=True),
                        hostname=_req_str(h, "hostname"), os=_req_str(h, "os"),
                        labels=dict(labels), agent_version=_req_str(h, "agent_version"))
    return ScanBundle(schema_version=BUNDLE_SCHEMA_VERSION, scan_uuid=_req_str(doc, "scan_uuid", nonempty=True),
                      host=host, scan=dict(scan), findings=findings)

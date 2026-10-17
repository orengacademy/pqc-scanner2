# pqcscan Fleet / Agent Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let thousands of hosts push their pqcscan results to one daemon that keeps per-host history, a fleet view, drift findings and fleet-wide exports, using the existing binary as the agent.

**Architecture:** The existing `pqcscan scan` gains `--report-to`: after a scan it serialises the scan into a gzip JSON `ScanBundle` and POSTs it with a per-agent bearer token to the existing FastAPI daemon, which gains `/api/agents/enroll`, `/api/ingest`, a `hosts` table, `fleet_summary()` and a `/fleet` page. `pqcscan agent` is a thin loop (enroll, spool, backoff) around that one-shot path. Fleet exports materialise a temporary rollup scan so every renderer stays unchanged.

**Tech Stack:** Python 3.11, click, FastAPI, SQLAlchemy 2 (SQLite WAL default, Postgres optional), httpx (already a dependency), Jinja2 UI, pytest + pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-10-16-pqcscan-fleet-agent-design.md`

## Global Constraints

- Python `>=3.11`; no new base dependencies (httpx, sqlalchemy, fastapi, click already present). `psycopg[binary]` only under a new `[fleet-pg]` extra.
- Line length 120, `ruff check src/ tests/` and `mypy src/pqcscan` must stay clean after every task.
- Every commit: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider <changed tests>`; before each phase tag the full suite (`PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider`) must pass.
- Commit messages: `<type>: <imperative summary>` and end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Probes already redact key bytes; bundles carry findings only. Token files and spool dirs are created `0600`/`0700`.
- Bundle hard caps: 8 MB gzip on the wire, 50 MB after decompression. Per-agent ingest rate: 1 bundle per 60 s.
- Single tenant per daemon. SQLite default; the only SQLite-specific code is the PRAGMA listener in `store/repo.py`, which must become conditional on `engine.dialect.name == "sqlite"`.
- Work on branch `feat/fleet-agent` (already exists, holds the spec). Tags: v0.10.0 after Task 9, v0.10.1 after Task 12, v0.10.2 after Task 16.

---

## File structure

| File | Status | Responsibility |
|---|---|---|
| `src/pqcscan/store/schema.py` | modify | `Host` model; `Scan.host_id`, `Scan.scan_uuid` |
| `src/pqcscan/store/migrations.py` | modify | `create_all` + idempotent `ALTER TABLE scans ADD COLUMN` for pre-fleet DBs + unique index on `scan_uuid` |
| `src/pqcscan/store/repo.py` | modify | SQLite-only pragmas; `scan_uuid` on create; host CRUD; `ingest_bundle`; `fleet_summary`; `host_history`; `prune_scans`; `materialize_fleet_rollup`; `delete_scan`; `drift_findings` (phase 3) |
| `src/pqcscan/store/bundle.py` | create | `ScanBundle` dataclass, `dump_bundle(repo, scan_id, host) -> bytes`, `load_bundle(data) -> ScanBundle`, caps |
| `src/pqcscan/util/hostid.py` | create | `machine_id()`, `host_identity(labels)` cross-OS |
| `src/pqcscan/daemon/fleet.py` | create | enroll / ingest / revoke / fleet JSON router + agent-token auth + rate limit |
| `src/pqcscan/daemon/app.py` | modify | `enroll_token` param, mount fleet router, exempt fleet paths from the cookie guard |
| `src/pqcscan/cli/daemon_cmd.py` | modify | `--enroll-token` (env `PQCSCAN_ENROLL_TOKEN`) |
| `src/pqcscan/cli/_report.py` | create | `ensure_agent_token`, `post_bundle`, `spool_bundle`, `flush_spool` (httpx) |
| `src/pqcscan/cli/scan.py` | modify | `run_local_scan()` extracted; `--report-to --enroll-token --agent-token --labels --state-dir --ca-cert --insecure` |
| `src/pqcscan/cli/fleet.py` | modify | `agents list|revoke`, `fleet summary|prune` |
| `src/pqcscan/cli/export.py` | modify | `--scan fleet` |
| `src/pqcscan/cli/agent.py` | create (phase 2) | `pqcscan agent` loop |
| `src/pqcscan/ui/routes.py`, `templates/fleet.html`, `templates/fleet_host.html`, `ui/i18n.py`, `templates/base.html` | modify/create (phase 2) | `/fleet`, `/fleet/{host_id}` |
| `packaging/fleet/*` , `docs/FLEET.md` | create (phase 2) | systemd timer/service, Windows Task Scheduler, Ansible, BigFix, osquery/Wazuh notes |
| `src/pqcscan/core/parity.py` | create (phase 3) | host-agnostic parity key |
| `src/pqcscan/core/agility.py` | create (phase 3) | crypto-agility score |
| `src/pqcscan/renderers/_report_context.py`, `xlsx_bukukerja.py` | modify (phase 3) | labels → Mosca inputs; agility column |

---

## Phase 1 — bundle, ingest, hosts, fleet exports (v0.10.0)

### Task 1: Schema — `hosts` table, `scans.host_id`, `scans.scan_uuid`, migration for existing DBs

**Files:**
- Modify: `src/pqcscan/store/schema.py` (after `class Scan`, and two new columns inside `Scan`)
- Modify: `src/pqcscan/store/migrations.py`
- Modify: `src/pqcscan/store/repo.py:18-43` (pragma listener), `:47-66` (`create_scan`), `:73-101` (`begin_scan_if_idle`)
- Test: `tests/unit/test_fleet_schema.py`

**Interfaces:**
- Produces: `Host` ORM model with columns `id, machine_id (unique), hostname, os, labels (JSON), agent_version, first_seen, last_seen, token_hash (unique, nullable), revoked (bool)`; `Scan.host_id: int|None`, `Scan.scan_uuid: str|None`; `migrations.apply(engine)` upgrades a pre-fleet DB in place; `Repo.create_scan(..., scan_uuid=None)` auto-generates a UUID4 when None.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_fleet_schema.py
"""Fleet schema: hosts table, scans.host_id / scan_uuid, and in-place upgrade of pre-fleet DBs."""
import sqlite3
import uuid
from pathlib import Path

from sqlalchemy import inspect

from pqcscan.store.repo import Repo


def test_new_db_has_hosts_table_and_scan_columns(tmp_db_path: Path):
    repo = Repo(tmp_db_path); repo.init_schema()
    insp = inspect(repo.engine)
    assert "hosts" in insp.get_table_names()
    scan_cols = {c["name"] for c in insp.get_columns("scans")}
    assert {"host_id", "scan_uuid"} <= scan_cols
    host_cols = {c["name"] for c in insp.get_columns("hosts")}
    assert {"machine_id", "hostname", "os", "labels", "agent_version",
            "first_seen", "last_seen", "token_hash", "revoked"} <= host_cols


def test_create_scan_gets_a_uuid(tmp_db_path: Path):
    repo = Repo(tmp_db_path); repo.init_schema()
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    s = repo.get_scan(sid)
    assert s is not None and s.scan_uuid and uuid.UUID(s.scan_uuid)
    sid2 = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    assert repo.get_scan(sid2).scan_uuid != s.scan_uuid


def test_pre_fleet_db_is_upgraded_in_place(tmp_path: Path):
    # A 0.9.x DB: scans table without host_id / scan_uuid, no hosts table.
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE scans (id INTEGER PRIMARY KEY, started_at DATETIME, finished_at DATETIME,
            host_fingerprint VARCHAR(128), mode VARCHAR(8), status VARCHAR(16), label VARCHAR(128),
            probe_versions JSON, tool_versions JSON);
        INSERT INTO scans (started_at, mode, status, probe_versions, tool_versions)
            VALUES ('2026-01-01 00:00:00', 'user', 'done', '{}', '{}');
    """)
    con.commit(); con.close()
    repo = Repo(db); repo.init_schema()
    scan_cols = {c["name"] for c in inspect(repo.engine).get_columns("scans")}
    assert {"host_id", "scan_uuid"} <= scan_cols
    assert repo.get_scan(1).scan_uuid is None          # old rows keep NULL
    repo.init_schema()                                  # idempotent second run
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    assert repo.get_scan(sid).scan_uuid
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_fleet_schema.py`
Expected: 3 failed (`hosts` not in tables; `scan_uuid` attribute missing).

- [ ] **Step 3: Add the model and columns**

In `src/pqcscan/store/schema.py`, add `Boolean` to the sqlalchemy import, add two columns to `Scan` after `tool_versions`, and add the `Host` class after `Scan`:

```python
# inside class Scan, after tool_versions:
    # Fleet: which enrolled host produced this scan (NULL for a local scan),
    # and a stable id so a re-posted bundle is not stored twice.
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"), nullable=True, index=True)
    scan_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True)


class Host(Base):
    """An enrolled agent host (fleet mode). One row per machine id."""
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    machine_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(32), default="")
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # SHA-256 hex of the per-agent bearer token; the token itself is never stored.
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
```

Because `Scan` references `hosts.id`, `Host` must be defined before `Scan` is *mapped*; SQLAlchemy resolves string FKs at `create_all`, so defining `Host` after `Scan` in the file is fine.

- [ ] **Step 4: Make migrations add the columns to old DBs**

Replace `src/pqcscan/store/migrations.py`:

```python
from __future__ import annotations

from sqlalchemy import Engine, inspect, text

from pqcscan.store.schema import Base

# Columns added after a table first shipped. create_all() never alters an
# existing table, so each (table, column, DDL type) here is applied with an
# idempotent ALTER TABLE on DBs created before the column existed.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("scans", "host_id", "INTEGER"),
    ("scans", "scan_uuid", "VARCHAR(36)"),
)


def apply(engine: Engine) -> None:
    """Create all tables, then add any columns missing from pre-existing tables. Idempotent."""
    Base.metadata.create_all(engine)
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, column, ddl_type in _ADDED_COLUMNS:
            present = {c["name"] for c in insp.get_columns(table)}
            if column not in present:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_scans_scan_uuid ON scans (scan_uuid)"
        ))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_host_id ON scans (host_id)"))
```

(SQLite allows multiple NULLs in a unique index, so legacy rows with `scan_uuid IS NULL` coexist.)

- [ ] **Step 5: Generate the UUID on scan creation and keep pragmas SQLite-only**

In `src/pqcscan/store/repo.py`: add `import uuid` at the top; in `__init__` wrap the listener registration:

```python
        if self.engine.dialect.name == "sqlite":
            @event.listens_for(self.engine, "connect")
            def _set_sqlite_pragmas(dbapi_conn, _record) -> None:
                ...  # unchanged body
```

Add `scan_uuid: str | None = None` as a keyword parameter to both `create_scan` and `begin_scan_if_idle`, and pass `scan_uuid=scan_uuid or str(uuid.uuid4())` into each `Scan(...)` constructor.

- [ ] **Step 6: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_fleet_schema.py tests/unit/test_baselines_diff.py tests/unit/test_backlog_fixes.py`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/pqcscan/store/schema.py src/pqcscan/store/migrations.py src/pqcscan/store/repo.py tests/unit/test_fleet_schema.py
git commit -m "feat(store): hosts table, scans.host_id/scan_uuid, in-place migration for pre-fleet DBs

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: `store/bundle.py` — ScanBundle dump/load

**Files:**
- Create: `src/pqcscan/store/bundle.py`
- Test: `tests/unit/test_bundle.py`

**Interfaces:**
- Produces:
  - `BUNDLE_SCHEMA_VERSION = 1`, `MAX_GZIP_BYTES = 8 * 1024 * 1024`, `MAX_RAW_BYTES = 50 * 1024 * 1024`
  - `@dataclass HostIdentity(machine_id: str, hostname: str, os: str, labels: dict[str, str], agent_version: str)`
  - `@dataclass ScanBundle(schema_version: int, scan_uuid: str, host: HostIdentity, scan: dict, findings: list[dict])` where each finding dict has keys `probe_id, algorithm, classification, severity, title, evidence, remediation, created_at` (ISO) and `views: list[{framework, clause, verdict, deadline}]`
  - `dump_bundle(repo: Repo, scan_id: int, host: HostIdentity) -> bytes` (gzip JSON; raises `BundleTooLarge` over `MAX_RAW_BYTES`)
  - `load_bundle(data: bytes) -> ScanBundle` (raises `BundleTooLarge`, `BundleInvalid`)

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_bundle.py
"""ScanBundle round-trip: everything a host scan produced survives dump -> load."""
import gzip
import json
from datetime import date

import pytest

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import (
    MAX_GZIP_BYTES, BundleInvalid, BundleTooLarge, HostIdentity, dump_bundle, load_bundle,
)
from pqcscan.store.repo import Repo

HOST = HostIdentity(machine_id="m-1", hostname="web01", os="linux",
                    labels={"env": "prod"}, agent_version="0.10.0")


def _seed(repo: Repo) -> int:
    sid = repo.create_scan(mode="root", probe_versions={"p": "1"}, tool_versions={})
    fid = repo.record_finding(sid, Finding(
        probe_id="fs.cert.x509", algorithm="RSA-2048", classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT, title="weak cert", evidence={"path": "/etc/x.pem"},
        remediation={"replacement": "ML-DSA-65"},
    ))
    repo.record_framework_view(fid, framework="cnsa2", clause="CNSA2:RSA", verdict="non-compliant",
                               deadline=date(2030, 12, 31))
    repo.record_probe_error(sid, probe_id="net.tls.https", message="timeout")
    repo.finish_scan(sid, status="done")
    return sid


def test_round_trip(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    sid = _seed(repo)
    data = dump_bundle(repo, sid, HOST)
    b = load_bundle(data)
    assert b.schema_version == 1
    assert b.scan_uuid == repo.get_scan(sid).scan_uuid
    assert b.host == HOST
    assert b.scan["status"] == "done" and b.scan["mode"] == "root"
    assert b.scan["probe_versions"] == {"p": "1"}
    assert len(b.findings) == 2                             # finding + probe-error row
    f = next(x for x in b.findings if x["probe_id"] == "fs.cert.x509")
    assert f["evidence"] == {"path": "/etc/x.pem"} and f["classification"] == "sangat-tinggi"
    assert f["views"] == [{"framework": "cnsa2", "clause": "CNSA2:RSA",
                           "verdict": "non-compliant", "deadline": "2030-12-31"}]


def test_is_gzip_json(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    data = dump_bundle(repo, _seed(repo), HOST)
    doc = json.loads(gzip.decompress(data))
    assert doc["schema_version"] == 1 and doc["host"]["machine_id"] == "m-1"


def test_load_rejects_garbage_and_wrong_version():
    with pytest.raises(BundleInvalid):
        load_bundle(b"not gzip")
    with pytest.raises(BundleInvalid):
        load_bundle(gzip.compress(json.dumps({"schema_version": 99}).encode()))


def test_load_rejects_oversize():
    big = gzip.compress(b"\x00" * (MAX_GZIP_BYTES + 1))
    with pytest.raises(BundleTooLarge):
        load_bundle(b"\x1f\x8b" + b"\x00" * (MAX_GZIP_BYTES + 1))
    with pytest.raises(BundleTooLarge):
        load_bundle(big)  # decompresses past MAX_RAW_BYTES? no, 8 MB raw — exercise raw cap below
    zeros = gzip.compress(b"{" + b" " * (50 * 1024 * 1024 + 10) + b"}")
    with pytest.raises(BundleTooLarge):
        load_bundle(zeros)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_bundle.py`
Expected: ImportError on `pqcscan.store.bundle`.

- [ ] **Step 3: Implement `store/bundle.py`**

```python
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


class BundleInvalid(ValueError):
    """Not a bundle we can read (bad gzip/JSON, unknown schema, missing field)."""


class BundleTooLarge(ValueError):
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_bundle.py`
Expected: 4 passed. (If `test_load_rejects_oversize`'s second `load_bundle(big)` does not raise because 8 MB of zeros gzips to ~8 KB and decompresses under the raw cap, delete that one line — the other two assertions cover both caps.)

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/store/bundle.py tests/unit/test_bundle.py
git commit -m "feat(store): ScanBundle gzip-JSON dump/load with wire and raw size caps

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Repo — host CRUD, `ingest_bundle`, `fleet_summary`, `host_history`, `prune_scans`, `delete_scan`, `materialize_fleet_rollup`

**Files:**
- Modify: `src/pqcscan/store/repo.py` (append methods at the end of `class Repo`)
- Test: `tests/unit/test_fleet_repo.py`

**Interfaces:**
- Produces (all on `Repo`):
  - `upsert_host(identity: HostIdentity, *, token_hash: str | None = None) -> Host` (insert or update hostname/os/labels/agent_version/last_seen; sets token_hash only when given)
  - `get_host(host_id: int) -> Host | None`, `get_host_by_machine_id(machine_id) -> Host | None`, `get_host_by_token_hash(h) -> Host | None`, `list_hosts() -> list[Host]`, `revoke_host(host_id) -> bool`
  - `ingest_bundle(bundle: ScanBundle, host_id: int) -> IngestResult` with `@dataclass IngestResult(scan_id: int, stored_findings: int, stored_views: int, duplicate: bool)`; idempotent on `scan_uuid`; one transaction
  - `@dataclass HostSummary(host: Host, scan_id: int | None, finished_at: datetime | None, readiness: int | None, crit: int, high: int, total: int)`; `fleet_summary() -> list[HostSummary]` (latest `done` scan per host, ordered by hostname)
  - `host_history(host_id, limit=50) -> list[Scan]`
  - `prune_scans(keep_per_host: int) -> int` (deletes oldest scans per host beyond N, with their findings and views; returns scans deleted)
  - `delete_scan(scan_id) -> None`
  - `materialize_fleet_rollup() -> int | None` (new scan `label="fleet-rollup"`, `host_fingerprint="fleet"`, findings = latest done scan per host with `evidence["host"]=hostname`; returns id or None when no hosts)

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_fleet_repo.py
"""Fleet store: host upsert, idempotent ingest, summary, history, pruning, rollup."""
import gzip
import json
from datetime import date

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo

WEB01 = HostIdentity(machine_id="m-web01", hostname="web01", os="linux", labels={"env": "prod"})
WEB02 = HostIdentity(machine_id="m-web02", hostname="web02", os="linux", labels={"env": "dr"})


def _bundle(src: Repo, host: HostIdentity, algs: list[str], *, uuid: str | None = None) -> "ScanBundle":
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={}, scan_uuid=uuid)
    for a in algs:
        fid = src.record_finding(sid, Finding(
            probe_id="fs.cert.x509", algorithm=a, classification=Classification.SANGAT_TINGGI,
            severity=Severity.CRIT, title=f"{a} cert"))
        src.record_framework_view(fid, framework="cnsa2", clause="c", verdict="non-compliant", deadline=None)
    src.finish_scan(sid, status="done")
    return load_bundle(dump_bundle(src, sid, host))


def test_upsert_host_inserts_then_updates(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    h1 = repo.upsert_host(WEB01, token_hash="abc")
    h2 = repo.upsert_host(HostIdentity(machine_id="m-web01", hostname="web01.new", os="linux",
                                       labels={"env": "prod", "tier": "1"}, agent_version="0.10.0"))
    assert h1.id == h2.id and h2.hostname == "web01.new" and h2.labels["tier"] == "1"
    assert repo.get_host_by_token_hash("abc").id == h1.id        # token kept when not re-given
    assert repo.get_host_by_machine_id("m-web01").id == h1.id
    assert repo.revoke_host(h1.id) is True and repo.get_host(h1.id).revoked is True


def test_ingest_is_single_transaction_and_idempotent(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    b = _bundle(src, WEB01, ["RSA-2048", "RSA-1024"])
    r1 = fleet.ingest_bundle(b, host.id)
    assert (r1.stored_findings, r1.stored_views, r1.duplicate) == (2, 2, False)
    scan = fleet.get_scan(r1.scan_id)
    assert scan.host_id == host.id and scan.scan_uuid == b.scan_uuid and scan.status == "done"
    assert {v.framework for v in fleet.list_framework_views(r1.scan_id)} == {"cnsa2"}
    r2 = fleet.ingest_bundle(b, host.id)
    assert r2.duplicate is True and r2.scan_id == r1.scan_id
    assert len(fleet.list_scans()) == 1


def test_fleet_summary_latest_done_scan_per_host(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h1 = fleet.upsert_host(WEB01); h2 = fleet.upsert_host(WEB02)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-1024"]), h1.id)
    latest = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048", "ECDSA-P256"]), h1.id)
    fleet.ingest_bundle(_bundle(src, WEB02, []), h2.id)
    rows = {s.host.hostname: s for s in fleet.fleet_summary()}
    assert rows["web01"].scan_id == latest.scan_id and rows["web01"].crit == 2 and rows["web01"].total == 2
    assert rows["web02"].total == 0 and rows["web02"].readiness == 100
    assert [s.id for s in fleet.host_history(h1.id)][0] == latest.scan_id   # newest first


def test_prune_keeps_n_per_host(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    ids = [fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id).scan_id for _ in range(5)]
    assert fleet.prune_scans(keep_per_host=2) == 3
    left = [s.id for s in fleet.host_history(h.id)]
    assert sorted(left) == sorted(ids[-2:])
    assert fleet.list_findings(ids[0]) == []                   # findings gone with the scan


def test_materialize_fleet_rollup_unions_latest_per_host(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    assert fleet.materialize_fleet_rollup() is None
    h1 = fleet.upsert_host(WEB01); h2 = fleet.upsert_host(WEB02)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-1024"]), h1.id)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h1.id)      # latest for web01
    fleet.ingest_bundle(_bundle(src, WEB02, ["ECDSA-P256"]), h2.id)
    rid = fleet.materialize_fleet_rollup()
    rows = fleet.list_findings(rid)
    assert sorted((r.algorithm, r.evidence["host"]) for r in rows) == [("ECDSA-P256", "web02"), ("RSA-2048", "web01")]
    assert fleet.get_scan(rid).label == "fleet-rollup"
    fleet.delete_scan(rid)
    assert fleet.get_scan(rid) is None and fleet.list_findings(rid) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_fleet_repo.py`
Expected: AttributeError `Repo` has no `upsert_host`.

- [ ] **Step 3: Implement the methods**

Append to `src/pqcscan/store/repo.py` (imports at top: `from dataclasses import dataclass`, `from datetime import datetime`, `from sqlalchemy import delete, func`, `from pqcscan.store.schema import Host`, and under `if TYPE_CHECKING:` `from pqcscan.store.bundle import HostIdentity, ScanBundle`):

```python
@dataclass(slots=True)
class IngestResult:
    scan_id: int
    stored_findings: int
    stored_views: int
    duplicate: bool


@dataclass(slots=True)
class HostSummary:
    host: Host
    scan_id: int | None
    finished_at: datetime | None
    readiness: int | None
    crit: int
    high: int
    total: int
```

and inside `class Repo`:

```python
    # ------------------------------------------------------------------ fleet
    def upsert_host(self, identity: HostIdentity, *, token_hash: str | None = None) -> Host:
        with Session(self.engine) as s:
            h = s.execute(select(Host).where(Host.machine_id == identity.machine_id)).scalar_one_or_none()
            if h is None:
                h = Host(machine_id=identity.machine_id)
                s.add(h)
            h.hostname = identity.hostname or h.hostname
            h.os = identity.os or h.os
            h.labels = {**(h.labels or {}), **identity.labels}
            h.agent_version = identity.agent_version or h.agent_version
            h.last_seen = utcnow()
            if token_hash is not None:
                h.token_hash = token_hash
                h.revoked = False
            s.commit()
            s.refresh(h)
            s.expunge(h)
            return h

    def get_host(self, host_id: int) -> Host | None:
        with Session(self.engine) as s:
            return s.get(Host, host_id)

    def get_host_by_machine_id(self, machine_id: str) -> Host | None:
        with Session(self.engine) as s:
            return s.execute(select(Host).where(Host.machine_id == machine_id)).scalar_one_or_none()

    def get_host_by_token_hash(self, token_hash: str) -> Host | None:
        with Session(self.engine) as s:
            return s.execute(select(Host).where(Host.token_hash == token_hash)).scalar_one_or_none()

    def list_hosts(self) -> list[Host]:
        with Session(self.engine) as s:
            return list(s.execute(select(Host).order_by(Host.hostname, Host.id)).scalars())

    def revoke_host(self, host_id: int) -> bool:
        with Session(self.engine) as s:
            h = s.get(Host, host_id)
            if h is None:
                return False
            h.revoked = True
            h.token_hash = None
            s.commit()
            return True

    def ingest_bundle(self, bundle: ScanBundle, host_id: int) -> IngestResult:
        """Store one bundle in a single transaction; a repeated scan_uuid is a no-op."""
        with Session(self.engine) as s:
            existing = s.execute(select(Scan.id).where(Scan.scan_uuid == bundle.scan_uuid)).scalar_one_or_none()
            if existing is not None:
                return IngestResult(scan_id=existing, stored_findings=0, stored_views=0, duplicate=True)
            sc = bundle.scan
            scan = Scan(
                started_at=_parse_dt(sc.get("started_at")) or utcnow(),
                finished_at=_parse_dt(sc.get("finished_at")),
                host_fingerprint=bundle.host.hostname, mode=str(sc.get("mode", "user")),
                status=str(sc.get("status", "done")), label=None,
                probe_versions=dict(sc.get("probe_versions") or {}),
                tool_versions=dict(sc.get("tool_versions") or {}),
                host_id=host_id, scan_uuid=bundle.scan_uuid,
            )
            s.add(scan)
            s.flush()
            n_f = n_v = 0
            for f in bundle.findings:
                row = FindingRow(
                    scan_id=scan.id, probe_id=str(f["probe_id"]), algorithm=str(f.get("algorithm", "N/A")),
                    classification=str(f.get("classification", "info")), severity=str(f.get("severity", "info")),
                    title=str(f.get("title", "")), evidence=dict(f.get("evidence") or {}),
                    remediation=dict(f.get("remediation") or {}),
                    created_at=_parse_dt(f.get("created_at")) or utcnow(),
                )
                s.add(row)
                s.flush()
                n_f += 1
                for v in f.get("views") or []:
                    s.add(FrameworkView(finding_id=row.id, framework=str(v["framework"]), clause=str(v["clause"]),
                                        verdict=str(v["verdict"]),
                                        deadline=date.fromisoformat(v["deadline"]) if v.get("deadline") else None))
                    n_v += 1
            h = s.get(Host, host_id)
            if h is not None:
                h.last_seen = utcnow()
            s.commit()
            return IngestResult(scan_id=scan.id, stored_findings=n_f, stored_views=n_v, duplicate=False)

    def fleet_summary(self) -> list[HostSummary]:
        from pqcscan.core.bands import count_bands, readiness_score
        out: list[HostSummary] = []
        with Session(self.engine) as s:
            for h in s.execute(select(Host).order_by(Host.hostname, Host.id)).scalars().all():
                latest = s.execute(
                    select(Scan).where(Scan.host_id == h.id, Scan.status == "done")
                    .order_by(Scan.started_at.desc(), Scan.id.desc()).limit(1)
                ).scalar_one_or_none()
                s.expunge(h)
                if latest is None:
                    out.append(HostSummary(h, None, None, None, 0, 0, 0))
                    continue
                rows = s.execute(select(FindingRow).where(FindingRow.scan_id == latest.id)).scalars().all()
                out.append(HostSummary(
                    host=h, scan_id=latest.id, finished_at=latest.finished_at,
                    readiness=readiness_score(count_bands(rows)),
                    crit=sum(1 for r in rows if r.severity == "crit"),
                    high=sum(1 for r in rows if r.severity == "high"), total=len(rows),
                ))
        return out

    def host_history(self, host_id: int, limit: int = 50) -> list[Scan]:
        with Session(self.engine) as s:
            return list(s.execute(select(Scan).where(Scan.host_id == host_id)
                                  .order_by(Scan.started_at.desc(), Scan.id.desc()).limit(limit)).scalars())

    def delete_scan(self, scan_id: int) -> None:
        with Session(self.engine) as s:
            fids = select(FindingRow.id).where(FindingRow.scan_id == scan_id)
            s.execute(delete(FrameworkView).where(FrameworkView.finding_id.in_(fids)))
            s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
            s.execute(delete(Baseline).where(Baseline.scan_id == scan_id))
            s.execute(delete(Scan).where(Scan.id == scan_id))
            s.commit()

    def prune_scans(self, keep_per_host: int) -> int:
        deleted = 0
        with Session(self.engine) as s:
            host_ids = list(s.execute(select(Host.id)).scalars())
        for hid in host_ids:
            ids = [sc.id for sc in self.host_history(hid, limit=10_000)]
            for sid in ids[keep_per_host:]:
                self.delete_scan(sid)
                deleted += 1
        return deleted

    def materialize_fleet_rollup(self) -> int | None:
        """Temporary scan = latest done scan of every host, evidence['host'] set. Caller deletes it."""
        summary = [x for x in self.fleet_summary() if x.scan_id is not None]
        if not summary:
            return None
        with Session(self.engine) as s:
            roll = Scan(started_at=utcnow(), finished_at=utcnow(), host_fingerprint="fleet", mode="user",
                        status="done", label="fleet-rollup", probe_versions={},
                        tool_versions={"hosts": len(summary)}, scan_uuid=str(uuid.uuid4()))
            s.add(roll)
            s.flush()
            for x in summary:
                for r in s.execute(select(FindingRow).where(FindingRow.scan_id == x.scan_id)).scalars().all():
                    nf = FindingRow(scan_id=roll.id, probe_id=r.probe_id, algorithm=r.algorithm,
                                    classification=r.classification, severity=r.severity, title=r.title,
                                    evidence={**(r.evidence or {}), "host": x.host.hostname},
                                    remediation=r.remediation, created_at=r.created_at)
                    s.add(nf)
                    s.flush()
                    for v in s.execute(select(FrameworkView).where(FrameworkView.finding_id == r.id)).scalars():
                        s.add(FrameworkView(finding_id=nf.id, framework=v.framework, clause=v.clause,
                                            verdict=v.verdict, deadline=v.deadline))
            s.commit()
            return roll.id
```

Module-level helper (above `class Repo`):

```python
def _parse_dt(v: object) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v))
    except ValueError:
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_fleet_repo.py tests/unit/test_fleet_merge_diff.py`
Expected: all pass. Then `ruff check src tests` and `mypy src/pqcscan` clean (add `# noqa: F401` nothing; the TYPE_CHECKING import avoids a cycle with `bundle.py`, which imports `Repo`).

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/store/repo.py tests/unit/test_fleet_repo.py
git commit -m "feat(store): host CRUD, idempotent bundle ingest, fleet summary/history/prune, fleet rollup

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: `util/hostid.py` — cross-OS machine id and host identity

**Files:**
- Create: `src/pqcscan/util/hostid.py`
- Test: `tests/unit/test_hostid.py`

**Interfaces:**
- Produces: `machine_id() -> str` (Linux `/etc/machine-id` or `/var/lib/dbus/machine-id`; macOS `ioreg` `IOPlatformUUID`; Windows registry `MachineGuid`; fallback `sha256(hostname + MAC)` hex); `host_identity(labels: dict[str, str]) -> HostIdentity` (hostname via `socket.gethostname()`, os via `sys.platform` mapped to `linux|darwin|windows|other`, `agent_version=__version__`); `parse_labels(raw: Iterable[str]) -> dict[str, str]` accepting `k=v` items and comma-separated strings.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_hostid.py
import hashlib
from pathlib import Path

from pqcscan import __version__
from pqcscan.util import hostid


def test_linux_machine_id_file(monkeypatch, tmp_path: Path):
    (tmp_path / "machine-id").write_text("abc123\n")
    monkeypatch.setattr(hostid.sys, "platform", "linux")
    monkeypatch.setattr(hostid, "_LINUX_ID_FILES", (tmp_path / "nope", tmp_path / "machine-id"))
    assert hostid.machine_id() == "abc123"


def test_fallback_is_stable_hash(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(hostid.sys, "platform", "linux")
    monkeypatch.setattr(hostid, "_LINUX_ID_FILES", (tmp_path / "nope",))
    monkeypatch.setattr(hostid.socket, "gethostname", lambda: "h1")
    monkeypatch.setattr(hostid.uuid, "getnode", lambda: 0x1234)
    expect = hashlib.sha256(b"h1|4660").hexdigest()
    assert hostid.machine_id() == expect == hostid.machine_id()


def test_darwin_ioreg_parse(monkeypatch):
    monkeypatch.setattr(hostid.sys, "platform", "darwin")
    monkeypatch.setattr(hostid, "_run", lambda argv: '  "IOPlatformUUID" = "AAAA-BBBB"\n')
    assert hostid.machine_id() == "AAAA-BBBB"


def test_parse_labels_and_identity(monkeypatch):
    assert hostid.parse_labels(["env=prod,tier=1", "group=web"]) == {"env": "prod", "tier": "1", "group": "web"}
    monkeypatch.setattr(hostid, "machine_id", lambda: "m")
    ident = hostid.host_identity({"env": "prod"})
    assert ident.machine_id == "m" and ident.labels == {"env": "prod"} and ident.agent_version == __version__
    assert ident.os in {"linux", "darwin", "windows", "other"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_hostid.py`
Expected: ImportError.

- [ ] **Step 3: Implement**

```python
# src/pqcscan/util/hostid.py
"""Stable machine identity for fleet enrollment (no PII beyond hostname)."""
from __future__ import annotations

import hashlib
import socket
import subprocess
import sys
import uuid
from collections.abc import Iterable
from pathlib import Path

from pqcscan import __version__
from pqcscan.store.bundle import HostIdentity

_LINUX_ID_FILES: tuple[Path, ...] = (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id"))


def _run(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _fallback() -> str:
    return hashlib.sha256(f"{socket.gethostname()}|{uuid.getnode()}".encode()).hexdigest()


def machine_id() -> str:
    if sys.platform.startswith("linux"):
        for p in _LINUX_ID_FILES:
            try:
                v = p.read_text().strip()
            except OSError:
                continue
            if v:
                return v
    elif sys.platform == "darwin":
        for line in _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]).splitlines():
            if "IOPlatformUUID" in line and '"' in line:
                return line.split('"')[-2]
    elif sys.platform == "win32":
        try:
            import winreg  # type: ignore[import-not-found]
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return str(winreg.QueryValueEx(k, "MachineGuid")[0])
        except (ImportError, OSError):
            pass
    return _fallback()


def parse_labels(raw: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in raw:
        for part in str(item).split(","):
            if "=" in part:
                k, _, v = part.partition("=")
                if k.strip():
                    out[k.strip()] = v.strip()
    return out


def host_identity(labels: dict[str, str] | None = None) -> HostIdentity:
    plat = sys.platform
    os_name = "linux" if plat.startswith("linux") else "darwin" if plat == "darwin" else \
        "windows" if plat == "win32" else "other"
    return HostIdentity(machine_id=machine_id(), hostname=socket.gethostname(), os=os_name,
                        labels=dict(labels or {}), agent_version=__version__)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_hostid.py`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/util/hostid.py tests/unit/test_hostid.py
git commit -m "feat(util): cross-OS machine id + host identity for fleet enrollment

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: `daemon/fleet.py` — enroll, ingest, revoke, fleet JSON; wire into the app

**Files:**
- Create: `src/pqcscan/daemon/fleet.py`
- Modify: `src/pqcscan/daemon/app.py` (`create_app` signature; `_guard` exemptions; `include_router`)
- Modify: `src/pqcscan/cli/daemon_cmd.py` (`--enroll-token`)
- Test: `tests/unit/test_daemon_fleet.py`

**Interfaces:**
- Consumes: `Repo.upsert_host/get_host_by_token_hash/ingest_bundle/fleet_summary/host_history/revoke_host/list_hosts`, `load_bundle`, `HostIdentity`.
- Produces:
  - `create_app(..., enroll_token: str | None = None)`; env fallback `PQCSCAN_ENROLL_TOKEN`.
  - `POST /api/agents/enroll` body `{"enroll_token": str, "host": {machine_id, hostname, os, labels, agent_version}}` → `201 {"host_id", "agent_token"}`; 403 bad enroll token; 503 when no enroll token configured.
  - `POST /api/ingest` headers `Authorization: Bearer <agent_token>`, `Content-Type: application/gzip`, body = bundle bytes → `200 {"scan_id", "stored_findings", "stored_views", "duplicate"}`; 401 unknown/revoked token; 403 machine_id mismatch; 413 oversize; 400 invalid; 429 more than one bundle per 60 s per host.
  - `GET /api/fleet` → list of `{host_id, machine_id, hostname, os, labels, last_seen, scan_id, finished_at, readiness, crit, high, total}` (site token/cookie applies).
  - `GET /api/fleet/{host_id}` → `{host, scans:[...]}`; `POST /api/agents/{host_id}/revoke` → `{"revoked": true}`.
  - Helpers: `hash_token(t: str) -> str` (sha256 hex), `FLEET_BEARER_PATHS = ("/api/ingest", "/api/agents/enroll")`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_daemon_fleet.py
"""Enroll → ingest → fleet view, with every rejection path."""
import gzip
import json

from fastapi.testclient import TestClient

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.daemon.app import create_app
from pqcscan.daemon.fleet import hash_token
from pqcscan.store.bundle import HostIdentity, dump_bundle
from pqcscan.store.repo import Repo

HOST = {"machine_id": "m-1", "hostname": "web01", "os": "linux", "labels": {"env": "prod"}, "agent_version": "x"}


def _client(tmp_db_path, fast_registry, **kw):
    return TestClient(create_app(db_path=tmp_db_path, registry=fast_registry, enroll_token="ENROLL", **kw),
                      base_url="http://127.0.0.1")


def _bundle(tmp_path, machine_id="m-1"):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
    src.record_finding(sid, Finding(probe_id="fs.cert.x509", algorithm="RSA-2048",
                                    classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT, title="t"))
    src.finish_scan(sid, status="done")
    return dump_bundle(src, sid, HostIdentity(machine_id=machine_id, hostname="web01", os="linux",
                                              labels={"env": "prod"}, agent_version="x"))


def _enroll(c):
    r = c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": HOST})
    assert r.status_code == 201, r.text
    return r.json()


def test_enroll_then_ingest_then_fleet(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)
    assert tok["agent_token"] and tok["host_id"] == 1
    r = c.post("/api/ingest", content=_bundle(tmp_path), headers={
        "authorization": f"Bearer {tok['agent_token']}", "content-type": "application/gzip"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stored_findings"] == 1 and body["duplicate"] is False
    fleet = c.get("/api/fleet").json()
    assert fleet[0]["hostname"] == "web01" and fleet[0]["crit"] == 1 and fleet[0]["labels"] == {"env": "prod"}
    hist = c.get("/api/fleet/1").json()
    assert hist["host"]["machine_id"] == "m-1" and len(hist["scans"]) == 1
    # token is stored hashed
    assert Repo(tmp_db_path).get_host_by_token_hash(hash_token(tok["agent_token"])).id == 1


def test_enroll_rejections(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry)
    assert c.post("/api/agents/enroll", json={"enroll_token": "nope", "host": HOST}).status_code == 403
    assert c.post("/api/agents/enroll", json={"host": HOST}).status_code == 403
    no_enroll = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry), base_url="http://127.0.0.1")
    assert no_enroll.post("/api/agents/enroll", json={"enroll_token": "x", "host": HOST}).status_code == 503


def test_ingest_rejections(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    h = {"authorization": f"Bearer {tok}", "content-type": "application/gzip"}
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers={"content-type": "application/gzip"}).status_code == 401
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers={**h, "authorization": "Bearer bad"}).status_code == 401
    assert c.post("/api/ingest", content=b"garbage", headers=h).status_code == 400
    assert c.post("/api/ingest", content=_bundle(tmp_path, machine_id="other"), headers=h).status_code == 403
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 200
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 429   # 1/min/host
    big = gzip.compress(b"{" + b" " * (9 * 1024 * 1024) + b"}")
    assert c.post("/api/ingest", content=big, headers=h).status_code == 413


def test_revoked_token_is_401(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    assert c.post("/api/agents/1/revoke").json() == {"revoked": True}
    r = c.post("/api/ingest", content=_bundle(tmp_path),
               headers={"authorization": f"Bearer {tok}", "content-type": "application/gzip"})
    assert r.status_code == 401


def test_fleet_paths_bypass_site_cookie_guard(tmp_db_path, fast_registry, tmp_path):
    # Site token set: /api/fleet needs it, but enroll/ingest use the agent token only.
    c = _client(tmp_db_path, fast_registry, token="SITE")
    assert c.get("/api/fleet").status_code == 401
    assert c.get("/api/fleet", headers={"authorization": "Bearer SITE"}).status_code == 200
    tok = _enroll(c)["agent_token"]
    r = c.post("/api/ingest", content=_bundle(tmp_path),
               headers={"authorization": f"Bearer {tok}", "content-type": "application/gzip"})
    assert r.status_code == 200
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_daemon_fleet.py`
Expected: ImportError on `pqcscan.daemon.fleet`.

- [ ] **Step 3: Implement the router**

```python
# src/pqcscan/daemon/fleet.py
"""Fleet collector endpoints: agent enrollment, bundle ingest, fleet summary.

Auth model: /api/agents/enroll takes the shared enrollment token in the body
and mints a per-agent bearer token (stored SHA-256). /api/ingest accepts only
that bearer. Both are exempt from the site cookie/token guard; the fleet read
endpoints use the normal site guard.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Request, Response
from loguru import logger

from pqcscan.store.bundle import MAX_GZIP_BYTES, BundleInvalid, BundleTooLarge, HostIdentity, load_bundle
from pqcscan.store.repo import Repo

FLEET_BEARER_PATHS = ("/api/ingest", "/api/agents/enroll")
INGEST_MIN_INTERVAL_S = 60.0


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class _RateLimiter:
    def __init__(self, min_interval_s: float) -> None:
        self._last: dict[int, float] = {}
        self._lock = threading.Lock()
        self.min_interval_s = min_interval_s

    def allow(self, key: int) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and now - last < self.min_interval_s:
                return False
            self._last[key] = now
            return True


def _host_dict(h: Any) -> dict[str, Any]:
    return {"host_id": h.id, "machine_id": h.machine_id, "hostname": h.hostname, "os": h.os,
            "labels": h.labels or {}, "agent_version": h.agent_version,
            "first_seen": h.first_seen.isoformat() if h.first_seen else None,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None, "revoked": bool(h.revoked)}


def build_fleet_router(repo: Repo, *, enroll_token: str | None) -> APIRouter:
    router = APIRouter()
    limiter = _RateLimiter(INGEST_MIN_INTERVAL_S)

    def _agent_host(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(401, "agent token required")
        host = repo.get_host_by_token_hash(hash_token(auth[7:].strip()))
        if host is None or host.revoked:
            raise HTTPException(401, "unknown or revoked agent token")
        return host

    @router.post("/api/agents/enroll", status_code=201)
    async def enroll(body: dict = Body(...)) -> dict:
        if not enroll_token:
            raise HTTPException(503, "enrollment disabled: daemon started without --enroll-token")
        presented = str(body.get("enroll_token") or "")
        if not hmac.compare_digest(presented.encode(), enroll_token.encode()):
            raise HTTPException(403, "bad enrollment token")
        h = body.get("host") or {}
        if not h.get("machine_id"):
            raise HTTPException(400, "host.machine_id required")
        ident = HostIdentity(machine_id=str(h["machine_id"]), hostname=str(h.get("hostname", "")),
                             os=str(h.get("os", "")), labels=dict(h.get("labels") or {}),
                             agent_version=str(h.get("agent_version", "")))
        token = secrets.token_urlsafe(32)
        host = repo.upsert_host(ident, token_hash=hash_token(token))
        logger.info("fleet: enrolled host {} ({})", host.hostname, host.machine_id)
        return {"host_id": host.id, "agent_token": token}

    @router.post("/api/ingest")
    async def ingest(request: Request) -> dict:
        host = _agent_host(request)
        length = int(request.headers.get("content-length") or 0)
        if length > MAX_GZIP_BYTES:
            raise HTTPException(413, f"bundle over {MAX_GZIP_BYTES} bytes")
        data = await request.body()
        try:
            bundle = load_bundle(data)
        except BundleTooLarge as e:
            raise HTTPException(413, str(e)) from e
        except BundleInvalid as e:
            raise HTTPException(400, str(e)) from e
        if bundle.host.machine_id != host.machine_id:
            raise HTTPException(403, "bundle machine_id does not match the agent token")
        if not limiter.allow(host.id):
            raise HTTPException(429, "one bundle per minute per host")
        repo.upsert_host(bundle.host)
        res = repo.ingest_bundle(bundle, host.id)
        return {"scan_id": res.scan_id, "stored_findings": res.stored_findings,
                "stored_views": res.stored_views, "duplicate": res.duplicate}

    @router.get("/api/fleet")
    async def fleet() -> list[dict]:
        return [{**_host_dict(x.host), "scan_id": x.scan_id,
                 "finished_at": x.finished_at.isoformat() if x.finished_at else None,
                 "readiness": x.readiness, "crit": x.crit, "high": x.high, "total": x.total}
                for x in repo.fleet_summary()]

    @router.get("/api/fleet/{host_id}")
    async def fleet_host(host_id: int) -> dict:
        host = repo.get_host(host_id)
        if host is None:
            raise HTTPException(404, "host not found")
        return {"host": _host_dict(host),
                "scans": [{"id": s.id, "started_at": s.started_at.isoformat(), "status": s.status,
                           "finished_at": s.finished_at.isoformat() if s.finished_at else None}
                          for s in repo.host_history(host_id)]}

    @router.post("/api/agents/{host_id}/revoke")
    async def revoke(host_id: int) -> dict:
        if not repo.revoke_host(host_id):
            raise HTTPException(404, "host not found")
        return {"revoked": True}

    return router
```

- [ ] **Step 4: Wire into `create_app` and exempt the bearer-only paths**

In `src/pqcscan/daemon/app.py`:
- signature: `def create_app(*, db_path: Path, registry: Registry | None = None, token: str | None = None, allowed_hosts: Iterable[str] = (), enroll_token: str | None = None) -> FastAPI:`
- after `token = ...`: `enroll_token = enroll_token if enroll_token is not None else os.environ.get("PQCSCAN_ENROLL_TOKEN") or None`
- in `_guard`, change the site-token condition to `if token and request.url.path not in ("/api/health", "/login") and request.url.path not in FLEET_BEARER_PATHS:` (import `FLEET_BEARER_PATHS, build_fleet_router` from `pqcscan.daemon.fleet`). The Origin check still applies to those POSTs; agents send no Origin.
- before the UI mount: `app.include_router(build_fleet_router(repo, enroll_token=enroll_token))`.

In `src/pqcscan/cli/daemon_cmd.py` add `@click.option("--enroll-token", default=None, envvar="PQCSCAN_ENROLL_TOKEN", help="Shared token agents present once to enroll (fleet mode). Without it, /api/agents/enroll is disabled.")`, the `enroll_token: str | None` parameter, and pass `enroll_token=enroll_token` to `create_app`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_daemon_fleet.py tests/unit/test_daemon_guard.py tests/integration/test_daemon_api.py`
Expected: all pass; `ruff` + `mypy` clean.

- [ ] **Step 6: Commit**

```bash
git add src/pqcscan/daemon/fleet.py src/pqcscan/daemon/app.py src/pqcscan/cli/daemon_cmd.py tests/unit/test_daemon_fleet.py
git commit -m "feat(daemon): fleet collector — agent enrollment, bearer-only bundle ingest, fleet JSON, revoke

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: `cli/_report.py` + `scan --report-to`

**Files:**
- Create: `src/pqcscan/cli/_report.py`
- Modify: `src/pqcscan/cli/scan.py` (new options; `run_local_scan()` extracted; report step after the scan)
- Test: `tests/unit/test_cli_report.py`

**Interfaces:**
- Produces (in `cli/_report.py`):
  - `default_state_dir() -> Path` (`default_db_path().parent / "agent"`)
  - `make_client(*, ca_cert: Path | None, insecure: bool, timeout: float = 60.0) -> httpx.Client`
  - `ensure_agent_token(server: str, *, enroll_token: str | None, identity: HostIdentity, state_dir: Path, client: httpx.Client) -> str` (reads `state_dir/agent.token`; else enrolls and writes it 0600; raises `ReportError`)
  - `post_bundle(server: str, token: str, data: bytes, client: httpx.Client) -> dict` (POST `/api/ingest`; raises `ReportError(status, detail)` on non-2xx; `status=0` on transport error)
  - `spool_bundle(state_dir: Path, data: bytes) -> Path` (`state_dir/spool/<uuid>.bundle.gz`, dir 0700)
  - `flush_spool(server, token, state_dir, client) -> tuple[int, int]` (sent, kept)
  - `report_scan(repo, scan_id, *, server, enroll_token, agent_token, labels, state_dir, client) -> dict | None` (dump → ensure token → post; on `ReportError` spools and returns None; never raises)
  - In `cli/scan.py`: `run_local_scan(*, db_path, paths, target, ot, watch=False) -> tuple[Repo, int]` reused by Task 10's agent.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_cli_report.py
"""scan --report-to: enroll once, post the bundle, spool on failure."""
import json
from pathlib import Path

import httpx
import pytest

from pqcscan.cli import _report
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity
from pqcscan.store.repo import Repo

IDENT = HostIdentity(machine_id="m-1", hostname="h", os="linux", labels={}, agent_version="x")


def _seed(tmp_path) -> tuple[Repo, int]:
    repo = Repo(tmp_path / "db.db"); repo.init_schema()
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(sid, Finding(probe_id="p", algorithm="RSA-2048", classification=Classification.TINGGI,
                                     severity=Severity.HIGH, title="t"))
    repo.finish_scan(sid, status="done")
    return repo, sid


class _Server:
    """Fake collector: records requests, returns scripted responses."""
    def __init__(self, ingest_status=200):
        self.calls: list[tuple[str, bytes, dict]] = []
        self.ingest_status = ingest_status

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append((req.url.path, req.content, dict(req.headers)))
        if req.url.path == "/api/agents/enroll":
            return httpx.Response(201, json={"host_id": 1, "agent_token": "AGENT"})
        if req.url.path == "/api/ingest":
            if self.ingest_status == 200:
                return httpx.Response(200, json={"scan_id": 7, "stored_findings": 1, "stored_views": 0, "duplicate": False})
            return httpx.Response(self.ingest_status, json={"detail": "nope"})
        return httpx.Response(404)


def _client(server: _Server) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(server.handler), base_url="http://c")


def test_enroll_writes_token_0600_and_reuses_it(tmp_path):
    srv = _Server(); state = tmp_path / "state"
    tok = _report.ensure_agent_token("http://c", enroll_token="E", identity=IDENT, state_dir=state, client=_client(srv))
    assert tok == "AGENT" and (state / "agent.token").read_text() == "AGENT"
    assert oct((state / "agent.token").stat().st_mode & 0o777) == "0o600"
    sent = json.loads(srv.calls[0][1])
    assert sent["enroll_token"] == "E" and sent["host"]["machine_id"] == "m-1"
    assert _report.ensure_agent_token("http://c", enroll_token=None, identity=IDENT, state_dir=state,
                                      client=_client(srv)) == "AGENT"
    assert len(srv.calls) == 1                                   # no second enroll


def test_report_scan_posts_bundle(tmp_path):
    repo, sid = _seed(tmp_path); srv = _Server()
    res = _report.report_scan(repo, sid, server="http://c", enroll_token="E", agent_token=None,
                              labels={"env": "prod"}, state_dir=tmp_path / "s", client=_client(srv))
    assert res == {"scan_id": 7, "stored_findings": 1, "stored_views": 0, "duplicate": False}
    path, body, headers = srv.calls[-1]
    assert path == "/api/ingest" and headers["authorization"] == "Bearer AGENT"
    assert headers["content-type"] == "application/gzip" and body[:2] == b"\x1f\x8b"
    assert not list((tmp_path / "s" / "spool").glob("*")) if (tmp_path / "s" / "spool").exists() else True


def test_report_scan_spools_on_server_error_and_flush_resends(tmp_path):
    repo, sid = _seed(tmp_path); srv = _Server(ingest_status=503)
    state = tmp_path / "s"
    assert _report.report_scan(repo, sid, server="http://c", enroll_token="E", agent_token=None,
                               labels={}, state_dir=state, client=_client(srv)) is None
    spooled = list((state / "spool").glob("*.bundle.gz"))
    assert len(spooled) == 1 and oct((state / "spool").stat().st_mode & 0o777) == "0o700"
    srv.ingest_status = 200
    assert _report.flush_spool("http://c", "AGENT", state, _client(srv)) == (1, 0)
    assert not list((state / "spool").glob("*.bundle.gz"))


def test_post_bundle_raises_report_error_with_status(tmp_path):
    srv = _Server(ingest_status=401)
    with pytest.raises(_report.ReportError) as ei:
        _report.post_bundle("http://c", "AGENT", b"\x1f\x8b", _client(srv))
    assert ei.value.status == 401


def test_scan_cli_has_report_options():
    from click.testing import CliRunner
    from pqcscan.cli.scan import scan_cmd
    out = " ".join(CliRunner().invoke(scan_cmd, ["--help"]).output.split())
    for opt in ("--report-to", "--enroll-token", "--agent-token", "--labels", "--state-dir", "--ca-cert", "--insecure"):
        assert opt in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_cli_report.py`
Expected: ImportError on `pqcscan.cli._report`.

- [ ] **Step 3: Implement `cli/_report.py`**

```python
"""Report a finished scan to the fleet daemon (enroll once, POST the bundle, spool on failure)."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import httpx
from loguru import logger

from pqcscan.store.bundle import HostIdentity, dump_bundle
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path

TOKEN_FILE = "agent.token"
SPOOL_DIR = "spool"


class ReportError(RuntimeError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


def default_state_dir() -> Path:
    return default_db_path().parent / "agent"


def make_client(*, ca_cert: Path | None = None, insecure: bool = False, timeout: float = 60.0) -> httpx.Client:
    verify: bool | str = False if insecure else (str(ca_cert) if ca_cert else True)
    return httpx.Client(verify=verify, timeout=timeout, follow_redirects=False)


def _write_private(path: Path, data: bytes | str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data.encode() if isinstance(data, str) else data)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _raise_for(r: httpx.Response) -> None:
    if r.status_code // 100 != 2:
        try:
            detail = str(r.json().get("detail", r.text))
        except ValueError:
            detail = r.text
        raise ReportError(r.status_code, detail)


def ensure_agent_token(server: str, *, enroll_token: str | None, identity: HostIdentity,
                       state_dir: Path, client: httpx.Client) -> str:
    token_path = state_dir / TOKEN_FILE
    if token_path.is_file():
        tok = token_path.read_text().strip()
        if tok:
            return tok
    if not enroll_token:
        raise ReportError(0, f"no agent token at {token_path} and no --enroll-token given")
    try:
        r = client.post(server.rstrip("/") + "/api/agents/enroll", json={
            "enroll_token": enroll_token,
            "host": {"machine_id": identity.machine_id, "hostname": identity.hostname, "os": identity.os,
                     "labels": identity.labels, "agent_version": identity.agent_version},
        })
    except httpx.HTTPError as e:
        raise ReportError(0, f"enroll failed: {e}") from e
    _raise_for(r)
    tok = str(r.json()["agent_token"])
    _write_private(token_path, tok, 0o600)
    return tok


def post_bundle(server: str, token: str, data: bytes, client: httpx.Client) -> dict:
    try:
        r = client.post(server.rstrip("/") + "/api/ingest", content=data,
                        headers={"authorization": f"Bearer {token}", "content-type": "application/gzip"})
    except httpx.HTTPError as e:
        raise ReportError(0, f"ingest failed: {e}") from e
    _raise_for(r)
    return dict(r.json())


def spool_bundle(state_dir: Path, data: bytes) -> Path:
    p = state_dir / SPOOL_DIR / f"{uuid.uuid4()}.bundle.gz"
    _write_private(p, data, 0o600)
    return p


def flush_spool(server: str, token: str, state_dir: Path, client: httpx.Client) -> tuple[int, int]:
    sent = kept = 0
    for p in sorted((state_dir / SPOOL_DIR).glob("*.bundle.gz")) if (state_dir / SPOOL_DIR).is_dir() else []:
        try:
            post_bundle(server, token, p.read_bytes(), client)
        except ReportError as e:
            if e.status in (400, 403, 413):      # will never succeed; keep for inspection, don't retry forever
                logger.warning("fleet: spool {} rejected ({}), left in place", p.name, e.status)
            kept += 1
            if e.status in (0, 429) or e.status >= 500:
                break                            # server down or throttling: stop this pass
            continue
        p.unlink(missing_ok=True)
        sent += 1
    return sent, kept


def report_scan(repo: Repo, scan_id: int, *, server: str, enroll_token: str | None, agent_token: str | None,
                labels: dict[str, str], state_dir: Path, client: httpx.Client) -> dict | None:
    from pqcscan.util.hostid import host_identity
    identity = host_identity(labels)
    data = dump_bundle(repo, scan_id, identity)
    try:
        token = agent_token or ensure_agent_token(server, enroll_token=enroll_token, identity=identity,
                                                  state_dir=state_dir, client=client)
        flush_spool(server, token, state_dir, client)
        return post_bundle(server, token, data, client)
    except ReportError as e:
        p = spool_bundle(state_dir, data)
        logger.warning("fleet: report to {} failed ({}); spooled {}", server, e, p)
        return None
```

- [ ] **Step 4: Extract `run_local_scan` and add the options in `cli/scan.py`**

Move the body between `try: db_path = ...` and `scan_id = asyncio.run(_go())` into:

```python
def run_local_scan(*, db_path: Path, paths: Iterable[str] = (), target: str | None = None,
                   ot: Iterable[str] = (), watch: bool = False) -> tuple[Repo, int]:
    """Run one in-process scan; returns (repo, scan_id). Raises on failure."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo(db_path); repo.init_schema()
    bus = EventBus()
    runner = ProbeRunner(registry=default_registry(), repo=repo, bus=bus)
    scan_paths, server_target, ot_targets = parse_scan_inputs(target=target, paths=list(paths), ot=list(ot))

    async def _go() -> int:
        watcher_task = None
        if watch:
            async def _watch() -> None:
                async for ev in bus.subscribe():
                    click.echo(f"[event] {type(ev).__name__}: {ev}", err=True)
            watcher_task = asyncio.create_task(_watch())
        sid = await runner.run(mode=current_mode(), available_capabilities=detect_capabilities(),
                               scan_paths=scan_paths, server_target=server_target, ot_targets=ot_targets)
        if watcher_task:
            watcher_task.cancel()
        return sid

    return repo, asyncio.run(_go())
```

`scan_cmd` becomes: options as before plus

```python
@click.option("--report-to", default=None, help="Fleet daemon URL; POST this scan's results after it finishes.")
@click.option("--enroll-token", default=None, envvar="PQCSCAN_ENROLL_TOKEN",
              help="Enroll on first contact (fleet). Stored per-agent token is reused afterwards.")
@click.option("--agent-token", default=None, envvar="PQCSCAN_AGENT_TOKEN", help="Use this agent token directly.")
@click.option("--labels", multiple=True, help="Host labels k=v (repeatable or comma-separated), e.g. env=prod.")
@click.option("--state-dir", type=click.Path(path_type=Path), default=None,
              help="Agent state (token, spool). Default: <db dir>/agent.")
@click.option("--ca-cert", type=click.Path(path_type=Path, exists=True), default=None, help="CA bundle for --report-to.")
@click.option("--insecure", is_flag=True, help="Skip TLS verification for --report-to (lab only).")
```

then:

```python
    try:
        db_path = db or default_db_path()
        repo, scan_id = run_local_scan(db_path=db_path, paths=paths, target=target, ot=ot, watch=watch)
    except Exception as e:  # documented "scan failed" exit
        click.echo(f"scan failed: {e}", err=True)
        sys.exit(2)
    report: dict | None = None
    if report_to:
        from pqcscan.cli._report import default_state_dir, make_client, report_scan
        from pqcscan.util.hostid import parse_labels
        with make_client(ca_cert=ca_cert, insecure=insecure) as client:
            report = report_scan(repo, scan_id, server=report_to, enroll_token=enroll_token,
                                 agent_token=agent_token, labels=parse_labels(labels),
                                 state_dir=state_dir or default_state_dir(), client=client)
```

and add `"report": report` to the JSON output and a line `click.echo(f"Reported to {report_to}: {'ok' if report else 'spooled for retry'}.")` to the text output. The gate exit code is unchanged by reporting.

- [ ] **Step 5: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_cli_report.py tests/unit/test_cli_scan_gate.py tests/unit/test_cli_exit_and_strings.py tests/integration/test_cli_scan.py`
Expected: all pass; ruff/mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/pqcscan/cli/_report.py src/pqcscan/cli/scan.py tests/unit/test_cli_report.py
git commit -m "feat(cli): scan --report-to posts the ScanBundle to the fleet daemon (enroll once, spool on failure)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: `pqcscan agents list|revoke`, `pqcscan fleet summary|prune`, `export --scan fleet`

**Files:**
- Modify: `src/pqcscan/cli/fleet.py` (add `agents_cmd` group and `fleet_cmd` group)
- Modify: `src/pqcscan/cli/main.py` (register both groups)
- Modify: `src/pqcscan/cli/export.py` (`--scan` accepts `fleet`)
- Modify: `src/pqcscan/daemon/app.py` export endpoint (`scan_id` path accepts `fleet`)
- Test: `tests/unit/test_cli_fleet_admin.py`

**Interfaces:**
- Produces: `pqcscan agents list [--db] [--json]`, `pqcscan agents revoke <host_id> [--db]`; `pqcscan fleet summary [--db] [--json]`, `pqcscan fleet prune --keep N [--db]`; `pqcscan export --scan fleet --format … -o …` and `GET /api/scans/fleet/export/{fmt}`; helper `resolve_scan_ref(repo, ref: str) -> tuple[int, bool]` in `cli/fleet.py` returning `(scan_id, is_temp_rollup)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_cli_fleet_admin.py
import json

from click.testing import CliRunner

from pqcscan.cli.export import export_cmd
from pqcscan.cli.fleet import agents_cmd, fleet_cmd, resolve_scan_ref
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo


def _fleet_db(tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_path / "fleet.db"); fleet.init_schema()
    for name in ("web01", "web02"):
        h = fleet.upsert_host(HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux"), token_hash=name)
        for _ in range(3):
            sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
            src.record_finding(sid, Finding(probe_id="p", algorithm="RSA-2048", classification=Classification.TINGGI,
                                            severity=Severity.HIGH, title=f"{name} t"))
            src.finish_scan(sid, status="done")
            fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux"))), h.id)
    return tmp_path / "fleet.db"


def test_agents_list_and_revoke(tmp_path):
    db = _fleet_db(tmp_path)
    r = CliRunner().invoke(agents_cmd, ["list", "--db", str(db), "--json"])
    assert r.exit_code == 0 and [x["hostname"] for x in json.loads(r.output)] == ["web01", "web02"]
    assert CliRunner().invoke(agents_cmd, ["revoke", "1", "--db", str(db)]).exit_code == 0
    assert Repo(db).get_host(1).revoked is True
    assert CliRunner().invoke(agents_cmd, ["revoke", "99", "--db", str(db)]).exit_code == 3


def test_fleet_summary_and_prune(tmp_path):
    db = _fleet_db(tmp_path)
    r = CliRunner().invoke(fleet_cmd, ["summary", "--db", str(db), "--json"])
    rows = json.loads(r.output)
    assert r.exit_code == 0 and rows[0]["hostname"] == "web01" and rows[0]["high"] == 1
    r = CliRunner().invoke(fleet_cmd, ["prune", "--keep", "1", "--db", str(db)])
    assert r.exit_code == 0 and "4 scans" in r.output
    assert len(Repo(db).list_scans()) == 2


def test_export_scan_fleet_materialises_and_cleans_up(tmp_path):
    db = _fleet_db(tmp_path)
    out = tmp_path / "fleet.cdx.json"
    r = CliRunner().invoke(export_cmd, ["--db", str(db), "--scan", "fleet", "--format", "cbom", "-o", str(out)])
    assert r.exit_code == 0, r.output
    names = [c["name"] for c in json.loads(out.read_text())["components"]]
    assert sum("RSA-2048" in n for n in names) == 2                      # one latest scan per host
    assert not [s for s in Repo(db).list_scans() if s.label == "fleet-rollup"]   # temp rollup deleted
    sid, temp = resolve_scan_ref(Repo(db), "3")
    assert (sid, temp) == (3, False)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_cli_fleet_admin.py`
Expected: ImportError (`agents_cmd`).

- [ ] **Step 3: Implement**

Append to `src/pqcscan/cli/fleet.py`:

```python
def resolve_scan_ref(repo: Repo, ref: str) -> tuple[int, bool]:
    """'fleet' -> a temporary rollup scan (caller must delete_scan when done); else int id."""
    if ref.strip().lower() == "fleet":
        rid = repo.materialize_fleet_rollup()
        if rid is None:
            raise click.ClickException("no enrolled hosts with a completed scan")
        return rid, True
    try:
        return int(ref), False
    except ValueError as e:
        raise click.BadParameter("must be a scan id or 'fleet'") from e


@click.group("agents")
def agents_cmd() -> None:
    """Enrolled fleet agents."""


@agents_cmd.command("list")
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True)
def agents_list(db: Path | None, as_json: bool) -> None:
    repo = Repo(db or default_db_path()); repo.init_schema()
    rows = [{"host_id": h.id, "hostname": h.hostname, "machine_id": h.machine_id, "os": h.os,
             "labels": h.labels or {}, "agent_version": h.agent_version, "revoked": bool(h.revoked),
             "last_seen": h.last_seen.isoformat() if h.last_seen else None} for h in repo.list_hosts()]
    if as_json:
        click.echo(json.dumps(rows))
        return
    for r in rows:
        flag = " (revoked)" if r["revoked"] else ""
        click.echo(f"{r['host_id']}\t{r['hostname']}\t{r['os']}\t{r['last_seen']}\t{r['labels']}{flag}")


@agents_cmd.command("revoke")
@click.argument("host_id", type=int)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def agents_revoke(host_id: int, db: Path | None) -> None:
    repo = Repo(db or default_db_path()); repo.init_schema()
    if not repo.revoke_host(host_id):
        click.echo(f"host {host_id} not found", err=True)
        sys.exit(3)
    click.echo(f"revoked host {host_id}; its agent must re-enroll")


@click.group("fleet")
def fleet_cmd() -> None:
    """Fleet-wide views and maintenance."""


@fleet_cmd.command("summary")
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True)
def fleet_summary(db: Path | None, as_json: bool) -> None:
    repo = Repo(db or default_db_path()); repo.init_schema()
    rows = [{"host_id": x.host.id, "hostname": x.host.hostname, "labels": x.host.labels or {},
             "scan_id": x.scan_id, "finished_at": x.finished_at.isoformat() if x.finished_at else None,
             "readiness": x.readiness, "crit": x.crit, "high": x.high, "total": x.total}
            for x in repo.fleet_summary()]
    if as_json:
        click.echo(json.dumps(rows))
        return
    click.echo(f"{'host':24s} {'readiness':>9} {'crit':>5} {'high':>5} {'total':>6}  last scan")
    for r in rows:
        click.echo(f"{r['hostname']:24s} {str(r['readiness']):>9} {r['crit']:>5} {r['high']:>5} "
                   f"{r['total']:>6}  {r['finished_at'] or '-'}")


@fleet_cmd.command("prune")
@click.option("--keep", type=int, default=12, show_default=True, help="Scans to keep per host.")
@click.option("--db", type=click.Path(path_type=Path), default=None)
def fleet_prune(keep: int, db: Path | None) -> None:
    repo = Repo(db or default_db_path()); repo.init_schema()
    n = repo.prune_scans(keep_per_host=keep)
    click.echo(f"pruned {n} scans (kept {keep} per host)")
```

In `src/pqcscan/cli/main.py`: `from pqcscan.cli.fleet import agents_cmd, diff_cmd, fleet_cmd, merge_cmd` and `cli.add_command(agents_cmd, name="agents")`, `cli.add_command(fleet_cmd, name="fleet")`.

In `src/pqcscan/cli/export.py`: change `--scan` to `@click.option("--scan", "scan_ref", required=True, help="Scan id, or 'fleet' for the latest scan of every enrolled host.")`, then at the top of the body:

```python
    from pqcscan.cli.fleet import resolve_scan_ref
    repo = Repo(db or default_db_path()); repo.init_schema()
    scan_id, temp = resolve_scan_ref(repo, scan_ref)
    if repo.get_scan(scan_id) is None:
        click.echo(f"scan {scan_id} not found", err=True); sys.exit(3)
    try:
        ... existing format dispatch, unchanged ...
    finally:
        if temp:
            repo.delete_scan(scan_id)
```

In `src/pqcscan/daemon/app.py` export endpoint: change the path to `/api/scans/{scan_ref}/export/{fmt}` with `scan_ref: str`; resolve with the same helper (`temp` rollup deleted in the existing `finally`); the UI's existing links pass numeric ids so nothing else changes.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_cli_fleet_admin.py tests/unit/test_cli_exit_and_strings.py tests/integration/test_daemon_api.py tests/integration/test_end_to_end.py`
Expected: all pass; ruff/mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/cli/fleet.py src/pqcscan/cli/main.py src/pqcscan/cli/export.py src/pqcscan/daemon/app.py tests/unit/test_cli_fleet_admin.py
git commit -m "feat(cli): agents list/revoke, fleet summary/prune, export --scan fleet via temporary rollup

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Integration — two reporting hosts against a live daemon

**Files:**
- Test: `tests/integration/test_fleet_e2e.py`

**Interfaces:**
- Consumes: everything from Tasks 1–7. No new production code.

- [ ] **Step 1: Write the test**

```python
# tests/integration/test_fleet_e2e.py
"""Two hosts scan with --report-to against a live daemon; the fleet shows both and exports them."""
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from pqcscan.daemon.app import create_app

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def daemon(tmp_path, fast_registry):
    port = _free_port()
    app = create_app(db_path=tmp_path / "fleet.db", registry=fast_registry, enroll_token="E")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True); t.start()
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/api/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", tmp_path / "fleet.db"
    server.should_exit = True
    t.join(timeout=5)


def _host_scan(url: str, tmp_path: Path, name: str, machine_id: str) -> dict:
    env = {**os.environ, "PYTHONPATH": SRC, "PQCSCAN_TEST_MACHINE_ID": machine_id}
    scan_dir = tmp_path / name; scan_dir.mkdir()
    p = subprocess.run([sys.executable, "-m", "pqcscan", "scan", "--json", "--fail-on", "none",
                        "--db", str(tmp_path / f"{name}.db"), "--path", str(scan_dir),
                        "--report-to", url, "--enroll-token", "E", "--labels", f"host={name}",
                        "--state-dir", str(tmp_path / f"{name}-state")],
                       capture_output=True, text=True, env=env, timeout=600)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_two_hosts_report_and_fleet_exports(daemon, tmp_path):
    url, db = daemon
    a = _host_scan(url, tmp_path, "web01", "m-web01")
    b = _host_scan(url, tmp_path, "web02", "m-web02")
    assert a["report"]["stored_findings"] > 0 and b["report"]["stored_findings"] > 0
    fleet = httpx.get(f"{url}/api/fleet").json()
    assert sorted(h["labels"]["host"] for h in fleet) == ["web01", "web02"]
    cbom = httpx.get(f"{url}/api/scans/fleet/export/cbom").json()
    assert cbom["bomFormat"] == "CycloneDX"
    out = subprocess.run([sys.executable, "-m", "pqcscan", "fleet", "summary", "--db", str(db), "--json"],
                         capture_output=True, text=True, env={**os.environ, "PYTHONPATH": SRC})
    assert len(json.loads(out.stdout)) == 2
```

`PQCSCAN_TEST_MACHINE_ID`: add to `util/hostid.machine_id()` as the first branch — `if v := os.environ.get("PQCSCAN_TEST_MACHINE_ID"): return v` — so two agents on one CI box enroll as two hosts. Document it as test-only in the docstring.

- [ ] **Step 2: Run the test**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_fleet_e2e.py`
Expected: 1 passed (subprocess scans are scoped to empty dirs, so they take seconds).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_fleet_e2e.py src/pqcscan/util/hostid.py
git commit -m "test: fleet end-to-end — two reporting hosts, fleet JSON, fleet CBOM export

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Docs + release v0.10.0

**Files:**
- Create: `docs/FLEET.md`
- Modify: `README.md` (CLI section + a Fleet paragraph), `docs/DEPLOYMENT.md` (enroll token row), `CHANGELOG.md` (`[0.10.0]`), `docs/STATUS.md` (version/date), `src/pqcscan/__init__.py` (`0.10.0`), `action.yml` + `docs/CICD.md` pins (`v0.10.0`)

- [ ] **Step 1: Write `docs/FLEET.md`**

```markdown
# Fleet mode — thousands of hosts, one daemon

1. **Collector.** `pqcscan daemon --bind 0.0.0.0 --token <site> --enroll-token <enroll> --tls-cert c.pem --tls-key k.pem` (or behind the nginx recipe in DEPLOYMENT.md with `--allow-host`). `--enroll-token` enables `/api/agents/enroll`.
2. **Host, one-shot (recommended).** From cron / systemd timer / Task Scheduler / BigFix / Ansible:
   `pqcscan scan --report-to https://pqc.internal:8765 --enroll-token <enroll> --labels env=prod,group=web --fail-on none`
   First run enrolls and stores a per-agent token in `<db dir>/agent/agent.token` (0600). Later runs reuse it. If the collector is down, the bundle is spooled under `<db dir>/agent/spool/` and sent on the next run.
3. **Fleet view.** `GET /api/fleet` (JSON), `pqcscan fleet summary --db …`, and `/fleet` in the web UI (v0.10.1).
4. **Exports.** `pqcscan export --scan fleet --format cbom|sarif|xlsx-bukukerja|pdf-tech … -o …` — latest scan of every host, `evidence.host` set.
5. **Parity (HA/DR).** `pqcscan diff --scan <dr scan> --baseline-scan <primary scan> --fail-on-drift`.
6. **Admin.** `pqcscan agents list|revoke <id>`, `pqcscan fleet prune --keep 12`.
7. **Scale.** SQLite handles ~2,000 hosts daily; past ~10k/day run the daemon with `--db postgresql://…` (`pip install pqcscan[fleet-pg]`).

Security: tokens hashed at rest; ingest is bearer-only, 8 MB/50 MB capped, 1 bundle/min/host; bundle `machine_id` must match the token; findings never carry key bytes.
```

- [ ] **Step 2: Version bump, CHANGELOG, pins**

`__version__ = "0.10.0"`; CHANGELOG `## [0.10.0] — <date>` under `[Unreleased]` with the phase-1 bullets (bundle, enroll/ingest, hosts table, `scan --report-to`, `agents`/`fleet` CLIs, `export --scan fleet`, in-place migration); README probe/feature banner → v0.10.0 + fleet paragraph; `action.yml` default and `docs/CICD.md` pins → `v0.10.0`; `docs/DEPLOYMENT.md` config table gains `| Enroll token | --enroll-token / PQCSCAN_ENROLL_TOKEN | none (fleet off) |`; add `fleet-pg = ["psycopg[binary]>=3.1"]` to `[project.optional-dependencies]`.

- [ ] **Step 3: Full suite, lint, type-check**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider && .venv/bin/ruff check src tests && .venv/bin/mypy src/pqcscan`
Expected: all pass.

- [ ] **Step 4: Commit, PR, merge, tag**

```bash
git add -A && git commit -m "release: v0.10.0 — fleet mode phase 1 (bundle, ingest, hosts, fleet exports)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
git push -u origin feat/fleet-agent
gh pr create --base main --fill --body "$(printf 'Fleet mode phase 1 per docs/superpowers/specs/2026-10-16-pqcscan-fleet-agent-design.md\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)')"
gh pr merge --squash --delete-branch
git checkout main && git pull --ff-only && git tag -a v0.10.0 -m "pqcscan v0.10.0" && git push origin v0.10.0
git checkout -b feat/fleet-agent-p2
```

---

## Phase 2 — agent loop, fleet UI, deployment recipes (v0.10.1)

### Task 10: `pqcscan agent` loop

**Files:**
- Create: `src/pqcscan/cli/agent.py`
- Modify: `src/pqcscan/cli/main.py` (register `agent_cmd`)
- Test: `tests/unit/test_cli_agent.py`

**Interfaces:**
- Consumes: `run_local_scan` (Task 6), `_report.ensure_agent_token/post_bundle/flush_spool/spool_bundle/make_client/ReportError`, `hostid.host_identity/parse_labels`, `dump_bundle`.
- Produces: `pqcscan agent --server URL [--enroll-token E] [--labels k=v] [--interval 24h] [--jitter 2h] [--once] [--state-dir D] [--path P ...] [--ca-cert F] [--insecure] [--keep-local 3]`; pure function `agent_cycle(cfg: AgentConfig, client: httpx.Client) -> CycleResult` (`@dataclass AgentConfig(server, enroll_token, labels, state_dir, paths, keep_local)`, `@dataclass CycleResult(scan_id, reported: bool, spooled: bool, re_enrolled: bool)`); `parse_duration("24h") -> float` seconds (`s/m/h/d`); `next_delay(base_s, jitter_s, failures) -> float` (exponential backoff capped at 1 h on failures, else base + uniform jitter).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_cli_agent.py
"""pqcscan agent: one cycle = flush spool, scan, post; backoff and re-enroll rules."""
import json
from pathlib import Path

import httpx
import pytest

from pqcscan.cli import agent as agent_mod
from pqcscan.cli.agent import AgentConfig, agent_cycle, next_delay, parse_duration


def test_parse_duration():
    assert parse_duration("90s") == 90 and parse_duration("2m") == 120
    assert parse_duration("24h") == 86400 and parse_duration("1d") == 86400
    with pytest.raises(ValueError):
        parse_duration("soon")


def test_next_delay_backoff_and_jitter(monkeypatch):
    monkeypatch.setattr(agent_mod.random, "uniform", lambda a, b: b)
    assert next_delay(3600, 600, failures=0) == 4200
    assert next_delay(3600, 600, failures=1) == 60
    assert next_delay(3600, 600, failures=4) == 480
    assert next_delay(3600, 600, failures=20) == 3600           # capped


class _Srv:
    def __init__(self):
        self.ingest = [200]
        self.enrolls = 0
        self.posts = 0

    def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/agents/enroll":
            self.enrolls += 1
            return httpx.Response(201, json={"host_id": 1, "agent_token": f"T{self.enrolls}"})
        self.posts += 1
        code = self.ingest.pop(0) if len(self.ingest) > 1 else self.ingest[0]
        if code == 200:
            return httpx.Response(200, json={"scan_id": 1, "stored_findings": 0, "stored_views": 0, "duplicate": False})
        return httpx.Response(code, json={"detail": "x"})


def _cfg(tmp_path) -> AgentConfig:
    d = tmp_path / "scan"; d.mkdir(exist_ok=True)
    return AgentConfig(server="http://c", enroll_token="E", labels={"env": "t"},
                       state_dir=tmp_path / "state", paths=[str(d)], keep_local=2)


def _client(srv) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(srv.handler), base_url="http://c")


def test_cycle_scans_and_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "_fast", True)      # use fast_registry-equivalent (see impl)
    srv = _Srv()
    r = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r.reported and not r.spooled and srv.enrolls == 1 and srv.posts == 1
    assert (tmp_path / "state" / "agent.token").read_text() == "T1"


def test_cycle_spools_on_5xx_then_flushes(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "_fast", True)
    srv = _Srv(); srv.ingest = [503, 200]
    r1 = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r1.spooled and not r1.reported
    assert len(list((tmp_path / "state" / "spool").glob("*.bundle.gz"))) == 1
    r2 = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r2.reported and not list((tmp_path / "state" / "spool").glob("*.bundle.gz"))


def test_cycle_re_enrolls_once_on_401(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "_fast", True)
    srv = _Srv(); srv.ingest = [401, 200]
    (tmp_path / "state").mkdir(); (tmp_path / "state" / "agent.token").write_text("STALE")
    r = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r.re_enrolled and r.reported and srv.enrolls == 1
    assert (tmp_path / "state" / "agent.token").read_text() == "T1"


def test_local_db_pruned_to_keep_local(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "_fast", True)
    srv = _Srv()
    for _ in range(4):
        agent_cycle(_cfg(tmp_path), _client(srv))
    from pqcscan.store.repo import Repo
    assert len(Repo(tmp_path / "state" / "agent.db").list_scans()) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_cli_agent.py`
Expected: ImportError.

- [ ] **Step 3: Implement**

```python
# src/pqcscan/cli/agent.py
"""`pqcscan agent` — scheduler loop around `scan --report-to` for hosts with no cron/CM agent."""
from __future__ import annotations

import random
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import click
import httpx
from loguru import logger

from pqcscan.cli._report import (
    ReportError, default_state_dir, ensure_agent_token, flush_spool, make_client, post_bundle, spool_bundle,
)
from pqcscan.store.bundle import dump_bundle
from pqcscan.util.hostid import host_identity, parse_labels

_fast = False   # tests set True: scan with the one-probe registry instead of all 180 probes
_DUR = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_MAX_BACKOFF_S = 3600.0


def parse_duration(text: str) -> float:
    m = _DUR.match(text.strip())
    if not m:
        raise ValueError(f"bad duration {text!r}; use e.g. 90s, 15m, 24h, 1d")
    return int(m.group(1)) * _UNITS[m.group(2)]


def next_delay(base_s: float, jitter_s: float, failures: int) -> float:
    if failures > 0:
        return min(60.0 * (2 ** (failures - 1)), _MAX_BACKOFF_S)
    return base_s + random.uniform(0, jitter_s)


@dataclass(slots=True)
class AgentConfig:
    server: str
    enroll_token: str | None
    labels: dict[str, str]
    state_dir: Path
    paths: list[str]
    keep_local: int = 3


@dataclass(slots=True)
class CycleResult:
    scan_id: int
    reported: bool
    spooled: bool
    re_enrolled: bool


def _scan(cfg: AgentConfig):
    from pqcscan.cli.scan import run_local_scan
    db = cfg.state_dir / "agent.db"
    if _fast:   # pragma: no cover - exercised by tests only
        from pqcscan.probes._registry import Registry
        from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
        import pqcscan.cli.scan as scan_mod
        reg = Registry(); reg.register(AuxClockCertValidity())
        scan_mod.default_registry = lambda: reg  # type: ignore[assignment]
    repo, sid = run_local_scan(db_path=db, paths=cfg.paths)
    # Keep the local DB bounded; the collector holds history.
    ids = [s.id for s in repo.list_scans()]
    for old in ids[cfg.keep_local:]:
        repo.delete_scan(old)
    return repo, sid


def agent_cycle(cfg: AgentConfig, client: httpx.Client) -> CycleResult:
    identity = host_identity(cfg.labels)
    repo, sid = _scan(cfg)
    data = dump_bundle(repo, sid, identity)
    re_enrolled = False
    try:
        token = ensure_agent_token(cfg.server, enroll_token=cfg.enroll_token, identity=identity,
                                   state_dir=cfg.state_dir, client=client)
        try:
            flush_spool(cfg.server, token, cfg.state_dir, client)
            post_bundle(cfg.server, token, data, client)
        except ReportError as e:
            if e.status != 401 or not cfg.enroll_token:
                raise
            (cfg.state_dir / "agent.token").unlink(missing_ok=True)
            token = ensure_agent_token(cfg.server, enroll_token=cfg.enroll_token, identity=identity,
                                       state_dir=cfg.state_dir, client=client)
            re_enrolled = True
            post_bundle(cfg.server, token, data, client)
        return CycleResult(sid, reported=True, spooled=False, re_enrolled=re_enrolled)
    except ReportError as e:
        spool_bundle(cfg.state_dir, data)
        logger.warning("agent: report failed ({}); spooled", e)
        return CycleResult(sid, reported=False, spooled=True, re_enrolled=re_enrolled)


@click.command("agent")
@click.option("--server", required=True, help="Fleet daemon URL, e.g. https://pqc.internal:8765")
@click.option("--enroll-token", default=None, envvar="PQCSCAN_ENROLL_TOKEN")
@click.option("--labels", multiple=True, help="k=v labels (repeatable / comma-separated).")
@click.option("--interval", default="24h", show_default=True, help="Time between scans (s/m/h/d).")
@click.option("--jitter", default="2h", show_default=True, help="Random extra delay to spread load.")
@click.option("--once", is_flag=True, help="One cycle then exit (for cron).")
@click.option("--state-dir", type=click.Path(path_type=Path), default=None)
@click.option("--path", "paths", multiple=True, type=click.Path(), help="Scope file probes (repeatable).")
@click.option("--keep-local", type=int, default=3, show_default=True, help="Local scans to keep in agent.db.")
@click.option("--ca-cert", type=click.Path(path_type=Path, exists=True), default=None)
@click.option("--insecure", is_flag=True)
def agent_cmd(server: str, enroll_token: str | None, labels: tuple[str, ...], interval: str, jitter: str,
              once: bool, state_dir: Path | None, paths: tuple[str, ...], keep_local: int,
              ca_cert: Path | None, insecure: bool) -> None:
    """Run scans on a schedule and push them to the fleet daemon."""
    try:
        base, jit = parse_duration(interval), parse_duration(jitter)
    except ValueError as e:
        click.echo(str(e), err=True); sys.exit(2)
    cfg = AgentConfig(server=server, enroll_token=enroll_token, labels=parse_labels(labels),
                      state_dir=state_dir or default_state_dir(), paths=list(paths), keep_local=keep_local)
    failures = 0
    with make_client(ca_cert=ca_cert, insecure=insecure) as client:
        while True:
            try:
                r = agent_cycle(cfg, client)
                failures = 0 if r.reported else failures + 1
                click.echo(f"agent: scan {r.scan_id} {'reported' if r.reported else 'spooled'}")
            except Exception as e:  # a failed scan must not kill the loop
                failures += 1
                logger.exception("agent: cycle failed: {}", e)
            if once:
                sys.exit(0 if failures == 0 else 1)
            time.sleep(next_delay(base, jit, failures))
```

Register in `main.py`: `from pqcscan.cli.agent import agent_cmd` and `cli.add_command(agent_cmd, name="agent")`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_cli_agent.py tests/unit/test_cli_report.py`
Expected: all pass; ruff/mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/cli/agent.py src/pqcscan/cli/main.py tests/unit/test_cli_agent.py
git commit -m "feat(cli): pqcscan agent — scheduled scan + report loop with spool, backoff and re-enroll

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: `/fleet` and `/fleet/{host_id}` pages (EN/MS)

**Files:**
- Create: `src/pqcscan/ui/templates/fleet.html`, `src/pqcscan/ui/templates/fleet_host.html`
- Modify: `src/pqcscan/ui/routes.py` (two routes), `src/pqcscan/ui/i18n.py` (keys in both locales), `src/pqcscan/ui/templates/base.html:38-43` (nav entry)
- Test: `tests/integration/test_ui_fleet.py`

**Interfaces:**
- Consumes: `repo.fleet_summary()`, `repo.get_host`, `repo.host_history`.
- Produces: `GET /fleet?label=k=v` (filter), `GET /fleet/{host_id}`; i18n keys `nav.fleet, fleet.title, fleet.host, fleet.labels, fleet.last_seen, fleet.readiness, fleet.crit, fleet.high, fleet.total, fleet.stale, fleet.none, fleet.history, fleet.diff_with`; a host is **stale** when `last_seen` is older than 48 h.

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_ui_fleet.py
from datetime import timedelta

from fastapi.testclient import TestClient

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.daemon.app import create_app
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo
from pqcscan.util.clock import utcnow


def _seed(db, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(db); fleet.init_schema()
    for name, env in (("web01", "prod"), ("dr01", "dr")):
        h = fleet.upsert_host(HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux", labels={"env": env}))
        sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
        src.record_finding(sid, Finding(probe_id="p", algorithm="RSA-2048", classification=Classification.SANGAT_TINGGI,
                                        severity=Severity.CRIT, title=f"{name} weak"))
        src.finish_scan(sid, status="done")
        fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux"))), h.id)
    return fleet


def test_fleet_page_lists_hosts_and_filters(tmp_db_path, fast_registry, tmp_path):
    _seed(tmp_db_path, tmp_path)
    c = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry), base_url="http://127.0.0.1")
    r = c.get("/fleet")
    assert r.status_code == 200 and "web01" in r.text and "dr01" in r.text
    r = c.get("/fleet?label=env=dr")
    assert "dr01" in r.text and "web01" not in r.text
    assert 'href="/fleet"' in c.get("/").text                   # nav entry
    assert "Armada" in c.get("/fleet", cookies={"pqcscan_locale": "ms"}).text


def test_fleet_host_page_and_stale_flag(tmp_db_path, fast_registry, tmp_path):
    fleet = _seed(tmp_db_path, tmp_path)
    from sqlalchemy.orm import Session
    from pqcscan.store.schema import Host
    with Session(fleet.engine) as s:
        h = s.execute(__import__("sqlalchemy").select(Host).where(Host.hostname == "dr01")).scalar_one()
        h.last_seen = utcnow() - timedelta(days=5); s.commit()
    c = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry), base_url="http://127.0.0.1")
    assert "stale" in c.get("/fleet").text.lower()
    r = c.get("/fleet/1")
    assert r.status_code == 200 and "web01" in r.text and "/scans/" in r.text
    assert c.get("/fleet/99").status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_ui_fleet.py`
Expected: 404 on `/fleet`.

- [ ] **Step 3: Implement routes, templates, i18n, nav**

Routes (append to `src/pqcscan/ui/routes.py`):

```python
_STALE_AFTER = timedelta(hours=48)


@router.get("/fleet", response_class=HTMLResponse)
async def fleet_page(request: Request, label: str | None = None) -> HTMLResponse:
    repo = request.app.state.repo
    rows = repo.fleet_summary()
    if label and "=" in label:
        k, _, v = label.partition("=")
        rows = [x for x in rows if (x.host.labels or {}).get(k) == v]
    now = utcnow()
    view = [{"host": x.host, "scan_id": x.scan_id, "finished_at": x.finished_at, "readiness": x.readiness,
             "crit": x.crit, "high": x.high, "total": x.total,
             "stale": bool(x.host.last_seen and now - x.host.last_seen > _STALE_AFTER)} for x in rows]
    return _render(request, "fleet.html", {"rows": view, "label": label or ""})


@router.get("/fleet/{host_id}", response_class=HTMLResponse)
async def fleet_host_page(request: Request, host_id: int) -> HTMLResponse:
    repo = request.app.state.repo
    host = repo.get_host(host_id)
    if host is None:
        raise HTTPException(404, "host not found")
    return _render(request, "fleet_host.html", {"host": host, "scans": repo.host_history(host_id)})
```

(add `from datetime import timedelta` and `from pqcscan.util.clock import utcnow` to the imports.)

`templates/fleet.html` — extend `base.html` like `scans_list.html`; a form with one text input `label` (GET), then a table with columns `t('fleet.host')`, `t('fleet.labels')`, `t('fleet.last_seen')`, `t('fleet.readiness')`, `t('fleet.crit')`, `t('fleet.high')`, `t('fleet.total')`; each row links `/fleet/{{ row.host.id }}` and, when `row.scan_id`, `/scans/{{ row.scan_id }}`; render `<span class="sev-chip">{{ t('fleet.stale') }}</span>` when `row.stale`; readiness cell uses the same colour rule as the dashboard gauge (`>=67` green, `>=34` amber, else red); empty state `t('fleet.none')`.

`templates/fleet_host.html` — host header (hostname, machine id, os, labels, agent version, last seen), then the scan list (id, started, status, link to `/scans/{{ s.id }}`), and a line `t('fleet.diff_with')` showing the CLI: `pqcscan diff --scan <id> --baseline-scan <primary id> --fail-on-drift`.

`i18n.py` — add to `en`: `"nav.fleet": "Fleet", "fleet.title": "Fleet", "fleet.host": "Host", "fleet.labels": "Labels", "fleet.last_seen": "Last seen", "fleet.readiness": "Readiness", "fleet.crit": "Critical", "fleet.high": "High", "fleet.total": "Findings", "fleet.stale": "stale", "fleet.none": "No enrolled hosts yet. Run pqcscan scan --report-to on a host.", "fleet.history": "Scan history", "fleet.diff_with": "Parity check against a primary:"`; to `ms`: `"nav.fleet": "Armada", "fleet.title": "Armada", "fleet.host": "Hos", "fleet.labels": "Label", "fleet.last_seen": "Terakhir dilihat", "fleet.readiness": "Kesediaan", "fleet.crit": "Kritikal", "fleet.high": "Tinggi", "fleet.total": "Penemuan", "fleet.stale": "lapuk", "fleet.none": "Tiada hos berdaftar lagi. Jalankan pqcscan scan --report-to pada hos.", "fleet.history": "Sejarah imbasan", "fleet.diff_with": "Semakan pariti terhadap hos utama:"` (the existing `test_translation_keys_match_across_locales` enforces parity).

`base.html` nav list: insert `('/fleet', 'nav.fleet', 'Fleet'),` after the `/scans` entry.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_ui_fleet.py tests/integration/test_ui.py tests/unit/test_i18n.py`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/ui tests/integration/test_ui_fleet.py
git commit -m "feat(ui): /fleet and /fleet/{host} pages with label filter and stale flag (EN/MS)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: Deployment recipes + release v0.10.1

**Files:**
- Create: `packaging/fleet/pqcscan-agent.service`, `packaging/fleet/pqcscan-agent.timer`, `packaging/fleet/windows-task.ps1`, `packaging/fleet/ansible-playbook.yml`, `packaging/fleet/bigfix-fixlet.md`, `packaging/fleet/osquery-wazuh.md`
- Modify: `docs/FLEET.md` (recipes section), `build/pyinstaller.spec` (nothing to bundle; recipes are docs), `CHANGELOG.md`, `src/pqcscan/__init__.py` (`0.10.1`), pins
- Test: `tests/unit/test_fleet_recipes.py` (files exist, unit/timer parse, PowerShell references `scan --report-to`)

- [ ] **Step 1: Write the recipes**

`packaging/fleet/pqcscan-agent.service`:
```ini
[Unit]
Description=pqcscan one-shot scan + report to the fleet daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=-/etc/pqcscan/agent.env
# agent.env: PQCSCAN_SERVER=https://pqc.internal:8765  PQCSCAN_ENROLL_TOKEN=...  PQCSCAN_LABELS=env=prod,group=web
ExecStart=/usr/local/bin/pqcscan scan --fail-on none --report-to ${PQCSCAN_SERVER} --labels ${PQCSCAN_LABELS} --db /var/lib/pqcscan/pqcscan.db
StateDirectory=pqcscan
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/pqcscan
NoNewPrivileges=true
```

`packaging/fleet/pqcscan-agent.timer`:
```ini
[Unit]
Description=Daily pqcscan fleet report

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
```

`packaging/fleet/windows-task.ps1` — registers a daily Scheduled Task running `pqcscan-windows-x86_64.exe scan --fail-on none --report-to $Server --labels $Labels` as SYSTEM with a 2-hour random delay (`New-ScheduledTaskTrigger -Daily -At 02:00 -RandomDelay (New-TimeSpan -Hours 2)`), parameters `-Server`, `-EnrollToken` (written to `%ProgramData%\pqcscan\agent.env` with ACL restricted to SYSTEM/Administrators), `-Labels`.

`packaging/fleet/ansible-playbook.yml` — one play: download the pinned release binary and `SHA256SUMS.txt`, verify, install to `/usr/local/bin`, template `/etc/pqcscan/agent.env` (0600), install service+timer, `systemctl enable --now pqcscan-agent.timer`.

`packaging/fleet/bigfix-fixlet.md` — the two action-script lines (download pinned binary, run `scan --report-to … --once-style`) and the relevance clause; `packaging/fleet/osquery-wazuh.md` — Wazuh `command` wodle invoking the one-shot scan daily; osquery note that the binary is invoked by the CM agent, not loaded as an extension.

- [ ] **Step 2: Write the test**

```python
# tests/unit/test_fleet_recipes.py
import configparser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "packaging" / "fleet"


def test_recipes_exist_and_reference_report_to():
    for name in ("pqcscan-agent.service", "pqcscan-agent.timer", "windows-task.ps1",
                 "ansible-playbook.yml", "bigfix-fixlet.md", "osquery-wazuh.md"):
        assert (ROOT / name).is_file(), name
    for name in ("pqcscan-agent.service", "windows-task.ps1", "ansible-playbook.yml", "bigfix-fixlet.md"):
        assert "--report-to" in (ROOT / name).read_text(), name


def test_systemd_units_parse():
    for name in ("pqcscan-agent.service", "pqcscan-agent.timer"):
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        cp.read_string((ROOT / name).read_text())
        assert "Unit" in cp.sections()
    svc = configparser.ConfigParser(strict=False, interpolation=None)
    svc.read_string((ROOT / "pqcscan-agent.service").read_text())
    assert svc["Service"]["Type"] == "oneshot"
```

- [ ] **Step 3: Run, docs, release**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_fleet_recipes.py` then the full suite + ruff + mypy. Add a "Deployment recipes" section to `docs/FLEET.md` pointing at each file; `__version__ = "0.10.1"`; CHANGELOG `[0.10.1]` (agent loop, fleet pages, recipes); pins → `v0.10.1`. Commit `release: v0.10.1 — fleet phase 2 (agent loop, fleet UI, deployment recipes)`, push, PR, squash-merge, tag `v0.10.1`, branch `feat/fleet-agent-p3`.

---

## Phase 3 — drift, labels → risk, crypto-agility (v0.10.2)

### Task 13: Host-agnostic parity key + `fleet.drift` findings on ingest

**Files:**
- Create: `src/pqcscan/core/parity.py`
- Modify: `src/pqcscan/store/repo.py` (`ingest_bundle` emits drift rows; `diff_findings(..., parity=True)` option), `src/pqcscan/cli/fleet.py` (`diff --parity`)
- Test: `tests/unit/test_parity_drift.py`

**Interfaces:**
- Produces: `parity_key(probe_id: str, algorithm: str, title: str, evidence: dict) -> tuple[str, str, str]` — strips `host:port`, IPv4/IPv6 literals and `at <host>` phrases from the title, and prefers `evidence["path"]` or `evidence["endpoint"]` port-only forms; `drift_rows(previous: list[FindingRow], current: list[FindingRow]) -> list[Finding]` returning one `fleet.drift` INFO finding per added/removed parity key with `evidence={"change": "added"|"removed", "probe_id", "algorithm", "title"}`; `Repo.ingest_bundle` calls `drift_rows` against the host's previous done scan and stores the result in the new scan; `Repo.diff_findings(..., parity: bool = False)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_parity_drift.py
from pqcscan.core.parity import parity_key, drift_rows
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo


def test_parity_key_strips_endpoints():
    k1 = parity_key("net.tls.https", "RSA-2048", "server at 10.0.0.1:443 offers RSA-2048", {"endpoint": "10.0.0.1:443"})
    k2 = parity_key("net.tls.https", "RSA-2048", "server at 10.0.0.2:443 offers RSA-2048", {"endpoint": "10.0.0.2:443"})
    assert k1 == k2 and ":443" in k1[2]
    assert parity_key("ot.modbus.tcp", "plain-Modbus", "plain Modbus/TCP at plc-a:502", {}) == \
        parity_key("ot.modbus.tcp", "plain-Modbus", "plain Modbus/TCP at [fe80::1]:502", {})
    assert parity_key("fs.cert.x509", "RSA-2048", "cert /etc/ssl/a.pem", {"path": "/etc/ssl/a.pem"}) != \
        parity_key("fs.cert.x509", "RSA-2048", "cert /etc/ssl/b.pem", {"path": "/etc/ssl/b.pem"})


def _f(alg, title):
    return Finding(probe_id="fs.cert.x509", algorithm=alg, classification=Classification.TINGGI,
                   severity=Severity.HIGH, title=title)


def test_drift_rows_added_and_removed(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    a = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    b = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(a, _f("RSA-2048", "x")); repo.record_finding(a, _f("RSA-1024", "y"))
    repo.record_finding(b, _f("RSA-2048", "x")); repo.record_finding(b, _f("ECDSA-P256", "z"))
    rows = drift_rows(repo.list_findings(a), repo.list_findings(b))
    changes = sorted((r.evidence["change"], r.evidence["algorithm"]) for r in rows)
    assert changes == [("added", "ECDSA-P256"), ("removed", "RSA-1024")]
    assert all(r.probe_id == "fleet.drift" and r.classification is Classification.INFO for r in rows)


def test_ingest_emits_drift_against_previous_scan(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "s.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    ident = HostIdentity(machine_id="m", hostname="h", os="linux")
    h = fleet.upsert_host(ident)
    for algs in (["RSA-2048"], ["RSA-2048", "RSA-1024"]):
        sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
        for a in algs:
            src.record_finding(sid, _f(a, f"cert {a}"))
        src.finish_scan(sid, status="done")
        res = fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, ident)), h.id)
    drift = [r for r in fleet.list_findings(res.scan_id) if r.probe_id == "fleet.drift"]
    assert len(drift) == 1 and drift[0].evidence["change"] == "added" and drift[0].evidence["algorithm"] == "RSA-1024"
    d = fleet.diff_findings(current_scan_id=res.scan_id, baseline_scan_id=res.scan_id - 1, parity=True)
    assert len(d["added"]) == 1          # drift rows themselves are excluded from parity diffs
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_parity_drift.py`
Expected: ImportError.

- [ ] **Step 3: Implement**

```python
# src/pqcscan/core/parity.py
"""Host-agnostic identity for a finding so two hosts (primary vs DR) can be compared."""
from __future__ import annotations

import re

from pqcscan.core.types import Classification, Finding, Severity

_HOSTPORT = re.compile(r"(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")
_AT_HOST = re.compile(r"\bat\s+\S+")
DRIFT_PROBE = "fleet.drift"


def _norm_title(title: str) -> str:
    t = _HOSTPORT.sub(r"<host>:\1", title)
    t = _AT_HOST.sub("at <host>", t)
    return re.sub(r"\s+", " ", t).strip()


def parity_key(probe_id: str, algorithm: str, title: str, evidence: dict) -> tuple[str, str, str]:
    ev = evidence or {}
    if ev.get("path"):
        return probe_id, algorithm, f"path={ev['path']}"
    if ev.get("endpoint"):
        m = _HOSTPORT.search(str(ev["endpoint"]))
        if m:
            return probe_id, algorithm, f"port={m.group(1)}"
    return probe_id, algorithm, _norm_title(title)


def drift_rows(previous: list, current: list) -> list[Finding]:
    def keys(rows):
        return {parity_key(r.probe_id, r.algorithm, r.title, r.evidence or {}): r
                for r in rows if r.probe_id != DRIFT_PROBE}
    prev, cur = keys(previous), keys(current)
    out: list[Finding] = []
    for k, r in cur.items():
        if k not in prev:
            out.append(_drift("added", r))
    for k, r in prev.items():
        if k not in cur:
            out.append(_drift("removed", r))
    return out


def _drift(change: str, r) -> Finding:
    return Finding(probe_id=DRIFT_PROBE, algorithm=r.algorithm, classification=Classification.INFO,
                   severity=Severity.INFO, title=f"drift: {change} {r.probe_id} {r.algorithm}",
                   evidence={"change": change, "probe_id": r.probe_id, "algorithm": r.algorithm, "title": r.title})
```

In `Repo.ingest_bundle`, after the findings loop and before `commit`: fetch the host's previous done scan (`select(Scan).where(Scan.host_id == host_id, Scan.status == "done", Scan.id != scan.id).order_by(Scan.started_at.desc()).limit(1)`), load its rows, build `drift_rows(prev_rows, new_rows)` where `new_rows` are the `FindingRow`s just added, and `s.add(FindingRow(scan_id=scan.id, ...))` for each drift finding. In `diff_findings` add `parity: bool = False`; when true use `parity_key(...)` as the key and skip rows with `probe_id == DRIFT_PROBE`. In `cli/fleet.py` `diff_cmd` add `--parity` flag passing through.

- [ ] **Step 4: Run tests, commit**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_parity_drift.py tests/unit/test_fleet_repo.py tests/unit/test_fleet_merge_diff.py tests/unit/test_baselines_diff.py`
Expected: all pass.

```bash
git add src/pqcscan/core/parity.py src/pqcscan/store/repo.py src/pqcscan/cli/fleet.py tests/unit/test_parity_drift.py
git commit -m "feat(fleet): host-agnostic parity key, fleet.drift findings on ingest, diff --parity

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 14: Host labels drive Mosca inputs in reports

**Files:**
- Modify: `src/pqcscan/renderers/_report_context.py:114-130` (`build_report_context`)
- Test: `tests/unit/test_labels_risk_inputs.py`

**Interfaces:**
- Produces: `mosca_from_labels(labels: dict[str, str]) -> MoscaInputs | None` (reads `data_lifetime`, `migration_years`, `threat_years`; None when absent/invalid); `build_report_context(...)` uses the scan's host labels when `mosca_inputs is None` and the scan has a `host_id`; the context gains `"host_labels": dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_labels_risk_inputs.py
from pqcscan.renderers._report_context import build_report_context, mosca_from_labels
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo


def test_mosca_from_labels():
    assert mosca_from_labels({"data_lifetime": "25", "migration_years": "4"}).data_lifetime_years == 25
    assert mosca_from_labels({"data_lifetime": "25"}).migration_years == 5.0     # default kept
    assert mosca_from_labels({}) is None and mosca_from_labels({"data_lifetime": "x"}) is None


def test_report_context_reads_host_labels(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "s.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    ident = HostIdentity(machine_id="m", hostname="core-db", os="linux", labels={"data_lifetime": "25"})
    h = fleet.upsert_host(ident)
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={}); src.finish_scan(sid, status="done")
    res = fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, ident)), h.id)
    ctx = build_report_context(fleet, res.scan_id, lang="en")
    assert ctx["mosca"]["x"] == 25.0 and ctx["mosca"]["assumed"] is False
    assert ctx["host_labels"] == {"data_lifetime": "25"}
```

- [ ] **Step 2: Implement**

In `_report_context.py`:

```python
def mosca_from_labels(labels: dict[str, str]) -> MoscaInputs | None:
    try:
        x = float(labels["data_lifetime"])
    except (KeyError, TypeError, ValueError):
        return None
    def _f(key: str, default: float) -> float:
        try:
            return float(labels.get(key, default))
        except (TypeError, ValueError):
            return default
    return MoscaInputs(data_lifetime_years=x, migration_years=_f("migration_years", 5.0),
                       threat_years=_f("threat_years", 10.0))
```

and in `build_report_context`, after loading `scan`: `host = repo.get_host(scan.host_id) if scan.host_id else None`; `labels = dict(host.labels or {}) if host else {}`; `if mosca_inputs is None and labels: mosca_inputs = mosca_from_labels(labels)`; add `"host_labels": labels` to the returned dict.

- [ ] **Step 3: Run tests, commit**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_labels_risk_inputs.py tests/unit/test_mosca.py tests/unit/test_reports_bilingual.py`

```bash
git add src/pqcscan/renderers/_report_context.py tests/unit/test_labels_risk_inputs.py
git commit -m "feat(reports): per-host labels (data_lifetime, migration_years, threat_years) drive Mosca inputs

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 15: `core/agility.py` — crypto-agility score

**Files:**
- Create: `src/pqcscan/core/agility.py`
- Modify: `src/pqcscan/renderers/_report_context.py` (context gains `agility`), `src/pqcscan/renderers/xlsx_bukukerja.py:484-494` (column reads the score), `src/pqcscan/renderers/_report_text.py` (label in EN/MS), `src/pqcscan/renderers/templates/pdf_technical.html` (one line in the summary)
- Test: `tests/unit/test_agility.py`

**Interfaces:**
- Produces: `finding_agility(probe_id: str, evidence: dict) -> int` (0–100); `score_findings(findings: list) -> AgilityResult(score: int, band: str, by_source: dict[str, int])` where `band` is `"high" (>=70) | "medium" (>=40) | "low"`; the rule table:

| Source (by probe id prefix / evidence) | Score | Rationale |
|---|---|---|
| `host.crypto_policies`, `host.java.security`, `host.openssl.*`, `fs.conf.*`, `app.*`, `host.ssh.*`, `host.gnutls`, `host.nss`, `host.windows.schannel`, `k8s.*`, `fs.iac.*` | 90 | policy/config change, no rebuild |
| `net.*` (negotiated at runtime) | 80 | server config change |
| `fs.cert.*`, `fs.keystore.*`, `email.*`, `dns.*`, `sign.*`, `trust.*`, `host.cloud_kms`, `fs.keyref.cloud` | 70 | re-issue / rotate |
| `sbom.*`, `container.*` | 50 | dependency upgrade + redeploy |
| `code.*` | 30 | source change |
| `fs.binary.crypto` with `evidence.detection == "constant-signature"` or `linked == "embedded"`; `storage.*`, `vpn.*` | 20 | rebuild / re-encrypt |
| `hw.*`, `host.tpm.*`, `ot.*`, `fs.conf.ibmi_sysval` | 10 | hardware / firmware / vendor |
| anything else | 50 | unknown |

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_agility.py
from types import SimpleNamespace

from pqcscan.core.agility import finding_agility, score_findings


def test_rule_table():
    assert finding_agility("fs.conf.nginx", {}) == 90
    assert finding_agility("net.tls.https", {}) == 80
    assert finding_agility("fs.cert.x509", {}) == 70
    assert finding_agility("sbom.lang.pip", {}) == 50
    assert finding_agility("code.ts.java", {}) == 30
    assert finding_agility("fs.binary.crypto", {"detection": "constant-signature"}) == 20
    assert finding_agility("fs.binary.crypto", {"linked": "linked"}) == 50
    assert finding_agility("hw.tpm_algorithms", {}) == 10
    assert finding_agility("ot.modbus.tcp", {}) == 10
    assert finding_agility("something.new", {}) == 50


def test_score_findings_weights_vulnerable_only():
    rows = [SimpleNamespace(probe_id="fs.conf.nginx", evidence={}, classification="sangat-tinggi"),
            SimpleNamespace(probe_id="ot.modbus.tcp", evidence={}, classification="sangat-tinggi"),
            SimpleNamespace(probe_id="host.platform_info", evidence={}, classification="info")]
    r = score_findings(rows)
    assert r.score == 50 and r.band == "medium" and r.by_source == {"config": 1, "hardware": 1}
    assert score_findings([]).score == 100 and score_findings([]).band == "high"
```

- [ ] **Step 2: Implement**

```python
# src/pqcscan/core/agility.py
"""Crypto-agility: how cheaply can this asset's cryptography be changed? 0 (rebuild hardware) to 100 (edit a config)."""
from __future__ import annotations

from dataclasses import dataclass, field

_VULNERABLE = {"sangat-tinggi", "tinggi", "sederhana"}
# (prefixes, score, source label) — first match wins; order matters.
_RULES: tuple[tuple[tuple[str, ...], int, str], ...] = (
    (("fs.conf.ibmi_sysval",), 10, "hardware"),
    (("hw.", "host.tpm", "ot."), 10, "hardware"),
    (("storage.", "vpn."), 20, "rebuild"),
    (("code.",), 30, "source"),
    (("sbom.", "container."), 50, "dependency"),
    (("fs.cert.", "fs.keystore.", "email.", "dns.", "sign.", "trust.", "host.cloud_kms", "fs.keyref.cloud"), 70, "rotate"),
    (("net.",), 80, "server-config"),
    (("host.crypto_policies", "host.java.security", "host.openssl.", "fs.conf.", "app.", "host.ssh.",
      "host.gnutls", "host.nss", "host.windows.schannel", "k8s.", "fs.iac."), 90, "config"),
)


def finding_agility(probe_id: str, evidence: dict) -> int:
    ev = evidence or {}
    if probe_id == "fs.binary.crypto":
        if ev.get("detection") == "constant-signature" or ev.get("linked") == "embedded":
            return 20
        return 50
    for prefixes, score, _src in _RULES:
        if probe_id.startswith(prefixes):
            return score
    return 50


def _source(probe_id: str, evidence: dict) -> str:
    if probe_id == "fs.binary.crypto":
        return "rebuild" if finding_agility(probe_id, evidence) == 20 else "dependency"
    for prefixes, _score, src in _RULES:
        if probe_id.startswith(prefixes):
            return src
    return "unknown"


@dataclass(slots=True)
class AgilityResult:
    score: int
    band: str
    by_source: dict[str, int] = field(default_factory=dict)


def score_findings(findings: list) -> AgilityResult:
    rows = [f for f in findings if str(getattr(f, "classification", "")) in _VULNERABLE]
    if not rows:
        return AgilityResult(100, "high", {})
    total = 0
    by: dict[str, int] = {}
    for f in rows:
        ev = getattr(f, "evidence", {}) or {}
        total += finding_agility(f.probe_id, ev)
        by[_source(f.probe_id, ev)] = by.get(_source(f.probe_id, ev), 0) + 1
    score = round(total / len(rows))
    return AgilityResult(score, "high" if score >= 70 else "medium" if score >= 40 else "low", by)
```

Report context: `"agility": asdict(score_findings(findings))`; `_report_text.py` gains `report.agility: "Crypto-agility" / "Ketangkasan kripto"`; `pdf_technical.html` prints `{{ t('report.agility') }}: {{ agility.score }}/100 ({{ agility.band }})` under the readiness gauge; BUKUKERJA CBOM sheet column: replace the Ya/Tidak Diketahui expression with `str(finding_agility(f.probe_id, ev))` (numeric, both locales).

- [ ] **Step 3: Run tests, commit**

Run: `PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_agility.py tests/unit/test_reports_bilingual.py tests/unit/test_renderer_d2.py`

```bash
git add src/pqcscan/core/agility.py src/pqcscan/renderers tests/unit/test_agility.py
git commit -m "feat(core): crypto-agility score per finding/host, surfaced in reports and BUKUKERJA

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 16: Retention default on ingest + release v0.10.2

**Files:**
- Modify: `src/pqcscan/daemon/fleet.py` (after a successful ingest, `repo.prune_scans(keep_per_host=keep)` for that host only — add `Repo.prune_host(host_id, keep)` in `repo.py`), `src/pqcscan/cli/daemon_cmd.py` (`--keep-scans-per-host`, default 12), `docs/FLEET.md`, `CHANGELOG.md`, `__init__.py` (`0.10.2`), pins, `docs/STATUS.md`, `docs/TODO.md` (replace the roadmap with the remaining gap list from the gap-analysis doc)
- Test: `tests/unit/test_daemon_fleet.py` gains `test_ingest_prunes_to_keep` (ingest 3 bundles with `keep_scans_per_host=2` → `host_history` has 2)

- [ ] **Step 1: Test, implement, run**

Add `keep_scans_per_host: int = 12` to `create_app` and `build_fleet_router`; after `res = repo.ingest_bundle(...)`: `repo.prune_host(host.id, keep_scans_per_host)`. `prune_host` is `prune_scans` restricted to one host (refactor `prune_scans` to call it). Test: three ingests with distinct `scan_uuid`s (use three source scans), assert `len(repo.host_history(1)) == 2`. The rate limiter blocks a second ingest within 60 s, so the test sets `INGEST_MIN_INTERVAL_S` to 0 via `monkeypatch.setattr(fleet_mod, "INGEST_MIN_INTERVAL_S", 0.0)` before building the app.

- [ ] **Step 2: Release**

Full suite + ruff + mypy green → `__version__ = "0.10.2"`, CHANGELOG `[0.10.2]` (drift, labels → Mosca, agility, retention), pins, STATUS/TODO refresh, commit `release: v0.10.2 — fleet phase 3 (drift, per-host risk inputs, crypto-agility, retention)`, push, PR, squash-merge, tag `v0.10.2`.

---

## Self-review

**Spec coverage.** §3.1 units → Tasks 1–7, 10–11, 13–15 (one task per unit; `cli/fleet.py` admin in 7). §3.2 data flow → Tasks 5–6, 8. §3.3 security → Task 5 (hashed tokens, bearer-only, size/rate caps, machine-id match), Task 6 (0600 token, 0700 spool), Task 9 docs. §3.4 scale → Task 1 (SQLite-only pragmas), Task 9 (`fleet-pg` extra, docs). §3.5 error table → Tasks 6, 10 (spool, backoff, 401 re-enroll; 413 split is **not** implemented — bundles are capped at dump time and a 413 is spooled like any other rejection; noted in FLEET.md as a known limit, revisit if real bundles exceed 8 MB gzip). §4 testing → unit tests per task, integration in Task 8 and 11; the 500-bundle load test is **not** in this plan (manual script in a follow-up; the per-host rate limit makes concurrent bursts from one host impossible by design). §5 phases → tags in Tasks 9, 12, 16. §6 non-goals respected.

**Placeholders.** None: every step has code or an exact command. Task 12's PowerShell/Ansible/BigFix files are described by their required contents and verified by `test_fleet_recipes.py`; the implementer writes them to that contract.

**Type consistency.** `HostIdentity` (Task 2) used by Tasks 3–6, 8, 10–11, 13–14 with the same fields; `IngestResult`/`HostSummary` (Task 3) consumed by Tasks 5, 7, 11; `ReportError.status` (Task 6) consumed by Task 10; `resolve_scan_ref` (Task 7) consumed by the daemon export; `parity_key`/`DRIFT_PROBE` (Task 13) consumed by `diff_findings(parity=True)`; `finding_agility` (Task 15) consumed by BUKUKERJA.

# pqcscan v2 — MVP Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the foundation of pqcscan v2 — a working `pqcscan` binary that scans the host with ~7 representative probes (one per family), streams findings live over SSE to a minimal web UI, exposes a headless CLI, persists results to SQLite, and exports a valid CycloneDX 1.6 CBOM.

**Architecture:** Single Python 3.11 process. asyncio event loop. FastAPI HTTP+SSE server. Probe runner topologically schedules probe classes that emit findings on an in-memory event bus. SQLAlchemy + SQLite for persistence. Jinja2 + HTMX + vendored Tailwind for UI. Click for CLI. Pytest for tests.

**Tech Stack:** Python 3.11, FastAPI, uvicorn, SQLAlchemy 2.x, sqlite3, Jinja2, HTMX 1.9, click, pydantic v2, loguru, cyclonedx-python-lib, cryptography, pytest, pytest-asyncio, ruff, mypy.

**Out of scope for this plan (covered in future plans B–F):** the other ~95 probes, compliance engine, PDF/XLSX renderers, baselines/diff, full UI (settings, frameworks, probes pages), PyInstaller packaging, offline pack, i18n EN/MS toggle.

---

## File structure produced by this plan

```
pqc-scanner2/
├── pyproject.toml
├── README.md                                # updated
├── .gitignore                               # already exists
├── .github/workflows/ci.yml
├── src/
│   └── pqcscan/
│       ├── __init__.py
│       ├── __main__.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── types.py
│       │   └── alg.py
│       ├── store/
│       │   ├── __init__.py
│       │   ├── schema.py
│       │   ├── repo.py
│       │   └── migrations.py
│       ├── runner/
│       │   ├── __init__.py
│       │   ├── event_bus.py
│       │   ├── capabilities.py
│       │   └── runner.py
│       ├── probes/
│       │   ├── __init__.py
│       │   ├── _base.py
│       │   ├── _registry.py
│       │   ├── host_openssl_config.py
│       │   ├── sbom_os_dpkg.py
│       │   ├── net_tls_https.py
│       │   ├── fs_cert_x509.py
│       │   ├── code_ts_python.py
│       │   ├── pqc_alg_normaliser.py
│       │   └── aux_clock_cert_validity.py
│       ├── cbom/
│       │   ├── __init__.py
│       │   └── builder.py
│       ├── daemon/
│       │   ├── __init__.py
│       │   ├── app.py
│       │   └── sse.py
│       ├── ui/
│       │   ├── __init__.py
│       │   ├── routes.py
│       │   ├── templates/
│       │   │   ├── base.html
│       │   │   ├── dashboard.html
│       │   │   ├── scans_list.html
│       │   │   └── scan_detail.html
│       │   └── static/
│       │       ├── htmx-1.9.10.min.js
│       │       └── tailwind.min.css
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py
│       │   ├── scan.py
│       │   ├── daemon_cmd.py
│       │   └── export.py
│       └── util/
│           ├── __init__.py
│           └── paths.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── unit/
    │   ├── test_types.py
    │   ├── test_alg.py
    │   ├── test_store_schema.py
    │   ├── test_store_repo.py
    │   ├── test_capabilities.py
    │   ├── test_event_bus.py
    │   ├── test_registry.py
    │   ├── test_registry_default_seed.py
    │   ├── test_runner.py
    │   ├── test_probe_host_openssl_config.py
    │   ├── test_probe_net_tls_https.py
    │   ├── test_probe_fs_cert_x509.py
    │   ├── test_probe_sbom_os_dpkg.py
    │   ├── test_probe_code_ts_python.py
    │   ├── test_probe_pqc_alg_normaliser.py
    │   └── test_cbom_builder.py
    └── integration/
        ├── __init__.py
        ├── test_daemon_api.py
        ├── test_ui.py
        ├── test_cli_scan.py
        └── test_end_to_end.py
```

---

## Phase 1 — Project skeleton

### Task 1: Initialise pyproject.toml and src layout

**Files:**
- Create: `pyproject.toml`
- Create: `src/pqcscan/__init__.py`
- Create: `src/pqcscan/__main__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write pyproject.toml**

```toml
[build-system]
requires = ["hatchling>=1.21"]
build-backend = "hatchling.build"

[project]
name = "pqcscan"
version = "0.1.0"
description = "Post-Quantum Cryptography readiness scanner (v2)"
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.11"
dependencies = [
  "fastapi>=0.110",
  "uvicorn[standard]>=0.27",
  "sqlalchemy>=2.0",
  "jinja2>=3.1",
  "click>=8.1",
  "pydantic>=2.6",
  "loguru>=0.7",
  "cyclonedx-python-lib>=7.6",
  "cryptography>=42",
  "httpx>=0.27",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0",
  "pytest-asyncio>=0.23",
  "pytest-cov>=4.1",
  "ruff>=0.4",
  "mypy>=1.10",
]

[project.scripts]
pqcscan = "pqcscan.cli.main:cli"

[tool.hatch.build.targets.wheel]
packages = ["src/pqcscan"]

[tool.hatch.build.targets.wheel.force-include]
"src/pqcscan/ui/templates" = "pqcscan/ui/templates"
"src/pqcscan/ui/static"    = "pqcscan/ui/static"

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
addopts = "-ra --strict-markers"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP", "B", "SIM", "ASYNC", "RUF"]

[tool.mypy]
python_version = "3.11"
strict = true
files = ["src/pqcscan"]
```

- [ ] **Step 2: Create package init**

`src/pqcscan/__init__.py`:
```python
__version__ = "0.1.0"
```

- [ ] **Step 3: Create entry-point module**

`src/pqcscan/__main__.py`:
```python
from pqcscan.cli.main import cli

if __name__ == "__main__":
    cli()
```

- [ ] **Step 4: Create tests/__init__.py and conftest.py**

`tests/__init__.py`: empty file.

`tests/conftest.py`:
```python
import pytest
from pathlib import Path


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """A fresh on-disk SQLite path per test."""
    return tmp_path / "pqcscan-test.db"


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path
```

- [ ] **Step 5: Install + sanity check**

Run: `pip install -e ".[dev]" && python -c "import pqcscan; print(pqcscan.__version__)"`
Expected: `0.1.0`

Run: `pytest -q`
Expected: `no tests ran` (zero tests yet, exit 0)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/ tests/
git commit -m "feat: scaffold src layout, pyproject, dev deps"
```

---

### Task 2: Add CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write GitHub Actions CI**

`.github/workflows/ci.yml`:
```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest]
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install
        run: pip install -e ".[dev]"
      - name: Lint
        run: ruff check src/ tests/
      - name: Type-check
        run: mypy src/pqcscan
      - name: Test
        run: pytest -q --cov=pqcscan --cov-report=term-missing
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add ruff + mypy + pytest workflow"
```

---

## Phase 2 — Core types & algorithm normaliser

### Task 3: Define Capability + ProbeFamily + Classification + Severity enums

**Files:**
- Create: `src/pqcscan/core/__init__.py`
- Create: `src/pqcscan/core/types.py`
- Test: `tests/unit/test_types.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_types.py`:
```python
from pqcscan.core.types import Capability, ProbeFamily, Classification, Severity


def test_capability_values():
    assert Capability.ROOT.value == "root"
    assert Capability.NET_RAW.value == "net_raw"
    assert Capability.DAC_READ_SEARCH.value == "dac_read_search"
    assert Capability.KUBECTL.value == "kubectl"
    assert Capability.CONTAINER_RT.value == "container_rt"


def test_probe_family_includes_v1_families():
    expected = {
        "host", "sbom", "network", "filesystem", "code",
        "vpn", "storage", "container", "app", "sign",
        "dns_email", "pqc_meta", "aux",
    }
    actual = {f.value for f in ProbeFamily}
    assert actual == expected


def test_classification_includes_malay_terms():
    expected = {
        "sangat-tinggi", "tinggi", "sederhana", "rendah",
        "pqc-ready", "info", "error",
    }
    actual = {c.value for c in Classification}
    assert actual == expected


def test_severity_ordering():
    assert Severity.CRIT.numeric > Severity.HIGH.numeric
    assert Severity.HIGH.numeric > Severity.MED.numeric
    assert Severity.MED.numeric > Severity.LOW.numeric
    assert Severity.LOW.numeric > Severity.INFO.numeric
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_types.py -v`
Expected: `ModuleNotFoundError: No module named 'pqcscan.core'`

- [ ] **Step 3: Write minimal implementation**

`src/pqcscan/core/__init__.py`: empty.

`src/pqcscan/core/types.py`:
```python
from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    ROOT = "root"
    NET_RAW = "net_raw"
    DAC_READ_SEARCH = "dac_read_search"
    KUBECTL = "kubectl"
    CONTAINER_RT = "container_rt"


class ProbeFamily(str, Enum):
    HOST = "host"
    SBOM = "sbom"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    CODE = "code"
    VPN = "vpn"
    STORAGE = "storage"
    CONTAINER = "container"
    APP = "app"
    SIGN = "sign"
    DNS_EMAIL = "dns_email"
    PQC_META = "pqc_meta"
    AUX = "aux"


class Classification(str, Enum):
    SANGAT_TINGGI = "sangat-tinggi"
    TINGGI = "tinggi"
    SEDERHANA = "sederhana"
    RENDAH = "rendah"
    PQC_READY = "pqc-ready"
    INFO = "info"
    ERROR = "error"


class Severity(str, Enum):
    CRIT = "crit"
    HIGH = "high"
    MED = "med"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> int:
        return {"info": 0, "low": 1, "med": 2, "high": 3, "crit": 4}[self.value]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_types.py -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/core/ tests/unit/test_types.py
git commit -m "feat: core enums for Capability, ProbeFamily, Classification, Severity"
```

---

### Task 4: Define Finding and Component dataclasses

**Files:**
- Modify: `src/pqcscan/core/types.py`
- Modify: `tests/unit/test_types.py`

- [ ] **Step 1: Add the failing test**

Append to `tests/unit/test_types.py`:
```python
from datetime import datetime
from pqcscan.core.types import Finding, Component


def test_component_purl_round_trip():
    c = Component(
        purl="pkg:deb/debian/openssl@3.0.2-1ubuntu1.10",
        type="os-pkg",
        name="openssl",
        version="3.0.2-1ubuntu1.10",
        location="/usr/bin/openssl",
        discovered_by="sbom.os.dpkg",
    )
    assert c.purl.startswith("pkg:deb/")
    assert c.attributes == {}


def test_finding_minimal():
    f = Finding(
        probe_id="host.openssl.config",
        algorithm="RSA-2048",
        classification=Classification.TINGGI,
        severity=Severity.HIGH,
        title="RSA-2048 in default cipher list",
    )
    assert f.evidence == {}
    assert f.remediation == {}
    assert f.created_at <= datetime.utcnow()


def test_finding_with_component_purl():
    f = Finding(
        probe_id="fs.cert.x509",
        algorithm="sha1WithRSAEncryption",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="SHA-1 signature on cert",
        component_purl="pkg:file/etc/ssl/certs/legacy.pem",
    )
    assert f.component_purl is not None
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_types.py -v`
Expected: `ImportError: cannot import name 'Finding'`

- [ ] **Step 3: Implement**

Append to `src/pqcscan/core/types.py`:
```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Component:
    purl: str
    type: str  # os-pkg | lib | service | cert | key | file | app | container
    name: str
    version: str | None = None
    location: str = ""
    discovered_by: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    probe_id: str
    algorithm: str
    classification: Classification
    severity: Severity
    title: str
    component_purl: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_types.py -v`
Expected: 7 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/core/types.py tests/unit/test_types.py
git commit -m "feat: Finding and Component dataclasses"
```

---

### Task 5: Algorithm normaliser

**Files:**
- Create: `src/pqcscan/core/alg.py`
- Test: `tests/unit/test_alg.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_alg.py`:
```python
from pqcscan.core.alg import normalise, classify
from pqcscan.core.types import Classification


def test_normalise_oid():
    assert normalise("1.2.840.113549.1.1.11") == "RSA-SHA256"


def test_normalise_friendly_name():
    assert normalise("sha256WithRSAEncryption") == "RSA-SHA256"


def test_normalise_lib_name():
    assert normalise("RSA-SHA256") == "RSA-SHA256"


def test_normalise_unknown_passthrough():
    assert normalise("some-weird-alg") == "SOME-WEIRD-ALG"


def test_classify_rsa_2048_is_tinggi():
    assert classify("RSA-2048") == Classification.TINGGI


def test_classify_rsa_1024_is_sangat_tinggi():
    assert classify("RSA-1024") == Classification.SANGAT_TINGGI


def test_classify_md5_is_sangat_tinggi():
    assert classify("MD5") == Classification.SANGAT_TINGGI


def test_classify_aes_256_gcm_is_rendah():
    assert classify("AES-256-GCM") == Classification.RENDAH


def test_classify_ml_kem_768_is_pqc_ready():
    assert classify("ML-KEM-768") == Classification.PQC_READY


def test_classify_hybrid_is_pqc_ready():
    assert classify("X25519MLKEM768") == Classification.PQC_READY


def test_classify_unknown_is_info():
    assert classify("totally-unknown-alg") == Classification.INFO
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_alg.py -v`
Expected: `ModuleNotFoundError: No module named 'pqcscan.core.alg'`

- [ ] **Step 3: Implement**

`src/pqcscan/core/alg.py`:
```python
from __future__ import annotations

import re

from pqcscan.core.types import Classification


_OID_MAP: dict[str, str] = {
    "1.2.840.113549.1.1.5": "RSA-SHA1",
    "1.2.840.113549.1.1.11": "RSA-SHA256",
    "1.2.840.113549.1.1.12": "RSA-SHA384",
    "1.2.840.113549.1.1.13": "RSA-SHA512",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.3.101.112": "Ed25519",
    "1.3.6.1.4.1.2.267.7.4.4": "ML-DSA-44",
    "1.3.6.1.4.1.2.267.7.6.5": "ML-DSA-65",
}

_FRIENDLY_MAP: dict[str, str] = {
    "sha256withrsaencryption": "RSA-SHA256",
    "sha384withrsaencryption": "RSA-SHA384",
    "sha512withrsaencryption": "RSA-SHA512",
    "sha1withrsaencryption": "RSA-SHA1",
    "ecdsa-with-sha256": "ECDSA-SHA256",
    "ecdsa-with-sha384": "ECDSA-SHA384",
    "ed25519": "Ed25519",
    "id-ml-kem-512": "ML-KEM-512",
    "id-ml-kem-768": "ML-KEM-768",
    "id-ml-kem-1024": "ML-KEM-1024",
    "id-ml-dsa-44": "ML-DSA-44",
    "id-ml-dsa-65": "ML-DSA-65",
    "id-ml-dsa-87": "ML-DSA-87",
}


def normalise(s: str) -> str:
    """Return canonical algorithm name; unknown values are upper-cased."""
    if s in _OID_MAP:
        return _OID_MAP[s]
    key = s.lower().strip()
    if key in _FRIENDLY_MAP:
        return _FRIENDLY_MAP[key]
    return s.upper()


_RSA_RE = re.compile(r"^RSA-?(\d+)$", re.IGNORECASE)
_DH_RE = re.compile(r"^DH-?(\d+)$", re.IGNORECASE)


def classify(alg: str) -> Classification:
    """Map a normalised algorithm to a PQC threat classification."""
    a = normalise(alg).upper()

    pqc_ready_prefixes = (
        "ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "SPHINCS",
        "X25519MLKEM768", "P256+ML-KEM", "X448MLKEM",
    )
    if any(a.startswith(p.upper()) for p in pqc_ready_prefixes):
        return Classification.PQC_READY

    if a in {"MD5", "SHA-1", "RC4", "DES", "3DES", "TRIPLEDES", "DSA"}:
        return Classification.SANGAT_TINGGI

    if m := _RSA_RE.match(a):
        bits = int(m.group(1))
        if bits < 3072:
            return Classification.SANGAT_TINGGI
        return Classification.TINGGI

    if m := _DH_RE.match(a):
        bits = int(m.group(1))
        if bits < 3072:
            return Classification.SANGAT_TINGGI
        return Classification.TINGGI

    if a.startswith("ECDSA-") or a in {"ED25519"}:
        return Classification.TINGGI

    if a.startswith("AES-128-GCM") or a == "AES-128-GCM":
        return Classification.SEDERHANA
    if a.startswith("AES-128"):
        return Classification.TINGGI
    if a.startswith("AES-256"):
        return Classification.RENDAH

    if a in {"SHA-256", "SHA256"}:
        return Classification.SEDERHANA
    if a in {"SHA-384", "SHA384", "SHA-512", "SHA512"}:
        return Classification.RENDAH

    return Classification.INFO
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_alg.py -v`
Expected: 11 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/core/alg.py tests/unit/test_alg.py
git commit -m "feat: algorithm normaliser and PQC classifier"
```

---

## Phase 3 — Storage layer

### Task 6: SQLAlchemy schema for scans, components, findings

**Files:**
- Create: `src/pqcscan/store/__init__.py`
- Create: `src/pqcscan/store/schema.py`
- Test: `tests/unit/test_store_schema.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_store_schema.py`:
```python
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pqcscan.store.schema import Base, Scan, ComponentRow, FindingRow


def test_create_all_yields_six_tables(tmp_db_path):
    engine = create_engine(f"sqlite:///{tmp_db_path}")
    Base.metadata.create_all(engine)
    table_names = set(Base.metadata.tables.keys())
    expected = {"scans", "components", "findings", "graph_edges",
                "framework_views", "baselines"}
    assert table_names == expected


def test_scan_round_trip(tmp_db_path):
    engine = create_engine(f"sqlite:///{tmp_db_path}")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        scan = Scan(
            started_at=datetime.utcnow(),
            host_fingerprint="abc123",
            mode="user",
            status="running",
            probe_versions={"host.openssl.config": "0.1"},
            tool_versions={},
        )
        s.add(scan); s.commit()
        assert scan.id is not None


def test_finding_fk_to_scan(tmp_db_path):
    engine = create_engine(f"sqlite:///{tmp_db_path}")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        scan = Scan(started_at=datetime.utcnow(), mode="user", status="running",
                    probe_versions={}, tool_versions={})
        s.add(scan); s.commit()
        f = FindingRow(
            scan_id=scan.id,
            probe_id="host.openssl.config",
            algorithm="RSA-2048",
            classification="tinggi",
            severity="high",
            title="weak default cipher",
            evidence={"line": 42},
            remediation={},
        )
        s.add(f); s.commit()
        assert f.id is not None
        assert f.scan_id == scan.id
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_store_schema.py -v`
Expected: `ModuleNotFoundError: No module named 'pqcscan.store'`

- [ ] **Step 3: Implement**

`src/pqcscan/store/__init__.py`: empty.

`src/pqcscan/store/schema.py`:
```python
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON, ForeignKey, Index, String, Text, DateTime, Date, Integer,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    host_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mode: Mapped[str] = mapped_column(String(8))                # root | user
    status: Mapped[str] = mapped_column(String(16), index=True) # running | done | failed
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    probe_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ComponentRow(Base):
    __tablename__ = "components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    purl: Mapped[str] = mapped_column(String(512), index=True)
    type: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    location: Mapped[str] = mapped_column(Text, default="")
    discovered_by: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    __table_args__ = (Index("ix_components_scan_type", "scan_id", "type"),)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    component_id: Mapped[int | None] = mapped_column(ForeignKey("components.id"),
                                                      nullable=True, index=True)
    probe_id: Mapped[str] = mapped_column(String(64))
    algorithm: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    remediation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("components.id"))
    dst_id: Mapped[int] = mapped_column(ForeignKey("components.id"))
    edge_type: Mapped[str] = mapped_column(String(32), index=True)
    attrs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class FrameworkView(Base):
    __tablename__ = "framework_views"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    framework: Mapped[str] = mapped_column(String(32), index=True)
    clause: Mapped[str] = mapped_column(String(128))
    verdict: Mapped[str] = mapped_column(String(32))
    deadline: Mapped[Any | None] = mapped_column(Date, nullable=True)


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    label: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_store_schema.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/store/ tests/unit/test_store_schema.py
git commit -m "feat: SQLAlchemy schema for scans/components/findings/edges/frameworks/baselines"
```

---

### Task 7: Repo helpers (write a scan, write findings, list scans)

**Files:**
- Create: `src/pqcscan/store/repo.py`
- Create: `src/pqcscan/store/migrations.py`
- Test: `tests/unit/test_store_repo.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_store_repo.py`:
```python
from pqcscan.store.repo import Repo
from pqcscan.core.types import Finding, Classification, Severity


def test_init_creates_schema(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    repo.init_schema()  # idempotent


def test_create_scan_and_finish(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={"x": "1"}, tool_versions={})
    assert scan_id > 0
    repo.finish_scan(scan_id, status="done")
    scans = repo.list_scans()
    assert len(scans) == 1 and scans[0].status == "done"


def test_record_finding_round_trip(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    f = Finding(
        probe_id="host.openssl.config",
        algorithm="RSA-2048",
        classification=Classification.TINGGI,
        severity=Severity.HIGH,
        title="weak cipher",
        evidence={"line": 42},
    )
    repo.record_finding(scan_id, f)
    rows = repo.list_findings(scan_id)
    assert len(rows) == 1 and rows[0].algorithm == "RSA-2048"


def test_record_probe_error(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_probe_error(scan_id, probe_id="net.tls.https", message="connection refused")
    rows = repo.list_findings(scan_id)
    assert len(rows) == 1
    assert rows[0].classification == "error"
    assert rows[0].severity == "info"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_store_repo.py -v`
Expected: `ModuleNotFoundError: No module named 'pqcscan.store.repo'`

- [ ] **Step 3: Implement**

`src/pqcscan/store/migrations.py`:
```python
from __future__ import annotations

from sqlalchemy import Engine

from pqcscan.store.schema import Base


def apply(engine: Engine) -> None:
    """Create all tables. Idempotent."""
    Base.metadata.create_all(engine)
```

`src/pqcscan/store/repo.py`:
```python
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from pqcscan.core.types import Finding
from pqcscan.store import migrations
from pqcscan.store.schema import FindingRow, Scan


class Repo:
    def __init__(self, db_path: Path | str):
        self.engine = create_engine(f"sqlite:///{db_path}", future=True)

    def init_schema(self) -> None:
        migrations.apply(self.engine)

    def create_scan(
        self,
        *,
        mode: str,
        probe_versions: dict[str, str],
        tool_versions: dict[str, str],
        host_fingerprint: str | None = None,
    ) -> int:
        with Session(self.engine) as s:
            scan = Scan(
                started_at=datetime.utcnow(),
                host_fingerprint=host_fingerprint,
                mode=mode,
                status="running",
                probe_versions=probe_versions,
                tool_versions=tool_versions,
            )
            s.add(scan); s.commit()
            return scan.id

    def finish_scan(self, scan_id: int, *, status: str) -> None:
        with Session(self.engine) as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise ValueError(f"scan {scan_id} not found")
            scan.status = status
            scan.finished_at = datetime.utcnow()
            s.commit()

    def record_finding(self, scan_id: int, f: Finding) -> int:
        with Session(self.engine) as s:
            row = FindingRow(
                scan_id=scan_id,
                probe_id=f.probe_id,
                algorithm=f.algorithm,
                classification=f.classification.value,
                severity=f.severity.value,
                title=f.title,
                evidence=f.evidence,
                remediation=f.remediation,
                created_at=f.created_at,
            )
            s.add(row); s.commit()
            return row.id

    def record_probe_error(self, scan_id: int, *, probe_id: str, message: str) -> int:
        with Session(self.engine) as s:
            row = FindingRow(
                scan_id=scan_id,
                probe_id=probe_id,
                algorithm="N/A",
                classification="error",
                severity="info",
                title=f"probe error: {message}",
                evidence={"error": message},
                remediation={},
            )
            s.add(row); s.commit()
            return row.id

    def list_scans(self) -> list[Scan]:
        with Session(self.engine) as s:
            return list(
                s.execute(select(Scan).order_by(Scan.started_at.desc())).scalars()
            )

    def list_findings(self, scan_id: int) -> list[FindingRow]:
        with Session(self.engine) as s:
            return list(
                s.execute(
                    select(FindingRow)
                    .where(FindingRow.scan_id == scan_id)
                    .order_by(FindingRow.created_at)
                ).scalars()
            )

    def get_scan(self, scan_id: int) -> Scan | None:
        with Session(self.engine) as s:
            return s.get(Scan, scan_id)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_store_repo.py -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/store/repo.py src/pqcscan/store/migrations.py tests/unit/test_store_repo.py
git commit -m "feat: store.Repo for scan/finding CRUD"
```

---

## Phase 4 — Probe model + runner

### Task 8: Probe ABC and Capability detector

**Files:**
- Create: `src/pqcscan/probes/__init__.py`
- Create: `src/pqcscan/probes/_base.py`
- Create: `src/pqcscan/runner/__init__.py`
- Create: `src/pqcscan/runner/capabilities.py`
- Test: `tests/unit/test_capabilities.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_capabilities.py`:
```python
import os
from pqcscan.runner.capabilities import detect_capabilities, current_mode
from pqcscan.core.types import Capability


def test_current_mode_returns_user_or_root():
    mode = current_mode()
    assert mode in {"user", "root"}


def test_detect_capabilities_returns_set():
    caps = detect_capabilities()
    assert isinstance(caps, set)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        assert Capability.ROOT not in caps
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_capabilities.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/probes/__init__.py`: empty.

`src/pqcscan/probes/_base.py`:
```python
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from pqcscan.core.types import Capability, Finding, ProbeFamily


@dataclass(slots=True)
class ScanContext:
    scan_id: int
    mode: str  # "root" | "user"
    available_capabilities: set[Capability]
    scan_paths: list[Path] = field(default_factory=list)
    server_target: str | None = None


Emitter = Callable[[Finding], None]


class Probe(ABC):
    """Base class for all probes. Subclasses set class-level metadata."""

    id: str = ""
    family: ProbeFamily = ProbeFamily.AUX
    requires: frozenset[Capability] = frozenset()
    framework_tags: tuple[str, ...] = ()
    enabled_default: bool = True
    version: str = "0.1.0"

    async def applies(self, ctx: ScanContext) -> bool:
        """Quick gate. Default: yes if all required caps are available."""
        return self.requires.issubset(ctx.available_capabilities)

    @abstractmethod
    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        """Do the work; call emit(Finding(...)) for each result."""
        raise NotImplementedError
```

`src/pqcscan/runner/__init__.py`: empty.

`src/pqcscan/runner/capabilities.py`:
```python
from __future__ import annotations

import os
import sys

from pqcscan.core.types import Capability


def current_mode() -> str:
    """Return 'root' if effective uid is 0 (or Windows admin), else 'user'."""
    if sys.platform == "win32":
        try:
            import ctypes
            return "root" if ctypes.windll.shell32.IsUserAnAdmin() else "user"  # type: ignore[attr-defined]
        except Exception:
            return "user"
    return "root" if os.geteuid() == 0 else "user"


def detect_capabilities() -> set[Capability]:
    """Best-effort detection of what this process can do."""
    caps: set[Capability] = set()
    if current_mode() == "root":
        caps.add(Capability.ROOT)
        caps.add(Capability.NET_RAW)
        caps.add(Capability.DAC_READ_SEARCH)

    from shutil import which
    if which("kubectl"):
        caps.add(Capability.KUBECTL)
    if which("docker") or which("podman") or which("nerdctl"):
        caps.add(Capability.CONTAINER_RT)

    return caps
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_capabilities.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/_base.py src/pqcscan/probes/__init__.py \
        src/pqcscan/runner/__init__.py src/pqcscan/runner/capabilities.py \
        tests/unit/test_capabilities.py
git commit -m "feat: Probe ABC + capability detection"
```

---

### Task 9: Async event bus

**Files:**
- Create: `src/pqcscan/runner/event_bus.py`
- Test: `tests/unit/test_event_bus.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_event_bus.py`:
```python
import asyncio
import pytest

from pqcscan.runner.event_bus import (
    EventBus, FindingDiscovered, ScanCompleted, StageStarted, StageCompleted,
)


@pytest.mark.asyncio
async def test_pub_sub_one_subscriber():
    bus = EventBus()
    received: list = []

    async def consumer():
        async for ev in bus.subscribe():
            received.append(ev)
            if isinstance(ev, ScanCompleted):
                break

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0)
    await bus.publish(StageStarted(stage="host"))
    await bus.publish(FindingDiscovered(probe_id="x", title="t", algorithm="A",
                                        classification="info", severity="info"))
    await bus.publish(StageCompleted(stage="host"))
    await bus.publish(ScanCompleted(scan_id=1))
    await asyncio.wait_for(task, timeout=1.0)

    assert len(received) == 4
    assert isinstance(received[-1], ScanCompleted)


@pytest.mark.asyncio
async def test_two_subscribers_get_same_events():
    bus = EventBus()
    a, b = [], []

    async def consume(out):
        async for ev in bus.subscribe():
            out.append(ev)
            if isinstance(ev, ScanCompleted):
                return

    t1 = asyncio.create_task(consume(a))
    t2 = asyncio.create_task(consume(b))
    await asyncio.sleep(0)
    await bus.publish(ScanCompleted(scan_id=1))
    await asyncio.gather(t1, t2)
    assert len(a) == 1 and len(b) == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_event_bus.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/runner/event_bus.py`:
```python
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class StageStarted:
    stage: str


@dataclass(slots=True, frozen=True)
class StageCompleted:
    stage: str


@dataclass(slots=True, frozen=True)
class FindingDiscovered:
    probe_id: str
    title: str
    algorithm: str
    classification: str
    severity: str


@dataclass(slots=True, frozen=True)
class ScanCompleted:
    scan_id: int


Event = StageStarted | StageCompleted | FindingDiscovered | ScanCompleted


class EventBus:
    """In-memory pub/sub: each subscribe() returns its own queue."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._lock = asyncio.Lock()

    async def publish(self, event: Event) -> None:
        async with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            await q.put(event)

    async def subscribe(self) -> AsyncIterator[Event]:
        q: asyncio.Queue[Event] = asyncio.Queue()
        async with self._lock:
            self._subscribers.append(q)
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                if q in self._subscribers:
                    self._subscribers.remove(q)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_event_bus.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/runner/event_bus.py tests/unit/test_event_bus.py
git commit -m "feat: async event bus with multi-subscriber support"
```

---

### Task 10: Probe registry

**Files:**
- Create: `src/pqcscan/probes/_registry.py`
- Test: `tests/unit/test_registry.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_registry.py`:
```python
from pqcscan.probes._registry import Registry
from pqcscan.probes._base import Probe
from pqcscan.core.types import ProbeFamily


class _FakeProbe(Probe):
    id = "test.fake"
    family = ProbeFamily.AUX

    async def run(self, ctx, emit):
        return None


def test_registry_register_and_list():
    reg = Registry()
    reg.register(_FakeProbe())
    assert "test.fake" in reg.ids()
    assert isinstance(reg.get("test.fake"), _FakeProbe)


def test_registry_filter_by_family():
    reg = Registry()
    reg.register(_FakeProbe())
    aux = list(reg.by_family(ProbeFamily.AUX))
    assert len(aux) == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_registry.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/probes/_registry.py`:
```python
from __future__ import annotations

from collections.abc import Iterator

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Probe


class Registry:
    def __init__(self) -> None:
        self._probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        if not probe.id:
            raise ValueError(f"probe {type(probe).__name__} has empty id")
        if probe.id in self._probes:
            raise ValueError(f"duplicate probe id: {probe.id}")
        self._probes[probe.id] = probe

    def get(self, probe_id: str) -> Probe:
        return self._probes[probe_id]

    def ids(self) -> list[str]:
        return list(self._probes.keys())

    def all(self) -> Iterator[Probe]:
        return iter(self._probes.values())

    def by_family(self, family: ProbeFamily) -> Iterator[Probe]:
        return (p for p in self._probes.values() if p.family is family)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_registry.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/_registry.py tests/unit/test_registry.py
git commit -m "feat: Probe registry"
```

---

### Task 11: ProbeRunner — orchestrates probes, emits events, persists

**Files:**
- Create: `src/pqcscan/runner/runner.py`
- Test: `tests/unit/test_runner.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_runner.py`:
```python
import pytest
from pqcscan.runner.runner import ProbeRunner
from pqcscan.runner.event_bus import EventBus
from pqcscan.probes._registry import Registry
from pqcscan.probes._base import Probe
from pqcscan.core.types import (
    Capability, Classification, Finding, ProbeFamily, Severity,
)
from pqcscan.store.repo import Repo


class _OneFindingProbe(Probe):
    id = "test.one"
    family = ProbeFamily.AUX

    async def run(self, ctx, emit):
        emit(Finding(
            probe_id=self.id,
            algorithm="RSA-2048",
            classification=Classification.TINGGI,
            severity=Severity.HIGH,
            title="hello",
        ))


class _RootOnlyProbe(Probe):
    id = "test.root"
    family = ProbeFamily.AUX
    requires = frozenset({Capability.ROOT})

    async def run(self, ctx, emit):
        emit(Finding(probe_id=self.id, algorithm="X",
                     classification=Classification.INFO,
                     severity=Severity.INFO,
                     title="should not fire in user mode"))


class _CrashProbe(Probe):
    id = "test.crash"
    family = ProbeFamily.AUX

    async def run(self, ctx, emit):
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_runner_emits_findings_and_persists(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    bus = EventBus()
    reg = Registry(); reg.register(_OneFindingProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=bus)
    scan_id = await runner.run(mode="user", available_capabilities=set())
    findings = repo.list_findings(scan_id)
    assert len(findings) == 1 and findings[0].title == "hello"


@pytest.mark.asyncio
async def test_root_only_probe_skipped_in_user_mode(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    bus = EventBus()
    reg = Registry(); reg.register(_RootOnlyProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=bus)
    scan_id = await runner.run(mode="user", available_capabilities=set())
    findings = repo.list_findings(scan_id)
    assert len(findings) == 1
    assert findings[0].classification == "info"
    assert "skipped" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_crash_does_not_abort_run(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    bus = EventBus()
    reg = Registry(); reg.register(_CrashProbe()); reg.register(_OneFindingProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=bus)
    scan_id = await runner.run(mode="user", available_capabilities=set())
    findings = repo.list_findings(scan_id)
    classifications = {f.classification for f in findings}
    assert "error" in classifications
    assert "tinggi" in classifications
    scan = repo.get_scan(scan_id)
    assert scan is not None and scan.status == "done"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_runner.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/runner/runner.py`:
```python
from __future__ import annotations

import asyncio
import platform
from collections import defaultdict

from loguru import logger

from pqcscan.core.types import Capability, Classification, Finding, Severity
from pqcscan.probes._base import Probe, ScanContext
from pqcscan.probes._registry import Registry
from pqcscan.runner.event_bus import (
    EventBus, FindingDiscovered, ScanCompleted, StageCompleted, StageStarted,
)
from pqcscan.store.repo import Repo


class ProbeRunner:
    def __init__(
        self,
        *,
        registry: Registry,
        repo: Repo,
        bus: EventBus,
        per_probe_timeout_s: float = 30.0,
    ) -> None:
        self.registry = registry
        self.repo = repo
        self.bus = bus
        self.timeout = per_probe_timeout_s

    async def run(self, *, mode: str, available_capabilities: set[Capability]) -> int:
        probe_versions = {p.id: p.version for p in self.registry.all()}
        scan_id = self.repo.create_scan(
            mode=mode,
            probe_versions=probe_versions,
            tool_versions={"python": platform.python_version()},
        )
        ctx = ScanContext(
            scan_id=scan_id,
            mode=mode,
            available_capabilities=available_capabilities,
        )

        by_family: dict[str, list[Probe]] = defaultdict(list)
        for p in self.registry.all():
            by_family[p.family.value].append(p)

        for family_name, probes in by_family.items():
            await self.bus.publish(StageStarted(stage=family_name))
            await asyncio.gather(*(self._run_one(p, ctx) for p in probes))
            await self.bus.publish(StageCompleted(stage=family_name))

        self.repo.finish_scan(scan_id, status="done")
        await self.bus.publish(ScanCompleted(scan_id=scan_id))
        return scan_id

    async def _run_one(self, probe: Probe, ctx: ScanContext) -> None:
        if not probe.requires.issubset(ctx.available_capabilities):
            self.repo.record_finding(ctx.scan_id, Finding(
                probe_id=probe.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"skipped: probe requires {sorted(c.value for c in probe.requires)}",
                evidence={"reason": "skipped_privilege"},
            ))
            return
        if not await probe.applies(ctx):
            return

        def emit(f: Finding) -> None:
            self.repo.record_finding(ctx.scan_id, f)
            asyncio.create_task(self.bus.publish(FindingDiscovered(
                probe_id=f.probe_id, title=f.title, algorithm=f.algorithm,
                classification=f.classification.value, severity=f.severity.value,
            )))

        try:
            await asyncio.wait_for(probe.run(ctx, emit), timeout=self.timeout)
        except asyncio.TimeoutError:
            self.repo.record_probe_error(ctx.scan_id, probe_id=probe.id, message="timeout")
        except Exception as e:  # noqa: BLE001
            logger.exception("probe {} crashed", probe.id)
            self.repo.record_probe_error(ctx.scan_id, probe_id=probe.id, message=str(e))
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_runner.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/runner/runner.py tests/unit/test_runner.py
git commit -m "feat: ProbeRunner with isolation, privilege-skip, timeout"
```

---

## Phase 5 — Representative probes (one per family)

### Task 12: host.openssl.config probe

**Files:**
- Create: `src/pqcscan/probes/host_openssl_config.py`
- Test: `tests/unit/test_probe_host_openssl_config.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_probe_host_openssl_config.py`:
```python
import pytest
from pathlib import Path

from pqcscan.probes.host_openssl_config import HostOpenSSLConfig
from pqcscan.probes._base import ScanContext


@pytest.mark.asyncio
async def test_detects_legacy_provider(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text("""
[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
""")
    found: list = []
    probe = HostOpenSSLConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any("legacy" in f.title.lower() for f in found)


@pytest.mark.asyncio
async def test_no_findings_for_modern_config(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text("[default_sect]\nactivate = 1\n")
    found: list = []
    probe = HostOpenSSLConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert not found
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_probe_host_openssl_config.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/probes/host_openssl_config.py`:
```python
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_DEFAULT_PATHS = [
    Path("/etc/ssl/openssl.cnf"),
    Path("/etc/pki/tls/openssl.cnf"),
    Path("/usr/local/etc/openssl/openssl.cnf"),
    Path("/usr/local/etc/openssl@3/openssl.cnf"),
]


class HostOpenSSLConfig(Probe):
    id = "host.openssl.config"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host")

    def __init__(self, config_paths: list[Path] | None = None):
        self.config_paths = config_paths if config_paths is not None else _DEFAULT_PATHS

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.config_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in self.config_paths:
            if not path.exists():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        if re.search(r"^\s*legacy\s*=\s*legacy_sect", text, re.MULTILINE):
            if re.search(r"\[legacy_sect\][^\[]*activate\s*=\s*1", text, re.DOTALL):
                emit(Finding(
                    probe_id=self.id,
                    algorithm="MD5/RC4/etc-via-legacy-provider",
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.HIGH,
                    title=f"OpenSSL legacy provider activated in {path}",
                    evidence={"path": str(path), "section": "legacy_sect"},
                    remediation={
                        "snippet": "# Comment out 'legacy = legacy_sect' or set activate = 0",
                    },
                ))
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_probe_host_openssl_config.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/host_openssl_config.py tests/unit/test_probe_host_openssl_config.py
git commit -m "feat: probe host.openssl.config (legacy provider detection)"
```

---

### Task 13: net.tls.https probe

**Files:**
- Create: `src/pqcscan/probes/net_tls_https.py`
- Test: `tests/unit/test_probe_net_tls_https.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_probe_net_tls_https.py`:
```python
import asyncio
import os
import shutil
import ssl
import subprocess
import tempfile

import pytest

from pqcscan.probes.net_tls_https import NetTlsHttps
from pqcscan.probes._base import ScanContext


@pytest.fixture
async def tls_server():
    """Start an in-process TLS server with a self-signed RSA-2048 cert."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    d = tempfile.mkdtemp()
    key = os.path.join(d, "k.pem")
    cert = os.path.join(d, "c.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1",
         "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslctx.load_cert_chain(cert, key)

    async def handle(r, w):
        try:
            w.close()
            await w.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=sslctx)
    port = server.sockets[0].getsockname()[1]
    task = asyncio.create_task(server.serve_forever())
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()
        task.cancel()


@pytest.mark.asyncio
async def test_detects_rsa_2048_cert(tls_server):
    port = tls_server
    found: list = []
    probe = NetTlsHttps(host="127.0.0.1", port=port, verify=False)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    algos = {f.algorithm for f in found}
    assert any("RSA" in a for a in algos)
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_probe_net_tls_https.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/probes/net_tls_https.py`:
```python
from __future__ import annotations

import asyncio
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class NetTlsHttps(Probe):
    id = "net.tls.https"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "cnsa2:tls", "bukukerja:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 443, verify: bool = False):
        self.host = host
        self.port = port
        self.verify = verify

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        sslctx = ssl.create_default_context()
        if not self.verify:
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host, self.port, ssl=sslctx, server_hostname=self.host,
                ),
                timeout=10.0,
            )
        except (OSError, asyncio.TimeoutError) as e:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"TLS connection failed at {self.host}:{self.port}: {e}",
            ))
            return

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cert_bin = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            cipher = writer.get_extra_info("cipher")  # (cipher_name, version, bits)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        if cipher:
            cname, tlsver, _ = cipher
            cls = classify(cname)
            emit(Finding(
                probe_id=self.id,
                algorithm=normalise(cname),
                classification=cls,
                severity=_severity_for(cls),
                title=f"{tlsver} negotiated cipher {cname}",
                evidence={"endpoint": f"{self.host}:{self.port}", "version": tlsver},
            ))

        if cert_bin:
            cert = x509.load_der_x509_certificate(cert_bin)
            pk = cert.public_key()
            alg = _key_algorithm(pk)
            cls = classify(alg)
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=cls,
                severity=_severity_for(cls),
                title=f"server cert uses {alg}",
                evidence={
                    "endpoint": f"{self.host}:{self.port}",
                    "subject": cert.subject.rfc4514_string(),
                    "not_after": cert.not_valid_after.isoformat(),
                },
            ))


def _key_algorithm(pk: object) -> str:
    if isinstance(pk, rsa.RSAPublicKey):
        return f"RSA-{pk.key_size}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pk.curve.name}"
    if isinstance(pk, dsa.DSAPublicKey):
        return f"DSA-{pk.key_size}"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pk).__name__


def _severity_for(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_probe_net_tls_https.py -v`
Expected: 1 PASS (test will skip if openssl binary unavailable on the runner).

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/net_tls_https.py tests/unit/test_probe_net_tls_https.py
git commit -m "feat: probe net.tls.https — cipher suite + cert key type detection"
```

---

### Task 14: fs.cert.x509 probe

**Files:**
- Create: `src/pqcscan/probes/fs_cert_x509.py`
- Test: `tests/unit/test_probe_fs_cert_x509.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_probe_fs_cert_x509.py`:
```python
import shutil
import subprocess
import pytest
from pathlib import Path

from pqcscan.probes.fs_cert_x509 import FsCertX509
from pqcscan.probes._base import ScanContext
from pqcscan.core.types import Classification


def _make_self_signed_cert(d: Path, key_size: int) -> Path:
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    key = d / "k.pem"
    cert = d / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", f"rsa:{key_size}", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=test"],
        check=True, capture_output=True,
    )
    return cert


@pytest.mark.asyncio
async def test_flags_rsa_1024(tmp_path: Path):
    _make_self_signed_cert(tmp_path, 1024)
    found: list = []
    probe = FsCertX509(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_flags_rsa_2048_as_tinggi(tmp_path: Path):
    _make_self_signed_cert(tmp_path, 2048)
    found: list = []
    probe = FsCertX509(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.classification is Classification.TINGGI for f in found)
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_probe_fs_cert_x509.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/probes/fs_cert_x509.py`:
```python
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_EXTS = (".pem", ".crt", ".cer", ".der")


class FsCertX509(Probe):
    id = "fs.cert.x509"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc"), Path("/usr/local/etc")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in _EXTS:
                    self._scan_one(path, emit)

    def _scan_one(self, path: Path, emit: Emitter) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        try:
            cert = x509.load_pem_x509_certificate(data)
        except ValueError:
            try:
                cert = x509.load_der_x509_certificate(data)
            except ValueError:
                return
        pk = cert.public_key()
        alg = _key_algorithm(pk)
        cls = classify(alg)
        emit(Finding(
            probe_id=self.id,
            algorithm=alg,
            classification=cls,
            severity=_sev(cls),
            title=f"{path.name}: {alg}",
            evidence={
                "path": str(path),
                "subject": cert.subject.rfc4514_string(),
                "not_after": cert.not_valid_after.isoformat(),
            },
        ))


def _key_algorithm(pk: object) -> str:
    if isinstance(pk, rsa.RSAPublicKey):
        return f"RSA-{pk.key_size}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pk.curve.name}"
    if isinstance(pk, dsa.DSAPublicKey):
        return f"DSA-{pk.key_size}"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pk).__name__


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_probe_fs_cert_x509.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/fs_cert_x509.py tests/unit/test_probe_fs_cert_x509.py
git commit -m "feat: probe fs.cert.x509 — recursive X.509 cert scan"
```

---

### Task 15: Stub probes — sbom / code / pqc_meta / aux

**Files:**
- Create: `src/pqcscan/probes/sbom_os_dpkg.py`
- Create: `src/pqcscan/probes/code_ts_python.py`
- Create: `src/pqcscan/probes/pqc_alg_normaliser.py`
- Create: `src/pqcscan/probes/aux_clock_cert_validity.py`
- Test: `tests/unit/test_probe_sbom_os_dpkg.py`
- Test: `tests/unit/test_probe_code_ts_python.py`
- Test: `tests/unit/test_probe_pqc_alg_normaliser.py`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_probe_sbom_os_dpkg.py`:
```python
import pytest
from pathlib import Path

from pqcscan.probes.sbom_os_dpkg import SbomOsDpkg
from pqcscan.probes._base import ScanContext


@pytest.mark.asyncio
async def test_sbom_dpkg_emits_packages(tmp_path: Path):
    status = tmp_path / "status"
    status.write_text(
        "Package: openssl\nVersion: 3.0.2-1ubuntu1.10\nStatus: install ok installed\n\n"
        "Package: libssl3\nVersion: 3.0.2-1ubuntu1.10\nStatus: install ok installed\n"
    )
    found = []
    probe = SbomOsDpkg(status_path=status)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("openssl" in t for t in titles)
    assert any("libssl3" in t for t in titles)
```

`tests/unit/test_probe_code_ts_python.py`:
```python
import pytest
from pathlib import Path

from pqcscan.probes.code_ts_python import CodeTsPython
from pqcscan.probes._base import ScanContext


@pytest.mark.asyncio
async def test_flags_md5_usage(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("import hashlib\n\nh = hashlib.md5(b'abc').hexdigest()\n")
    found = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda x: found.append(x))
    assert any("md5" in fnd.title.lower() for fnd in found)
```

`tests/unit/test_probe_pqc_alg_normaliser.py`:
```python
import pytest
from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser
from pqcscan.probes._base import ScanContext


@pytest.mark.asyncio
async def test_normaliser_emits_zero_findings_in_isolation():
    found = []
    probe = PqcAlgNormaliser()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda x: found.append(x))
    assert found == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `pytest tests/unit/test_probe_sbom_os_dpkg.py tests/unit/test_probe_code_ts_python.py tests/unit/test_probe_pqc_alg_normaliser.py -v`
Expected: ModuleNotFoundError on each.

- [ ] **Step 3: Implement**

`src/pqcscan/probes/sbom_os_dpkg.py`:
```python
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class SbomOsDpkg(Probe):
    id = "sbom.os.dpkg"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom",)

    def __init__(self, status_path: Path | None = None):
        self.status_path = status_path or Path("/var/lib/dpkg/status")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.status_path.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        text = self.status_path.read_text(errors="replace")
        for stanza in text.split("\n\n"):
            name = ""
            version = ""
            installed = False
            for line in stanza.splitlines():
                if line.startswith("Package: "):
                    name = line[9:].strip()
                elif line.startswith("Version: "):
                    version = line[9:].strip()
                elif line.startswith("Status: ") and "installed" in line:
                    installed = True
            if name and installed:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"package: {name} {version}",
                    evidence={
                        "name": name, "version": version, "manager": "dpkg",
                        "purl": f"pkg:deb/{name}@{version}",
                    },
                ))
```

`src/pqcscan/probes/code_ts_python.py`:
```python
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_WEAK_HASH_RE = re.compile(r"hashlib\.(md5|sha1)\s*\(", re.IGNORECASE)
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor",
                 "dist", "build", "target"}


class CodeTsPython(Probe):
    """Tree-sitter would parse the AST here; v1 MVP uses a regex placeholder."""
    id = "code.ts.python"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code",)

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*.py"):
                if any(part in _EXCLUDE_DIRS for part in path.parts):
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                for m in _WEAK_HASH_RE.finditer(text):
                    line_no = text[: m.start()].count("\n") + 1
                    alg = m.group(1).upper()
                    snippet = text.splitlines()[line_no - 1][:120]
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=alg,
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=f"{alg} usage in {path}:{line_no}",
                        evidence={"path": str(path), "line": line_no, "snippet": snippet},
                        remediation={"snippet": "# replace with hashlib.sha256()"},
                    ))
```

`src/pqcscan/probes/pqc_alg_normaliser.py`:
```python
from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext


class PqcAlgNormaliser(Probe):
    """Meta-probe: the algorithm normaliser lives in core.alg and is consumed by
    other probes. This Probe class is a placeholder so the registry can list it."""
    id = "pqc.alg.normaliser"
    family = ProbeFamily.PQC_META
    enabled_default = False

    async def applies(self, ctx: ScanContext) -> bool:
        return False

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        return None
```

`src/pqcscan/probes/aux_clock_cert_validity.py`:
```python
from __future__ import annotations

from datetime import datetime

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class AuxClockCertValidity(Probe):
    id = "aux.clock.cert_validity"
    family = ProbeFamily.AUX

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        now = datetime.utcnow()
        emit(Finding(
            probe_id=self.id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"system UTC clock at scan: {now.isoformat()}",
            evidence={"utc_now": now.isoformat()},
        ))
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_probe_sbom_os_dpkg.py tests/unit/test_probe_code_ts_python.py tests/unit/test_probe_pqc_alg_normaliser.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/sbom_os_dpkg.py src/pqcscan/probes/code_ts_python.py \
        src/pqcscan/probes/pqc_alg_normaliser.py src/pqcscan/probes/aux_clock_cert_validity.py \
        tests/unit/test_probe_sbom_os_dpkg.py tests/unit/test_probe_code_ts_python.py \
        tests/unit/test_probe_pqc_alg_normaliser.py
git commit -m "feat: probes — sbom.os.dpkg, code.ts.python, pqc.alg.normaliser, aux.clock.cert_validity"
```

---

### Task 16: Default registry seed (the 7 representative probes)

**Files:**
- Modify: `src/pqcscan/probes/_registry.py`
- Test: `tests/unit/test_registry_default_seed.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_registry_default_seed.py`:
```python
from pqcscan.probes._registry import default_registry


def test_default_registry_has_seven_probes():
    reg = default_registry()
    ids = set(reg.ids())
    expected = {
        "host.openssl.config", "sbom.os.dpkg", "net.tls.https",
        "fs.cert.x509", "code.ts.python", "pqc.alg.normaliser",
        "aux.clock.cert_validity",
    }
    assert expected.issubset(ids)
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_registry_default_seed.py -v`
Expected: `ImportError: cannot import name 'default_registry'`

- [ ] **Step 3: Implement**

Append to `src/pqcscan/probes/_registry.py`:
```python
def default_registry() -> Registry:
    """Built-in probe set for v1 MVP."""
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    from pqcscan.probes.code_ts_python import CodeTsPython
    from pqcscan.probes.fs_cert_x509 import FsCertX509
    from pqcscan.probes.host_openssl_config import HostOpenSSLConfig
    from pqcscan.probes.net_tls_https import NetTlsHttps
    from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser
    from pqcscan.probes.sbom_os_dpkg import SbomOsDpkg

    reg = Registry()
    reg.register(HostOpenSSLConfig())
    reg.register(SbomOsDpkg())
    reg.register(NetTlsHttps())
    reg.register(FsCertX509())
    reg.register(CodeTsPython())
    reg.register(PqcAlgNormaliser())
    reg.register(AuxClockCertValidity())
    return reg
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_registry_default_seed.py -v`
Expected: 1 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/_registry.py tests/unit/test_registry_default_seed.py
git commit -m "feat: default registry with 7 representative probes"
```

---

## Phase 6 — Daemon (FastAPI + SSE)

### Task 17: FastAPI app skeleton with health + version

**Files:**
- Create: `src/pqcscan/daemon/__init__.py`
- Create: `src/pqcscan/daemon/app.py`
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/test_daemon_api.py`

- [ ] **Step 1: Write the failing test**

`tests/integration/__init__.py`: empty.

`tests/integration/test_daemon_api.py`:
```python
import pytest
from fastapi.testclient import TestClient

from pqcscan.daemon.app import create_app


@pytest.fixture
def client(tmp_db_path):
    app = create_app(db_path=tmp_db_path)
    return TestClient(app)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["version"]


def test_version(client):
    r = client.get("/api/version")
    assert r.status_code == 200
    assert r.json()["version"] == "0.1.0"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/integration/test_daemon_api.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`src/pqcscan/daemon/__init__.py`: empty.

`src/pqcscan/daemon/app.py`:
```python
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from pqcscan import __version__
from pqcscan.runner.event_bus import EventBus
from pqcscan.store.repo import Repo


def create_app(*, db_path: Path) -> FastAPI:
    app = FastAPI(title="pqcscan", version=__version__)
    app.state.repo = Repo(db_path); app.state.repo.init_schema()
    app.state.bus = EventBus()

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/version")
    async def version() -> dict:
        return {"version": __version__}

    return app
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/integration/test_daemon_api.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/daemon/ tests/integration/
git commit -m "feat: FastAPI daemon skeleton with /api/health and /api/version"
```

---

### Task 18: Daemon scan endpoints + SSE stream

**Files:**
- Modify: `src/pqcscan/daemon/app.py`
- Create: `src/pqcscan/daemon/sse.py`
- Modify: `tests/integration/test_daemon_api.py`

- [ ] **Step 1: Append the failing tests**

Append to `tests/integration/test_daemon_api.py`:
```python
import time


def test_post_scan_creates_and_runs(client):
    r = client.post("/api/scans")
    assert r.status_code == 202
    body = r.json()
    assert "id" in body
    scan_id = body["id"]

    for _ in range(50):
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] == "done":
            break
        time.sleep(0.1)
    assert s["status"] == "done"


def test_list_scans(client):
    client.post("/api/scans")
    r = client.get("/api/scans")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1
    assert "id" in data[0] and "status" in data[0]


def test_scan_findings(client):
    r = client.post("/api/scans")
    scan_id = r.json()["id"]
    for _ in range(50):
        if client.get(f"/api/scans/{scan_id}").json()["status"] == "done":
            break
        time.sleep(0.1)
    r = client.get(f"/api/scans/{scan_id}/findings")
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) >= 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/integration/test_daemon_api.py -v`
Expected: 404 Not Found on POST.

- [ ] **Step 3: Implement**

Replace `src/pqcscan/daemon/app.py`:
```python
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse

from pqcscan import __version__
from pqcscan.daemon.sse import event_to_sse
from pqcscan.probes._registry import default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo


def create_app(*, db_path: Path) -> FastAPI:
    app = FastAPI(title="pqcscan", version=__version__)
    repo = Repo(db_path); repo.init_schema()
    bus = EventBus()
    registry = default_registry()
    runner = ProbeRunner(registry=registry, repo=repo, bus=bus)

    app.state.repo = repo
    app.state.bus = bus
    app.state.runner = runner

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/version")
    async def version() -> dict:
        return {"version": __version__}

    @app.post("/api/scans", status_code=202)
    async def post_scan() -> dict:
        mode = current_mode()
        caps = detect_capabilities()

        async def _run() -> None:
            await runner.run(mode=mode, available_capabilities=caps)

        asyncio.create_task(_run())
        for _ in range(50):
            scans = repo.list_scans()
            if scans:
                return {"id": scans[0].id}
            await asyncio.sleep(0.02)
        raise HTTPException(500, "scan failed to start")

    @app.get("/api/scans")
    async def list_scans() -> list[dict]:
        return [_scan_to_dict(s) for s in repo.list_scans()]

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: int) -> dict:
        scan = repo.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, "not found")
        return _scan_to_dict(scan)

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(scan_id: int) -> list[dict]:
        rows = repo.list_findings(scan_id)
        return [
            {
                "id": r.id, "probe_id": r.probe_id, "algorithm": r.algorithm,
                "classification": r.classification, "severity": r.severity,
                "title": r.title, "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]

    @app.get("/api/scans/{scan_id}/events")
    async def stream_events(scan_id: int) -> StreamingResponse:
        async def gen():
            async for ev in bus.subscribe():
                yield event_to_sse(ev)
        return StreamingResponse(gen(), media_type="text/event-stream")

    return app


def _scan_to_dict(s) -> dict:
    return {
        "id": s.id,
        "started_at": s.started_at.isoformat(),
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "status": s.status,
        "mode": s.mode,
        "label": s.label,
    }
```

`src/pqcscan/daemon/sse.py`:
```python
from __future__ import annotations

import json
from dataclasses import asdict

from pqcscan.runner.event_bus import (
    Event, FindingDiscovered, ScanCompleted, StageCompleted, StageStarted,
)


def event_to_sse(event: Event) -> str:
    """Encode an event as a single SSE message."""
    if isinstance(event, StageStarted):
        kind = "stage_started"
    elif isinstance(event, StageCompleted):
        kind = "stage_completed"
    elif isinstance(event, FindingDiscovered):
        kind = "finding"
    elif isinstance(event, ScanCompleted):
        kind = "scan_completed"
    else:
        kind = "unknown"
    payload = json.dumps(asdict(event))
    return f"event: {kind}\ndata: {payload}\n\n"
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/integration/test_daemon_api.py -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/daemon/app.py src/pqcscan/daemon/sse.py tests/integration/test_daemon_api.py
git commit -m "feat: daemon scan endpoints + SSE event stream"
```

---

## Phase 7 — CLI

### Task 19: CLI scaffold with click

**Files:**
- Create: `src/pqcscan/util/__init__.py`
- Create: `src/pqcscan/util/paths.py`
- Create: `src/pqcscan/cli/__init__.py`
- Create: `src/pqcscan/cli/main.py`
- Create: `src/pqcscan/cli/scan.py`
- Create: `src/pqcscan/cli/daemon_cmd.py`
- Create: `src/pqcscan/cli/export.py`
- Create: `tests/integration/test_cli_scan.py`

- [ ] **Step 1: Write the failing test**

`tests/integration/test_cli_scan.py`:
```python
import json
import subprocess
import sys


def _run(*args, env=None):
    return subprocess.run(
        [sys.executable, "-m", "pqcscan", *args],
        capture_output=True, text=True, env=env,
    )


def test_version():
    p = _run("version")
    assert p.returncode == 0
    assert "0.1.0" in p.stdout


def test_help():
    p = _run("--help")
    assert p.returncode == 0
    assert "Usage:" in p.stdout
    assert "scan" in p.stdout
    assert "daemon" in p.stdout
    assert "export" in p.stdout


def test_scan_in_process_writes_to_db(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    import os
    env = os.environ.copy(); env["PQCSCAN_DB_PATH"] = str(db)
    p = _run("scan", "--json", env=env)
    assert p.returncode in (0, 1)
    out = json.loads(p.stdout)
    assert "scan_id" in out
    assert isinstance(out["finding_count"], int)
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/integration/test_cli_scan.py -v`
Expected: ModuleNotFoundError or `No such command "scan"`.

- [ ] **Step 3: Implement**

`src/pqcscan/util/__init__.py`: empty.

`src/pqcscan/util/paths.py`:
```python
from __future__ import annotations

import os
import sys
from pathlib import Path


def default_db_path() -> Path:
    """Return OS-appropriate default DB path; respect PQCSCAN_DB_PATH env."""
    if env := os.environ.get("PQCSCAN_DB_PATH"):
        return Path(env)
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "pqcscan" / "pqcscan.db"
    if sys.platform == "darwin":
        return Path("/Library/Application Support/pqcscan/pqcscan.db")
    return Path("/var/lib/pqcscan/pqcscan.db")
```

`src/pqcscan/cli/__init__.py`: empty.

`src/pqcscan/cli/main.py`:
```python
from __future__ import annotations

import click

from pqcscan import __version__
from pqcscan.cli.daemon_cmd import daemon_cmd
from pqcscan.cli.export import export_cmd
from pqcscan.cli.scan import scan_cmd, scans_cmd, status_cmd


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """Post-Quantum Cryptography readiness scanner."""


@cli.command("version")
def version_cmd() -> None:
    """Print pqcscan version."""
    click.echo(f"pqcscan {__version__}")


cli.add_command(scan_cmd, name="scan")
cli.add_command(scans_cmd, name="scans")
cli.add_command(status_cmd, name="status")
cli.add_command(daemon_cmd, name="daemon")
cli.add_command(export_cmd, name="export")
```

`src/pqcscan/cli/scan.py`:
```python
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from pqcscan.probes._registry import default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON to stdout.")
@click.option("--watch", is_flag=True, help="Stream findings to stderr while scanning.")
def scan_cmd(db: Path | None, as_json: bool, watch: bool) -> None:
    """Run a scan in-process; persist to SQLite."""
    db_path = db or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo(db_path); repo.init_schema()
    bus = EventBus()
    registry = default_registry()
    runner = ProbeRunner(registry=registry, repo=repo, bus=bus)

    async def _go() -> int:
        watcher_task = None
        if watch:
            async def _watch():
                async for ev in bus.subscribe():
                    click.echo(f"[event] {type(ev).__name__}: {ev}", err=True)
            watcher_task = asyncio.create_task(_watch())
        scan_id = await runner.run(
            mode=current_mode(),
            available_capabilities=detect_capabilities(),
        )
        if watcher_task:
            watcher_task.cancel()
        return scan_id

    scan_id = asyncio.run(_go())
    findings = repo.list_findings(scan_id)
    high_or_crit = [f for f in findings if f.severity in {"high", "crit"}]

    if as_json:
        click.echo(json.dumps({
            "scan_id": scan_id,
            "finding_count": len(findings),
            "high_or_crit_count": len(high_or_crit),
            "db": str(db_path),
        }))
    else:
        click.echo(f"Scan {scan_id} done. {len(findings)} findings, "
                   f"{len(high_or_crit)} high/crit.")

    sys.exit(1 if high_or_crit else 0)


@click.command()
@click.option("--db", type=click.Path(path_type=Path), default=None)
def scans_cmd(db: Path | None) -> None:
    """List scans."""
    repo = Repo(db or default_db_path()); repo.init_schema()
    for s in repo.list_scans():
        click.echo(f"{s.id}\t{s.started_at.isoformat()}\t{s.status}\t{s.mode}")


@click.command()
@click.option("--id", "scan_id", type=int, required=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def status_cmd(scan_id: int, db: Path | None) -> None:
    """Show one scan's status."""
    repo = Repo(db or default_db_path()); repo.init_schema()
    s = repo.get_scan(scan_id)
    if s is None:
        click.echo(f"scan {scan_id} not found", err=True)
        sys.exit(3)
    click.echo(f"id={s.id} status={s.status} mode={s.mode} "
               f"started={s.started_at.isoformat()}")
```

`src/pqcscan/cli/daemon_cmd.py`:
```python
from __future__ import annotations

from pathlib import Path

import click
import uvicorn

from pqcscan.daemon.app import create_app
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--port", type=int, default=8765)
@click.option("--bind", default="127.0.0.1", help="Bind address. Default 127.0.0.1.")
@click.option("--db", type=click.Path(path_type=Path), default=None)
def daemon_cmd(port: int, bind: str, db: Path | None) -> None:
    """Run the daemon (HTTP+SSE on 127.0.0.1)."""
    db_path = db or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    app = create_app(db_path=db_path)
    uvicorn.run(app, host=bind, port=port, log_level="info")
```

`src/pqcscan/cli/export.py`:
```python
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--scan", "scan_id", type=int, required=True)
@click.option("--format", "fmt", required=True,
              type=click.Choice(["cbom"], case_sensitive=False))
@click.option("-o", "--out", type=click.Path(path_type=Path), required=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def export_cmd(scan_id: int, fmt: str, out: Path, db: Path | None) -> None:
    """Export a scan in the chosen format."""
    # Lazy import: pqcscan.cbom.builder lands in Task 21; loading it here keeps
    # the CLI module importable during Task 19 even though the cbom package
    # isn't created yet.
    from pqcscan.cbom.builder import build_cbom

    repo = Repo(db or default_db_path()); repo.init_schema()
    if repo.get_scan(scan_id) is None:
        click.echo(f"scan {scan_id} not found", err=True); sys.exit(3)

    if fmt.lower() == "cbom":
        doc = build_cbom(repo, scan_id)
        out.write_text(json.dumps(doc, indent=2))
        click.echo(f"wrote CycloneDX 1.6 CBOM → {out}")
```

- [ ] **Step 4: Run to verify pass**

Run: `pip install -e ".[dev]" && pytest tests/integration/test_cli_scan.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/cli/ src/pqcscan/util/ tests/integration/test_cli_scan.py
git commit -m "feat: CLI commands — version, scan, scans, status, daemon, export"
```

---

## Phase 8 — Minimal web UI

### Task 20: Vendor HTMX + Tailwind, base templates, dashboard route

**Files:**
- Create: `src/pqcscan/ui/__init__.py`
- Create: `src/pqcscan/ui/routes.py`
- Create: `src/pqcscan/ui/templates/base.html`
- Create: `src/pqcscan/ui/templates/dashboard.html`
- Create: `src/pqcscan/ui/templates/scans_list.html`
- Create: `src/pqcscan/ui/templates/scan_detail.html`
- Create: `src/pqcscan/ui/static/htmx-1.9.10.min.js` (vendor)
- Create: `src/pqcscan/ui/static/tailwind.min.css` (vendor)
- Modify: `src/pqcscan/daemon/app.py`
- Create: `tests/integration/test_ui.py`

- [ ] **Step 1: Write the failing test**

`tests/integration/test_ui.py`:
```python
import pytest
from fastapi.testclient import TestClient

from pqcscan.daemon.app import create_app


@pytest.fixture
def client(tmp_db_path):
    return TestClient(create_app(db_path=tmp_db_path))


def test_dashboard_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "pqcscan" in r.text.lower()
    assert "scan now" in r.text.lower()


def test_scans_list_page(client):
    client.post("/api/scans")
    r = client.get("/scans")
    assert r.status_code == 200
    assert "<table" in r.text


def test_static_htmx_served(client):
    r = client.get("/static/htmx-1.9.10.min.js")
    assert r.status_code == 200
    assert "htmx" in r.text.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/integration/test_ui.py -v`
Expected: 404 on `/`.

- [ ] **Step 3: Vendor HTMX + Tailwind**

```bash
mkdir -p src/pqcscan/ui/static
curl -sL https://unpkg.com/htmx.org@1.9.10/dist/htmx.min.js \
     -o src/pqcscan/ui/static/htmx-1.9.10.min.js
curl -sL "https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" \
     -o src/pqcscan/ui/static/tailwind.min.css
```

If the CDN download fails in your environment, write a minimal stub `src/pqcscan/ui/static/tailwind.min.css` with `body { font-family: system-ui; }` and a TODO comment to vendor a real build later. The test only verifies htmx is served, not tailwind.

- [ ] **Step 4: Implement**

`src/pqcscan/ui/__init__.py`: empty.

`src/pqcscan/ui/templates/base.html`:
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>pqcscan</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/static/tailwind.min.css">
  <script src="/static/htmx-1.9.10.min.js"></script>
</head>
<body class="bg-slate-950 text-slate-100 font-sans">
  <header class="px-6 py-3 border-b border-slate-800 flex justify-between items-center">
    <a href="/" class="text-lg font-semibold">pqcscan</a>
    <nav class="space-x-4 text-sm">
      <a href="/" class="hover:underline">Dashboard</a>
      <a href="/scans" class="hover:underline">Scans</a>
    </nav>
  </header>
  <main class="px-6 py-6">
    {% block body %}{% endblock %}
  </main>
</body>
</html>
```

`src/pqcscan/ui/templates/dashboard.html`:
```html
{% extends "base.html" %}
{% block body %}
<div class="flex justify-between items-center mb-6">
  <h1 class="text-xl font-semibold">Dashboard</h1>
  <button hx-post="/api/scans" hx-swap="none"
          class="bg-sky-600 hover:bg-sky-700 px-3 py-1.5 rounded text-sm font-medium">
    Scan now
  </button>
</div>
{% if last_scan %}
  <p class="text-slate-400 text-sm">
    Last scan #{{ last_scan.id }} — {{ last_scan.status }} ({{ last_scan.started_at }}, mode={{ last_scan.mode }}).
    <a href="/scans/{{ last_scan.id }}" class="text-sky-400 hover:underline">view</a>
  </p>
{% else %}
  <p class="text-slate-400 text-sm">No scans yet. Click "Scan now".</p>
{% endif %}
{% endblock %}
```

`src/pqcscan/ui/templates/scans_list.html`:
```html
{% extends "base.html" %}
{% block body %}
<h1 class="text-xl font-semibold mb-4">Scans</h1>
<table class="w-full text-sm border-collapse">
  <thead>
    <tr class="text-left text-slate-400 border-b border-slate-800">
      <th class="py-2">ID</th><th>Started</th><th>Status</th><th>Mode</th><th></th>
    </tr>
  </thead>
  <tbody>
    {% for s in scans %}
      <tr class="border-b border-slate-900">
        <td class="py-2">{{ s.id }}</td>
        <td>{{ s.started_at }}</td>
        <td>{{ s.status }}</td>
        <td>{{ s.mode }}</td>
        <td><a href="/scans/{{ s.id }}" class="text-sky-400 hover:underline">view</a></td>
      </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

`src/pqcscan/ui/templates/scan_detail.html`:
```html
{% extends "base.html" %}
{% block body %}
<h1 class="text-xl font-semibold mb-2">Scan #{{ scan.id }}</h1>
<p class="text-slate-400 text-sm mb-4">
  Status: {{ scan.status }} — mode: {{ scan.mode }} — started: {{ scan.started_at }}
</p>

<div id="findings" hx-ext="sse" sse-connect="/api/scans/{{ scan.id }}/events"
     sse-swap="finding" hx-swap="afterbegin" class="space-y-2">
  {% for f in findings %}
    <div class="border border-slate-800 rounded p-2 text-sm flex gap-2">
      <span class="px-1.5 py-0.5 rounded text-xs uppercase bg-slate-800">{{ f.severity }}</span>
      <span class="text-slate-300">{{ f.algorithm }}</span>
      <span>{{ f.title }}</span>
    </div>
  {% endfor %}
</div>
{% endblock %}
```

`src/pqcscan/ui/routes.py`:
```python
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
router = APIRouter()


def mount_static(app) -> None:
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    repo = request.app.state.repo
    scans = repo.list_scans()
    last_scan = scans[0] if scans else None
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "last_scan": last_scan},
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_list(request: Request):
    repo = request.app.state.repo
    scans = repo.list_scans()
    return templates.TemplateResponse(
        "scans_list.html", {"request": request, "scans": scans},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int):
    repo = request.app.state.repo
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    findings = repo.list_findings(scan_id)
    return templates.TemplateResponse(
        "scan_detail.html",
        {"request": request, "scan": scan, "findings": findings},
    )
```

Add to `src/pqcscan/daemon/app.py`, just before `return app` in `create_app`:
```python
    from pqcscan.ui.routes import mount_static, router as ui_router
    mount_static(app)
    app.include_router(ui_router)
```

- [ ] **Step 5: Run to verify pass**

Run: `pip install -e ".[dev]" && pytest tests/integration/test_ui.py -v`
Expected: 3 PASS

- [ ] **Step 6: Commit**

```bash
git add src/pqcscan/ui/ src/pqcscan/daemon/app.py tests/integration/test_ui.py
git commit -m "feat: minimal web UI — dashboard, scans list, live scan detail"
```

---

## Phase 9 — CycloneDX 1.6 CBOM renderer

### Task 21: CBOM builder + structural validation

**Files:**
- Create: `src/pqcscan/cbom/__init__.py`
- Create: `src/pqcscan/cbom/builder.py`
- Create: `tests/unit/test_cbom_builder.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_cbom_builder.py`:
```python
from pqcscan.cbom.builder import build_cbom
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.repo import Repo


def test_build_cbom_minimal_shape(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.https",
        algorithm="RSA-2048",
        classification=Classification.TINGGI,
        severity=Severity.HIGH,
        title="server cert uses RSA-2048",
        evidence={"endpoint": "127.0.0.1:443"},
    ))
    repo.finish_scan(scan_id, status="done")

    cbom = build_cbom(repo, scan_id)

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert "metadata" in cbom and "tools" in cbom["metadata"]
    assert any(c.get("type") == "cryptographic-asset" for c in cbom["components"])
    names = [c["name"] for c in cbom["components"]]
    assert any("RSA-2048" in n for n in names)


def test_build_cbom_skips_na_algorithm(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(scan_id, Finding(
        probe_id="aux.clock.cert_validity",
        algorithm="N/A",
        classification=Classification.INFO,
        severity=Severity.INFO,
        title="clock at scan",
    ))
    repo.finish_scan(scan_id, status="done")
    cbom = build_cbom(repo, scan_id)
    assert cbom["components"] == []


def test_build_cbom_includes_pqc_ready(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.https",
        algorithm="ML-KEM-768",
        classification=Classification.PQC_READY,
        severity=Severity.INFO,
        title="hybrid PQC kex",
    ))
    repo.finish_scan(scan_id, status="done")
    cbom = build_cbom(repo, scan_id)
    levels = [c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
              for c in cbom["components"]]
    assert max(levels) >= 3
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/unit/test_cbom_builder.py -v`
Expected: ModuleNotFoundError.

- [ ] **Step 3: Implement**

`src/pqcscan/cbom/__init__.py`: empty.

`src/pqcscan/cbom/builder.py`:
```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pqcscan import __version__
from pqcscan.store.repo import Repo


def build_cbom(repo: Repo, scan_id: int) -> dict[str, Any]:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)

    components: list[dict[str, Any]] = []
    for f in findings:
        if f.algorithm == "N/A":
            continue
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"finding-{f.id}",
            "name": f.algorithm,
            "description": f.title,
            "cryptoProperties": {
                "assetType": _asset_type_for(f.probe_id),
                "algorithmProperties": {
                    "primitive": _primitive_for(f.algorithm),
                    "parameterSetIdentifier": f.algorithm,
                    "executionEnvironment": "software-plain-ram",
                    "nistQuantumSecurityLevel": _nist_level_for(f.classification),
                },
            },
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "pqcscan", "name": "pqcscan", "version": __version__}],
            "component": {
                "type": "device",
                "name": scan.host_fingerprint or "host",
                "bom-ref": f"host-scan-{scan_id}",
            },
        },
        "components": components,
    }


def _asset_type_for(probe_id: str) -> str:
    if probe_id.startswith("net."):
        return "protocol"
    if probe_id.startswith("fs.cert"):
        return "certificate"
    if probe_id.startswith("fs.privkey") or probe_id.endswith(".privkey"):
        return "key"
    return "algorithm"


def _primitive_for(algorithm: str) -> str:
    a = algorithm.upper()
    if a.startswith(("RSA", "ECDSA", "DSA", "ED25519", "ED448",
                     "ML-DSA", "SLH-DSA", "FALCON")):
        return "signature"
    if a.startswith(("AES", "CHACHA")):
        return "cipher"
    if a.startswith(("SHA", "MD")):
        return "hash"
    if a.startswith(("ML-KEM", "X25519MLKEM", "ECDH", "DH")):
        return "key-agreement"
    return "other"


def _nist_level_for(classification: str) -> int:
    return {
        "pqc-ready": 3,
        "rendah": 2,
        "sederhana": 1,
        "tinggi": 0,
        "sangat-tinggi": 0,
        "info": 0,
        "error": 0,
    }.get(classification, 0)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_cbom_builder.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/cbom/ tests/unit/test_cbom_builder.py
git commit -m "feat: CycloneDX 1.6 CBOM builder"
```

---

## Phase 10 — End-to-end smoke test + README

### Task 22: End-to-end test — scan → export CBOM

**Files:**
- Create: `tests/integration/test_end_to_end.py`

- [ ] **Step 1: Write the test**

`tests/integration/test_end_to_end.py`:
```python
import json
import os
import subprocess
import sys
from pathlib import Path


def _run(*args, env=None):
    return subprocess.run(
        [sys.executable, "-m", "pqcscan", *args],
        capture_output=True, text=True, env=env,
    )


def test_scan_then_export_cbom(tmp_path: Path):
    db = tmp_path / "db.sqlite"
    env = os.environ.copy(); env["PQCSCAN_DB_PATH"] = str(db)

    p1 = _run("scan", "--json", env=env)
    assert p1.returncode in (0, 1), p1.stderr
    scan_id = json.loads(p1.stdout)["scan_id"]

    out = tmp_path / "cbom.json"
    p2 = _run("export", "--scan", str(scan_id),
              "--format", "cbom", "-o", str(out), env=env)
    assert p2.returncode == 0, p2.stderr
    assert out.exists()

    cbom = json.loads(out.read_text())
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
```

- [ ] **Step 2: Run to verify it passes**

Run: `pytest tests/integration/test_end_to_end.py -v`
Expected: 1 PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_end_to_end.py
git commit -m "test: e2e — scan → export CycloneDX 1.6 CBOM"
```

---

### Task 23: README quickstart

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace README contents**

`README.md`:
```markdown
# pqcscan

Post-Quantum Cryptography (PQC) readiness scanner. Single Python process. Bundled web UI + headless CLI. Runs locally on Linux, Windows, macOS.

> **MVP foundation status.** This release ships the foundation and 7 representative probes (one per family). The full ~95-probe inventory, the 8-framework compliance engine, the PDF/XLSX renderers, baselines/diff, the i18n EN/MS toggle, and PyInstaller cross-OS packaging are tracked in subsequent plans (B–F). See `docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md` for the full design.

## Install (development)

```bash
git clone https://github.com/orengacademy/pqc-scanner2 pqcscan
cd pqcscan
pip install -e ".[dev]"
```

Requirements: Python 3.11+. Optional: `openssl` binary on PATH (used by some tests for cert generation).

## Quickstart

```bash
# Start the daemon (web UI on 127.0.0.1:8765 by default).
pqcscan daemon &

# Trigger a scan from the CLI.
pqcscan scan --json
# → {"scan_id": 1, "finding_count": 12, "high_or_crit_count": 3, "db": "..."}

# List scans.
pqcscan scans

# Export the canonical CBOM.
pqcscan export --scan 1 --format cbom -o cbom.json

# Or just visit the UI.
xdg-open http://127.0.0.1:8765
```

## CLI

```
pqcscan version                            # print version
pqcscan daemon [--port 8765] [--bind ...]  # start daemon + web UI
pqcscan scan [--json] [--watch]            # one-shot scan
pqcscan scans                              # list past scans
pqcscan status --id N                      # one scan's status
pqcscan export --scan N --format cbom -o … # export CycloneDX 1.6
```

Exit codes:
- `0` — scan completed; nothing high/crit.
- `1` — scan completed; high or crit findings present.
- `2` — scan failed.
- `3` — invalid arguments.

## Tests

```bash
pytest -q --cov=pqcscan --cov-report=term-missing
```

## Licence

MIT (with caveat tracked in the design spec around scapy GPL-2 — not yet a dependency in the MVP).
```

- [ ] **Step 2: Sanity check**

Run: `grep -i pqcscan README.md | head -5`
Expected: at least 5 matches.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README quickstart for MVP foundation"
```

---

### Task 24: Final lint + type-check + push

- [ ] **Step 1: Lint**

Run: `ruff check src/ tests/`
Expected: success. If errors, run `ruff check --fix src/ tests/` and review the diff.

- [ ] **Step 2: Type-check**

Run: `mypy src/pqcscan`
Expected: success.

- [ ] **Step 3: Full test run with coverage**

Run: `pytest -q --cov=pqcscan --cov-report=term-missing`
Expected: all tests pass; coverage ≥ 70% across the foundation modules.

- [ ] **Step 4: Push**

```bash
git push
```

- [ ] **Step 5: Verify CI is green**

Open https://github.com/orengacademy/pqc-scanner2/actions and confirm the latest run is green.

---

## Success criteria

When all 24 tasks are complete and CI is green, you should be able to:

```bash
$ pqcscan version
pqcscan 0.1.0

$ pqcscan daemon &
INFO:     Uvicorn running on http://127.0.0.1:8765

$ pqcscan scan --json
{"scan_id": 1, "finding_count": 9, "high_or_crit_count": 0, "db": "/var/lib/pqcscan/pqcscan.db"}

$ pqcscan export --scan 1 --format cbom -o cbom.json
wrote CycloneDX 1.6 CBOM → cbom.json

$ python -c "import json; d=json.load(open('cbom.json')); print(d['bomFormat'], d['specVersion'])"
CycloneDX 1.6
```

…and visit http://127.0.0.1:8765 in a browser to see the dashboard, click "Scan now", and watch findings stream in.

---

## What this plan deliberately does NOT do

| Capability | Why deferred | Plan |
|---|---|---|
| Other ~95 probes | Repetitive — pattern is established by this plan's 7 representatives | Plan B |
| Compliance engine + 8 framework YAMLs | Needs all probes to be useful | Plan C |
| PDF + XLSX + BUKUKERJA renderers | Each is a renderer module on top of the same SQLite | Plan D |
| Baselines, diff, full UI (settings, frameworks, probes pages, i18n) | Requires fuller probe coverage | Plan E |
| PyInstaller cross-OS packaging, offline pack, service installers | Comes after probe + framework completeness | Plan F |
| User-extensible probes loader (`/etc/pqcscan/probes.d/`) | Defer until built-in inventory is complete | Plan B |

Each follow-up plan can be written independently of this one and consumes its `Repo`, `Probe` ABC, `EventBus`, daemon, and CLI surfaces directly.

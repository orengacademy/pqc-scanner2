"""Fuzz load_bundle / dump_bundle: whatever an agent posts, the collector raises only its two declared errors."""
from __future__ import annotations

import contextlib
import gzip
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("hypothesis")

from hypothesis import example, given
from hypothesis import strategies as st

from pqcscan.core.parity import DRIFT_PROBE
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import (
    MAX_LABEL_KEY,
    MAX_LABEL_VALUE,
    MAX_LABELS,
    BundleInvalid,
    BundleTooLarge,
    HostIdentity,
    ScanBundle,
    check_labels,
    dump_bundle,
    load_bundle,
)
from pqcscan.store.repo import Repo

_OK = (BundleInvalid, BundleTooLarge)
_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40)

_scalars = st.one_of(st.none(), st.booleans(), st.integers(min_value=-(10**30), max_value=10**30),
                     st.floats(allow_nan=True, allow_infinity=True), st.text(max_size=40))
json_values = st.recursive(
    _scalars,
    lambda kids: st.lists(kids, max_size=5) | st.dictionaries(st.text(max_size=12), kids, max_size=5),
    max_leaves=40,
)


def _gz(doc: Any) -> bytes:
    return gzip.compress(json.dumps(doc).encode())


def _check_loaded(b: ScanBundle) -> None:
    check_labels(b.host.labels)                       # whatever came out satisfies the label contract
    assert b.host.machine_id and isinstance(b.host.machine_id, str)
    assert isinstance(b.scan_uuid, str) and b.scan_uuid
    assert all(isinstance(x, str) for x in (b.host.hostname, b.host.os, b.host.agent_version))
    for f in b.findings:
        assert f.get("probe_id") != DRIFT_PROBE       # drift is server-derived
        ev = f.get("evidence")
        if isinstance(ev, dict):
            assert "_fleet" not in ev                 # attribution is server-derived


# --- arbitrary bytes ---------------------------------------------------------------------------------------------

@given(st.binary(max_size=4096))
def test_arbitrary_bytes_raise_only_bundle_errors(data):
    try:
        b = load_bundle(data)
    except _OK:
        return
    _check_loaded(b)                                  # a random blob that parses is fine, but must be sane


@given(st.binary(max_size=4096))
def test_valid_gzip_of_arbitrary_bytes(data):
    with contextlib.suppress(*_OK):
        load_bundle(gzip.compress(data))


@given(st.binary(min_size=10, max_size=400), st.integers(min_value=0, max_value=399), st.integers(0, 255))
def test_mutated_gzip_stream(payload, pos, byte):
    blob = bytearray(gzip.compress(payload))
    blob[pos % len(blob)] = byte
    with contextlib.suppress(*_OK):
        load_bundle(bytes(blob))


# --- arbitrary JSON documents --------------------------------------------------------------------------------------

@given(json_values)
def test_arbitrary_json_document(doc):
    try:
        b = load_bundle(_gz(doc))
    except _OK:
        return
    _check_loaded(b)


_label_values = st.one_of(_scalars, st.lists(st.text(max_size=5), max_size=3), st.text(max_size=300))
_labels = st.one_of(
    st.none(), st.text(max_size=10), st.lists(st.integers(), max_size=3),
    st.dictionaries(st.text(max_size=80), _label_values, max_size=80),
)
_evidence = st.one_of(
    st.none(), st.integers(), st.lists(st.integers(), max_size=3),
    st.dictionaries(st.sampled_from(["_fleet", "host", "path", "endpoint", "x"]), json_values, max_size=5),
)
_finding = st.one_of(
    json_values,
    st.fixed_dictionaries(
        {"probe_id": st.sampled_from([DRIFT_PROBE, "net.tls.https", "fs.cert.x509"]) | _scalars},
        optional={"algorithm": _scalars, "title": _scalars, "evidence": _evidence, "remediation": json_values,
                  "views": json_values, "severity": _scalars, "classification": _scalars, "created_at": _scalars},
    ),
)
_host = st.one_of(
    json_values,
    st.fixed_dictionaries(
        {}, optional={"machine_id": _scalars | st.just("m-1"), "hostname": _scalars, "os": _scalars,
                      "agent_version": _scalars, "labels": _labels},
    ),
)
_hostile_doc = st.fixed_dictionaries(
    {"schema_version": st.just(1) | _scalars},
    optional={"scan_uuid": st.just("u-1") | _scalars, "host": _host, "scan": st.one_of(json_values, st.just({})),
              "findings": st.one_of(st.none(), json_values, st.lists(_finding, max_size=8))},
)


@given(_hostile_doc)
def test_hostile_structured_documents(doc):
    doc.setdefault("schema_version", 1)
    try:
        b = load_bundle(_gz(doc))
    except _OK:
        return
    _check_loaded(b)


@given(st.integers(0, 130), st.integers(0, 140), st.integers(0, 600))
@example(MAX_LABELS, MAX_LABEL_KEY, MAX_LABEL_VALUE)
@example(MAX_LABELS + 1, 1, 1)
@example(1, MAX_LABEL_KEY + 1, 1)
@example(1, 1, MAX_LABEL_VALUE + 1)
def test_label_caps_are_exact(n, klen, vlen):
    labels = {(str(i) + "k" * klen)[:klen] if klen else str(i): "v" * vlen for i in range(n)}
    doc = {"schema_version": 1, "scan_uuid": "u", "host": {"machine_id": "m", "labels": labels},
           "scan": {}, "findings": []}
    expect_ok = (len(labels) <= MAX_LABELS and all(len(k) <= MAX_LABEL_KEY for k in labels)
                 and all(len(v) <= MAX_LABEL_VALUE for v in labels.values()))
    try:
        b = load_bundle(_gz(doc))
    except BundleInvalid:
        assert not expect_ok
    else:
        assert expect_ok and b.host.labels == labels


@given(st.lists(st.sampled_from([DRIFT_PROBE, "net.tls.https"]), max_size=10), st.booleans())
def test_drift_and_fleet_injection_never_survive(probes, nested):
    findings = [{"probe_id": p, "title": "t", "evidence": {"_fleet": {"host": "evil"}, "host": "h",
                                                           "n": {"_fleet": 1} if nested else 1}}
                for p in probes]
    doc = {"schema_version": 1, "scan_uuid": "u", "host": {"machine_id": "m"}, "scan": {}, "findings": findings}
    b = load_bundle(_gz(doc))
    assert b.dropped_drift == probes.count(DRIFT_PROBE)
    assert [f["probe_id"] for f in b.findings] == [p for p in probes if p != DRIFT_PROBE]
    assert all("_fleet" not in f["evidence"] and f["evidence"]["host"] == "h" for f in b.findings)


# --- store: a bundle that loads must either store or be refused the way the daemon maps it (400) -------------------

_nasty = st.sampled_from(["", "a", "\x00", "\ud800", "\udc80", "\u00e9", "' OR '1'='1", "x" * 70_000,
                          "2026-13-45", "9999-12-31T23:59:59+99:00", "0001-01-01", "1e999"])
_ingest_scalar = _scalars | _nasty
_ingest_finding = st.fixed_dictionaries(
    {"probe_id": st.sampled_from(["net.tls.https", "fs.cert.x509"]) | _ingest_scalar},
    optional={"algorithm": _ingest_scalar, "title": _ingest_scalar, "classification": _ingest_scalar,
              "severity": _ingest_scalar, "created_at": _ingest_scalar, "evidence": _evidence,
              "remediation": _evidence | json_values,
              "views": st.lists(st.one_of(json_values, st.fixed_dictionaries(
                  {"framework": _ingest_scalar, "clause": _ingest_scalar, "verdict": _ingest_scalar},
                  optional={"deadline": _ingest_scalar})), max_size=3) | json_values},
)
_ingest_doc = st.fixed_dictionaries({
    "schema_version": st.just(1), "scan_uuid": st.uuids().map(str),
    "host": st.fixed_dictionaries(
        {"machine_id": st.just("m-fuzz")},
        optional={"hostname": _nasty | st.just("h"), "os": _nasty | st.just("linux"),
                  "agent_version": _nasty | st.just("1"),
                  "labels": st.dictionaries(st.text(min_size=1, max_size=70), st.text(max_size=260), max_size=70)}),
    "scan": st.fixed_dictionaries(
        {}, optional={"status": st.sampled_from(["done", "failed", "interrupted", "running"]) | _ingest_scalar,
                      "started_at": _ingest_scalar, "finished_at": _ingest_scalar, "mode": _ingest_scalar,
                      "probe_versions": json_values, "tool_versions": json_values}),
    "findings": st.lists(_ingest_finding, max_size=6),
})


@pytest.fixture(scope="module")
def fleet_repo(tmp_path_factory):
    repo = Repo(tmp_path_factory.mktemp("fuzz-ingest") / "fleet.db")
    repo.init_schema()
    repo.upsert_host(HostIdentity("m-fuzz", "h", "linux"), token_hash="t")
    return repo


@given(_ingest_doc)
def test_any_loadable_bundle_is_stored_or_refused_as_a_400(fleet_repo, doc):
    host = fleet_repo.get_host_by_machine_id("m-fuzz")
    try:
        bundle = load_bundle(_gz(doc))
    except _OK:
        return
    try:
        res = fleet_repo.ingest_bundle(bundle, host.id)      # daemon/fleet.py maps ValueError/KeyError/TypeError to 400
    except (ValueError, KeyError, TypeError):
        return
    assert res.duplicate or res.scan_id
    labels = fleet_repo.get_host(host.id).labels or {}
    assert len(labels) <= MAX_LABELS and all(len(k) <= MAX_LABEL_KEY and len(v) <= MAX_LABEL_VALUE
                                             for k, v in labels.items())


_pool = [f"k{i}" for i in range(150)]


@given(st.lists(st.dictionaries(st.sampled_from(_pool), st.text(max_size=8), min_size=20, max_size=64),
               min_size=2, max_size=6))
def test_host_labels_never_exceed_the_cap_across_bundles(tmp_path_factory, label_sets):
    repo = Repo(tmp_path_factory.mktemp("fuzz-labels") / "fleet.db")
    repo.init_schema()
    host = repo.upsert_host(HostIdentity("m-lbl", "h", "linux"), token_hash="t")
    for i, labels in enumerate(label_sets):
        doc = {"schema_version": 1, "scan_uuid": f"u-{i}", "host": {"machine_id": "m-lbl", "labels": labels},
               "scan": {"status": "done"}, "findings": []}
        before = dict(repo.get_host(host.id).labels or {})
        try:
            repo.ingest_bundle(load_bundle(_gz(doc)), host.id)
        except ValueError:
            assert repo.get_host(host.id).labels == before          # refused as a whole, nothing half-applied
        assert len(repo.get_host(host.id).labels or {}) <= MAX_LABELS
    repo.engine.dispose()


# --- gzip framing ---------------------------------------------------------------------------------------------------

@given(st.integers(min_value=1, max_value=60))
def test_truncated_gzip_is_never_accepted(cut):
    blob = _gz({"schema_version": 1, "scan_uuid": "u", "host": {"machine_id": "m"}, "scan": {}, "findings": []})
    with pytest.raises(_OK):
        load_bundle(blob[: len(blob) - min(cut, len(blob) - 1)])


# --- dump -> load round trip ----------------------------------------------------------------------------------------

_json_leaf = st.one_of(st.none(), st.booleans(), st.integers(min_value=-(2**53), max_value=2**53), _TEXT)
_json_obj = st.dictionaries(_TEXT.filter(lambda k: k != "_fleet"), _json_leaf, max_size=4)
_finding_in = st.fixed_dictionaries({
    "probe_id": st.sampled_from(["net.tls.https", "fs.cert.x509", "src.python.rsa"]),
    "algorithm": st.sampled_from(["RSA-2048", "ECDSA-P256", "ML-KEM-768", "N/A"]),
    "classification": st.sampled_from(list(Classification)),
    "severity": st.sampled_from(list(Severity)),
    "title": _TEXT,
    "evidence": _json_obj,
    "remediation": _json_obj,
})
_identity = st.builds(
    HostIdentity, machine_id=_TEXT.filter(bool), hostname=_TEXT, os=_TEXT, agent_version=_TEXT,
    labels=st.dictionaries(_TEXT.filter(lambda k: len(k) <= MAX_LABEL_KEY), _TEXT.filter(lambda v: len(v) <= 256),
                           max_size=MAX_LABELS),
)


@given(st.lists(_finding_in, max_size=6), _identity)
def test_dump_then_load_round_trips(findings, ident):
    with tempfile.TemporaryDirectory() as td:
        repo = Repo(Path(td) / "f.db")
        repo.init_schema()
        sid = repo.create_scan(mode="user", probe_versions={"p": "1"}, tool_versions={})
        for f in findings:
            repo.record_finding(sid, Finding(**f))
        repo.finish_scan(sid, status="done")
        loaded = load_bundle(dump_bundle(repo, sid, ident))
        repo.engine.dispose()
    assert loaded.host == ident
    assert loaded.dropped_drift == 0
    got = [{k: f[k] for k in ("probe_id", "algorithm", "title", "evidence", "remediation")} for f in loaded.findings]
    want = [{k: (f[k].value if hasattr(f[k], "value") else f[k]) for k in
             ("probe_id", "algorithm", "title", "evidence", "remediation")} for f in findings]
    assert sorted(got, key=repr) == sorted(want, key=repr)
    assert sorted((f["classification"], f["severity"]) for f in loaded.findings) == \
        sorted((f["classification"].value, f["severity"].value) for f in findings)

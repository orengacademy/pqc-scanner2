import pytest

from pqcscan.core.mosca import MoscaInputs
from pqcscan.renderers._report_context import build_report_context, mosca_from_labels
from pqcscan.renderers._report_text import report_translator
from pqcscan.renderers.pdf_executive import build_html_executive
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo


def test_mosca_from_labels():
    assert mosca_from_labels({"data_lifetime": "25", "migration_years": "4"}).data_lifetime_years == 25
    assert mosca_from_labels({"data_lifetime": "25"}).migration_years == 5.0  # default kept
    assert mosca_from_labels({}) is None and mosca_from_labels({"data_lifetime": "x"}) is None


@pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "0", "-3", "201", "", "1e999", "abc"])
def test_mosca_from_labels_rejects_bad_values(bad):
    assert mosca_from_labels({"data_lifetime": bad}) is None
    got = mosca_from_labels({"data_lifetime": "25", "migration_years": bad, "threat_years": bad})
    assert (got.migration_years, got.threat_years) == (5.0, 10.0)


def _ingest(fleet, tmp_path, labels):
    src = Repo(tmp_path / "s.db")
    src.init_schema()
    ident = HostIdentity(machine_id="m", hostname="core-db", os="linux", labels=labels)
    h = fleet.upsert_host(ident)
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
    src.finish_scan(sid, status="done")
    return fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, ident)), h.id).scan_id


def test_report_context_reads_host_labels(tmp_db_path, tmp_path):
    fleet = Repo(tmp_db_path)
    fleet.init_schema()
    scan_id = _ingest(fleet, tmp_path, {"data_lifetime": "25"})
    ctx = build_report_context(fleet, scan_id, lang="en")
    assert ctx["mosca"]["x"] == 25.0 and ctx["mosca"]["assumed"] is False
    assert ctx["mosca"]["source"] == "labels"
    assert ctx["host_labels"] == {"data_lifetime": "25"}


def test_explicit_inputs_beat_labels(tmp_db_path, tmp_path):
    fleet = Repo(tmp_db_path)
    fleet.init_schema()
    scan_id = _ingest(fleet, tmp_path, {"data_lifetime": "25"})
    ctx = build_report_context(fleet, scan_id, mosca_inputs=MoscaInputs(data_lifetime_years=7.0))
    assert ctx["mosca"]["x"] == 7.0 and ctx["mosca"]["source"] == "explicit"


def test_bad_labels_fall_back_to_default(tmp_db_path, tmp_path):
    fleet = Repo(tmp_db_path)
    fleet.init_schema()
    scan_id = _ingest(fleet, tmp_path, {"data_lifetime": "nan"})
    ctx = build_report_context(fleet, scan_id)
    assert ctx["mosca"]["assumed"] is True and ctx["mosca"]["source"] == "default"


def test_local_scan_unchanged(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.finish_scan(sid, status="done")
    ctx = build_report_context(repo, sid)
    assert ctx["mosca"]["source"] == "default" and ctx["host_labels"] == {}


def test_huge_int_label_is_ignored():
    assert mosca_from_labels({"data_lifetime": 10**400}) is None  # float() raises OverflowError


def test_executive_html_notes_labels_source(tmp_db_path, tmp_path):
    note = report_translator("en")("mosca.from_labels")
    fleet = Repo(tmp_db_path)
    fleet.init_schema()
    assert note in build_html_executive(fleet, _ingest(fleet, tmp_path, {"data_lifetime": "25"}), "en")
    sid = fleet.create_scan(mode="user", probe_versions={}, tool_versions={})
    fleet.finish_scan(sid, status="done")
    assert note not in build_html_executive(fleet, sid, "en")

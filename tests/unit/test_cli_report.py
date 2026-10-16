"""scan --report-to: enroll once, post the bundle, spool on failure."""
import json

import httpx
import pytest

from pqcscan.cli import _report
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity
from pqcscan.store.repo import Repo

IDENT = HostIdentity(machine_id="m-1", hostname="h", os="linux", labels={}, agent_version="x")


def _seed(tmp_path) -> tuple[Repo, int]:
    repo = Repo(tmp_path / "db.db")
    repo.init_schema()
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
                return httpx.Response(
                    200, json={"scan_id": 7, "stored_findings": 1, "stored_views": 0, "duplicate": False})
            return httpx.Response(self.ingest_status, json={"detail": "nope"})
        return httpx.Response(404)


def _client(server: _Server) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(server.handler), base_url="http://c")


def test_enroll_writes_token_0600_and_reuses_it(tmp_path):
    srv = _Server()
    state = tmp_path / "state"
    tok = _report.ensure_agent_token("http://c", enroll_token="E", identity=IDENT, state_dir=state,
                                     client=_client(srv))
    assert tok == "AGENT" and (state / "agent.token").read_text() == "AGENT"
    assert oct((state / "agent.token").stat().st_mode & 0o777) == "0o600"
    sent = json.loads(srv.calls[0][1])
    assert sent["enroll_token"] == "E" and sent["host"]["machine_id"] == "m-1"
    assert _report.ensure_agent_token("http://c", enroll_token=None, identity=IDENT, state_dir=state,
                                      client=_client(srv)) == "AGENT"
    assert len(srv.calls) == 1                                   # no second enroll


def test_report_scan_posts_bundle(tmp_path):
    repo, sid = _seed(tmp_path)
    srv = _Server()
    res = _report.report_scan(repo, sid, server="http://c", enroll_token="E", agent_token=None,
                              labels={"env": "prod"}, state_dir=tmp_path / "s", client=_client(srv))
    assert res == {"scan_id": 7, "stored_findings": 1, "stored_views": 0, "duplicate": False}
    path, body, headers = srv.calls[-1]
    assert path == "/api/ingest" and headers["authorization"] == "Bearer AGENT"
    assert headers["content-type"] == "application/gzip" and body[:2] == b"\x1f\x8b"
    spool = tmp_path / "s" / "spool"
    assert not spool.exists() or not list(spool.glob("*.bundle.gz"))


def test_report_scan_spools_on_server_error_and_flush_resends(tmp_path):
    repo, sid = _seed(tmp_path)
    srv = _Server(ingest_status=503)
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
    for opt in ("--report-to", "--enroll-token", "--agent-token", "--labels", "--state-dir", "--ca-cert",
                "--insecure"):
        assert opt in out

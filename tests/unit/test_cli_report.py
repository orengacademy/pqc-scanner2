"""scan --report-to: enroll once, post the bundle, spool on failure."""
import json
import os
import sys

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
    res = _report.report_scan(repo, sid, server="http://127.0.0.1", enroll_token="E", agent_token=None,
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
    assert _report.report_scan(repo, sid, server="http://127.0.0.1", enroll_token="E", agent_token=None,
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
                "--insecure", "--allow-http"):
        assert opt in out


# ---- fix round 1: never lose a report, hardened state files, plain-http refusal ----

def _spool_files(state):
    d = state / "spool"
    return list(d.glob("*.bundle.gz")) if d.exists() else []


def test_post_bundle_transport_error_is_status_0():
    def boom(req):
        raise httpx.ConnectError("down")
    c = httpx.Client(transport=httpx.MockTransport(boom), base_url="http://c")
    with pytest.raises(_report.ReportError) as ei:
        _report.post_bundle("http://c", "T", b"x", c)
    assert ei.value.status == 0


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]"])
def test_post_bundle_malformed_200_is_report_error(body):
    c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body)),
                     base_url="http://c")
    with pytest.raises(_report.ReportError) as ei:
        _report.post_bundle("http://c", "T", b"x", c)
    assert ei.value.status == 0


@pytest.mark.parametrize("body", [b"not json", b"[1]", b'{"host_id": 1}', b'{"agent_token": ""}'])
def test_enroll_malformed_response_is_report_error_and_writes_nothing(tmp_path, body):
    c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(201, content=body)),
                     base_url="http://c")
    with pytest.raises(_report.ReportError) as ei:
        _report.ensure_agent_token("http://c", enroll_token="E", identity=IDENT, state_dir=tmp_path / "st",
                                   client=c)
    assert ei.value.status == 0 and not (tmp_path / "st" / "agent.token").exists()


def test_report_scan_spools_on_malformed_200(tmp_path):
    repo, sid = _seed(tmp_path)
    c = httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(201, json={"agent_token": "A"}) if r.url.path.endswith("enroll")
        else httpx.Response(200, content=b"<html>")), base_url="http://c")
    state = tmp_path / "s"
    assert _report.report_scan(repo, sid, server="http://127.0.0.1", enroll_token="E", agent_token=None, labels={},
                               state_dir=state, client=c) is None
    assert len(_spool_files(state)) == 1


def test_report_scan_spools_on_unexpected_exception(tmp_path, monkeypatch):
    repo, sid = _seed(tmp_path)
    monkeypatch.setattr(_report, "post_bundle", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bug")))
    state = tmp_path / "s"
    assert _report.report_scan(repo, sid, server="http://127.0.0.1", enroll_token=None, agent_token="T", labels={},
                               state_dir=state, client=_client(_Server())) is None
    assert len(_spool_files(state)) == 1


def test_agent_token_bypasses_enroll(tmp_path):
    repo, sid = _seed(tmp_path)
    srv = _Server()
    assert _report.report_scan(repo, sid, server="http://127.0.0.1", enroll_token=None, agent_token="T", labels={},
                               state_dir=tmp_path / "s", client=_client(srv)) is not None
    assert [c[0] for c in srv.calls] == ["/api/ingest"] and srv.calls[0][2]["authorization"] == "Bearer T"


def test_flush_spool_keeps_rejected_and_breaks_on_5xx(tmp_path):
    state = tmp_path / "s"
    for n in "1234":
        _report.spool_bundle(state, n.encode())
    files = sorted((state / "spool").glob("*.bundle.gz"))
    for i, f in enumerate(files):                   # deterministic order independent of uuid names
        f.rename(f.with_name(f"{i}.bundle.gz"))
    statuses = iter([400, 200, 503, 200])
    seen: list[int] = []

    def handler(req):
        st = next(statuses)
        seen.append(st)
        return httpx.Response(st, json={"detail": "x", "scan_id": 1})
    c = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://c")
    assert _report.flush_spool("http://c", "T", state, c) == (1, 2)
    assert seen == [400, 200, 503]                  # 4th never attempted
    assert sorted(f.name for f in _spool_files(state)) == ["0.bundle.gz", "2.bundle.gz", "3.bundle.gz"]


def test_flush_spool_keeps_unreadable_file(tmp_path):
    state = tmp_path / "s"
    (state / "spool" / "bad.bundle.gz").mkdir(parents=True)     # read_bytes() raises IsADirectoryError
    assert _report.flush_spool("http://c", "T", state, _client(_Server())) == (0, 1)
    assert (state / "spool" / "bad.bundle.gz").exists()


@pytest.mark.parametrize("server,ok", [
    ("https://fleet.example", True), ("http://127.0.0.1:8080", True), ("http://127.5.5.5", True),
    ("http://localhost:1", True), ("http://[::1]:1", True),
    ("http://10.0.0.1:1", False), ("http://fleet.example", False), ("fleet.example", False),
])
def test_check_server_scheme(server, ok):
    if ok:
        _report.check_server_scheme(server, False)
    else:
        with pytest.raises(_report.ReportError, match="--allow-http"):
            _report.check_server_scheme(server, False)
        _report.check_server_scheme(server, True)


def test_report_scan_refuses_plain_http_before_dump_or_spool(tmp_path):
    repo, sid = _seed(tmp_path)
    srv = _Server()
    with pytest.raises(_report.ReportError):
        _report.report_scan(repo, sid, server="http://10.0.0.1:1", enroll_token="E", agent_token=None,
                            labels={}, state_dir=tmp_path / "s", client=_client(srv))
    assert not srv.calls and not (tmp_path / "s").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink/permission semantics")
def test_write_private_refuses_symlink_and_exclusive_existing(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    state = tmp_path / "s"
    state.mkdir()
    (state / "agent.token").symlink_to(victim)
    with pytest.raises(OSError):
        _report._write_private(state / "agent.token", "SECRET", 0o600)
    assert victim.read_text() == "keep"
    planted = state / "planted"
    planted.write_text("old")
    with pytest.raises(FileExistsError):
        _report._write_private(planted, b"new", 0o600, exclusive=True)
    assert planted.read_text() == "old"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_existing_state_dir_keeps_its_mode_but_new_dirs_are_0700(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o755)
    _report._write_private(shared / "agent.token", "T", 0o600)
    assert oct(shared.stat().st_mode & 0o777) == "0o755"
    _report._write_private(tmp_path / "fresh" / "agent.token", "T", 0o600)
    assert oct((tmp_path / "fresh").stat().st_mode & 0o777) == "0o700"


def test_make_client_ca_cert_uses_ssl_context(tmp_path, monkeypatch):
    import ssl
    seen = {}
    monkeypatch.setattr(ssl, "create_default_context", lambda cafile=None: seen.setdefault("ca", cafile) or "CTX")
    got = {}
    monkeypatch.setattr(httpx, "Client", lambda **kw: got.update(kw))
    _report.make_client(ca_cert=tmp_path / "ca.pem")
    assert seen["ca"] == str(tmp_path / "ca.pem") and got["verify"] == str(tmp_path / "ca.pem")
    _report.make_client(insecure=True)
    assert got["verify"] is False


# ---- scan_cmd end to end (scan itself stubbed: covered elsewhere, and it takes ~15s) ----

@pytest.fixture
def stub_scan(tmp_path, monkeypatch):
    from pqcscan.cli import scan as scan_mod
    repo, sid = _seed(tmp_path)
    monkeypatch.setattr(scan_mod, "run_local_scan", lambda **kw: (repo, sid))
    return scan_mod


def test_scan_cli_unreachable_server_spools_and_keeps_exit_code(tmp_path, stub_scan):
    from click.testing import CliRunner
    state = tmp_path / "st"
    base = ["--db", str(tmp_path / "x.db"), "--path", str(tmp_path), "--fail-on", "none",
            "--report-to", "http://127.0.0.1:1", "--enroll-token", "E", "--state-dir", str(state)]
    r = CliRunner().invoke(stub_scan.scan_cmd, [*base, "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout.strip().splitlines()[-1])["report"] is None
    assert len(_spool_files(state)) == 1
    r = CliRunner().invoke(stub_scan.scan_cmd, base)
    assert r.exit_code == 0 and "Reported to http://127.0.0.1:1: spooled for retry." in r.stdout
    assert len(_spool_files(state)) == 2


def test_scan_cli_refuses_plain_http_without_allow_http(tmp_path, stub_scan):
    from click.testing import CliRunner
    state = tmp_path / "st"
    r = CliRunner().invoke(stub_scan.scan_cmd, [
        "--db", str(tmp_path / "x.db"), "--fail-on", "none", "--report-to", "http://10.0.0.1:1",
        "--enroll-token", "E", "--state-dir", str(state)])
    assert r.exit_code == 0
    assert "https" in r.stderr and "--allow-http" in r.stderr
    assert "not sent" in r.stdout and not _spool_files(state)


def test_scan_cli_gate_exit_code_unaffected_by_report(tmp_path, stub_scan):
    from click.testing import CliRunner
    r = CliRunner().invoke(stub_scan.scan_cmd, [
        "--db", str(tmp_path / "x.db"), "--fail-on", "high", "--report-to", "http://127.0.0.1:1",
        "--enroll-token", "E", "--state-dir", str(tmp_path / "st")])
    assert r.exit_code == 1                       # the seeded HIGH finding trips the gate, not the report

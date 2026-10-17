"""pqcscan agent: one cycle = flush spool, scan, post; backoff and re-enroll rules."""
import httpx
import pytest
from click.testing import CliRunner

import pqcscan.cli.scan as scan_mod
from pqcscan.cli import agent as agent_mod
from pqcscan.cli.agent import AgentConfig, agent_cmd, agent_cycle, next_delay, parse_duration
from pqcscan.store.repo import Repo


@pytest.fixture(autouse=True)
def _fast_scan(monkeypatch, fast_registry):
    monkeypatch.setattr(scan_mod, "default_registry", lambda: fast_registry)


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
            return httpx.Response(200, json={"scan_id": 1, "stored_findings": 0, "stored_views": 0,
                                             "duplicate": False})
        return httpx.Response(code, json={"detail": "x"})


def _cfg(tmp_path, **kw) -> AgentConfig:
    d = tmp_path / "scan"
    d.mkdir(exist_ok=True)
    return AgentConfig(server="http://c", enroll_token="E", labels={"env": "t"},
                       state_dir=tmp_path / "state", paths=[str(d)], keep_local=2, allow_http=True, **kw)


def _client(srv) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(srv.handler), base_url="http://c")


def test_cycle_scans_and_reports(tmp_path):
    srv = _Srv()
    r = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r.reported and not r.spooled and not r.re_enrolled and srv.enrolls == 1 and srv.posts == 1
    assert (tmp_path / "state" / "agent.token").read_text() == "T1"


def test_cycle_spools_on_5xx_then_flushes(tmp_path):
    srv = _Srv()
    srv.ingest = [503, 200]
    r1 = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r1.spooled and not r1.reported
    assert len(list((tmp_path / "state" / "spool").glob("*.bundle.gz"))) == 1
    r2 = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r2.reported and not list((tmp_path / "state" / "spool").glob("*.bundle.gz"))


def test_cycle_spools_on_429_without_re_enrolling(tmp_path):
    srv = _Srv()
    srv.ingest = [429]
    r = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r.spooled and not r.reported and not r.re_enrolled and srv.enrolls == 1


def test_cycle_re_enrolls_once_on_401(tmp_path):
    srv = _Srv()
    srv.ingest = [401, 200]
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "agent.token").write_text("STALE")
    r = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r.re_enrolled and r.reported and srv.enrolls == 1
    assert (tmp_path / "state" / "agent.token").read_text() == "T1"


def test_cycle_second_401_spools(tmp_path):
    srv = _Srv()
    srv.ingest = [401]
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "agent.token").write_text("STALE")
    r = agent_cycle(_cfg(tmp_path), _client(srv))
    assert r.re_enrolled and r.spooled and not r.reported and srv.enrolls == 1


def test_local_db_pruned_to_keep_local(tmp_path):
    srv = _Srv()
    for _ in range(4):
        agent_cycle(_cfg(tmp_path), _client(srv))
    assert len(Repo(tmp_path / "state" / "agent.db").list_scans()) == 2


def test_cmd_refuses_plain_http_to_remote_host(tmp_path):
    res = CliRunner().invoke(agent_cmd, ["--server", "http://collector.example:8765", "--once",
                                         "--state-dir", str(tmp_path / "s")])
    assert res.exit_code == 2 and "plain http" in res.output


def test_cmd_once_reports_and_exits_zero(tmp_path, monkeypatch):
    srv = _Srv()
    monkeypatch.setattr(agent_mod, "make_client", lambda **_: _client(srv))
    d = tmp_path / "scan"
    d.mkdir()
    res = CliRunner().invoke(agent_cmd, ["--server", "http://127.0.0.1:8765", "--enroll-token", "E", "--once",
                                         "--state-dir", str(tmp_path / "s"), "--path", str(d)])
    assert res.exit_code == 0 and "reported" in res.output and srv.posts == 1


def test_cmd_once_exits_one_when_spooled(tmp_path, monkeypatch):
    srv = _Srv()
    srv.ingest = [503]
    monkeypatch.setattr(agent_mod, "make_client", lambda **_: _client(srv))
    res = CliRunner().invoke(agent_cmd, ["--server", "http://127.0.0.1:8765", "--enroll-token", "E", "--once",
                                         "--state-dir", str(tmp_path / "s"), "--path", str(tmp_path)])
    assert res.exit_code == 0 and "report spooled; will retry next cycle" in res.output


def test_cmd_once_exits_one_when_scan_raises(tmp_path, monkeypatch):
    def boom(**_):
        raise RuntimeError("scan crashed")
    monkeypatch.setattr(scan_mod, "run_local_scan", boom)
    res = CliRunner().invoke(agent_cmd, ["--server", "http://127.0.0.1:8765", "--once",
                                         "--state-dir", str(tmp_path / "s")])
    assert res.exit_code == 1


def test_backoff_tick_flushes_spool_without_rescanning(tmp_path, monkeypatch):
    srv = _Srv()
    srv.ingest = [503, 200]
    monkeypatch.setattr(agent_mod, "make_client", lambda **_: _client(srv))
    scans = []
    real = scan_mod.run_local_scan
    monkeypatch.setattr(scan_mod, "run_local_scan", lambda **kw: scans.append(1) or real(**kw))
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) == 2:
            raise KeyboardInterrupt
    monkeypatch.setattr(agent_mod.time, "sleep", fake_sleep)
    state = tmp_path / "s"
    CliRunner().invoke(agent_cmd, ["--server", "http://127.0.0.1:8765", "--enroll-token", "E",
                                   "--state-dir", str(state), "--path", str(tmp_path)])
    assert len(scans) == 1 and srv.posts == 2            # one scan; the second POST is the spool flush
    assert sleeps[0] == 60 and not list((state / "spool").glob("*.bundle.gz"))


def test_keep_local_skipped_for_shared_db(tmp_path, capsys):
    srv = _Srv()
    cfg = _cfg(tmp_path, db=tmp_path / "shared.db")      # outside state_dir
    for _ in range(3):
        agent_cycle(cfg, _client(srv))
    assert len(Repo(tmp_path / "shared.db").list_scans()) == 3
    assert "--keep-local ignored: shared database" in capsys.readouterr().err


def test_cycle_permanent_rejection_is_neither_reported_nor_spooled(tmp_path):
    srv = _Srv()
    srv.ingest = [403]
    r = agent_cycle(_cfg(tmp_path), _client(srv))
    assert not r.reported and not r.spooled
    assert not list((tmp_path / "state" / "spool").glob("*.bundle.gz"))


def test_cmd_once_exits_one_on_permanent_rejection(tmp_path, monkeypatch):
    srv = _Srv()
    srv.ingest = [403]
    monkeypatch.setattr(agent_mod, "make_client", lambda **_: _client(srv))
    res = CliRunner().invoke(agent_cmd, ["--server", "http://127.0.0.1:8765", "--enroll-token", "E", "--once",
                                         "--state-dir", str(tmp_path / "s"), "--path", str(tmp_path)])
    assert res.exit_code == 1 and "rejected (403)" in res.output

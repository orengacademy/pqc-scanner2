"""Agent spool replay against the real collector: an outage must not leave a host permanently behind."""
import httpx
from fastapi.testclient import TestClient

from pqcscan.cli import _report
from pqcscan.daemon.app import create_app
from pqcscan.store.repo import Repo

SERVER = "http://127.0.0.1"


def test_spool_drains_after_outage_and_newest_run_stays_latest(tmp_path, fast_registry, monkeypatch):
    monkeypatch.setenv("PQCSCAN_TEST_MACHINE_ID", "m-agent")
    agent = Repo(tmp_path / "agent.db")
    agent.init_schema()
    state = tmp_path / "state"
    up = TestClient(create_app(db_path=tmp_path / "fleet.db", registry=fast_registry, enroll_token="ENROLL"),
                    base_url=SERVER)
    down = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(503, json={"detail": "down"})))
    fleet = Repo(tmp_path / "fleet.db")

    def run(client) -> str:
        sid = agent.create_scan(mode="user", probe_versions={}, tool_versions={})
        agent.finish_scan(sid, status="done")
        _report.report_scan(agent, sid, server=SERVER, enroll_token="ENROLL", agent_token=None, labels={},
                            state_dir=state, client=client, allow_http=True)
        return agent.get_scan(sid).scan_uuid

    def spooled() -> list:
        d = state / _report.SPOOL_DIR
        return sorted(d.iterdir()) if d.exists() else []

    run(down)
    run(down)
    assert len(spooled()) == 2
    for _ in range(3):
        newest = run(up)
        assert spooled() == []
        (latest,) = fleet.fleet_summary()
        assert fleet.get_scan(latest.scan_id).scan_uuid == newest
    assert len(fleet.host_history(latest.host.id)) == 5


def test_spool_files_replay_oldest_first(tmp_path):
    names = [_report.spool_bundle(tmp_path, str(i).encode()).name for i in range(5)]
    assert names == sorted(names)

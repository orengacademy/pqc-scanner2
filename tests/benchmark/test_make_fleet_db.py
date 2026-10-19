"""make_fleet_db at toy size: 10 hosts x 2 scans through the real Repo, labels set, drift on every 10th host."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import make_fleet_db
from pqcscan.store.repo import Repo

pytestmark = pytest.mark.benchmark


def test_ten_hosts_two_scans(tmp_path):
    db = tmp_path / "fleet.db"
    make_fleet_db.build(db, hosts=10, scans_per_host=2, findings=20)
    repo = Repo(db)
    hosts = repo.list_hosts()
    assert [h.hostname for h in hosts] == [f"soak-{i:04d}" for i in range(10)]
    assert {h.machine_id for h in hosts} == {f"m-ui-{i:04d}" for i in range(10)}
    assert all(h.labels["env"] in ("prod", "dr", "dev") and h.labels["site"] in {f"dc{i}" for i in range(5)}
               for h in hosts)
    assert len(repo.list_scans()) == 20
    assert all(len(repo.host_history(h.id)) == 2 for h in hosts)
    summary = {x.host.hostname: x for x in repo.fleet_summary()}
    assert summary["soak-0000"].drift > 0                         # every 10th host: second bundle drifted
    assert all(x.drift == 0 for name, x in summary.items() if name != "soak-0000")
    assert all(x.total == 20 for x in summary.values())

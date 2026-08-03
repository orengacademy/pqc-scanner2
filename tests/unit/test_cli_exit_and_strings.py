from click.testing import CliRunner

from pqcscan.cli.export import export_cmd
from pqcscan.cli.scan import scan_cmd
from pqcscan.store.repo import Repo


def test_scan_internal_error_exits_2(tmp_path):
    # A file where the DB's parent directory should be makes mkdir() blow up
    # before the scan starts — the documented "scan failed" exit code is 2.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    result = CliRunner().invoke(scan_cmd, ["--db", str(blocker / "pqcscan.db")])
    assert result.exit_code == 2


def test_export_cbom_reports_cyclonedx_17(tmp_path):
    db = tmp_path / "pqcscan.db"
    repo = Repo(db)
    repo.init_schema()
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.finish_scan(scan_id, status="done")
    result = CliRunner().invoke(export_cmd, [
        "--scan", str(scan_id), "--format", "cbom",
        "-o", str(tmp_path / "cbom.json"), "--db", str(db),
    ])
    assert result.exit_code == 0
    assert "CycloneDX 1.7" in result.output

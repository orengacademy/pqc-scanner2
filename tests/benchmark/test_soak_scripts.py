"""Static checks on the real-soak scripts: they parse, the Windows workflow loads, the sampler header is the one
`soak.sh collect` checks pulled CSVs against."""
import subprocess
from pathlib import Path

import yaml

CLOUD = Path(__file__).resolve().parents[2] / "benchmark/fleet/cloud"
HEADER = "ts,role,load1,mem_used_kb,mem_avail_kb,disk_used_kb,db_bytes,wal_bytes,state_bytes,spool_files,hosts,scans,findings"


def test_shell_scripts_parse():
    for s in ("soak.sh", "soak-agent-init.sh", "sampler.sh", "loadbox.sh", "suite.sh"):
        subprocess.run(["bash", "-n", str(CLOUD / s)], check=True)


def test_windows_soak_workflow_loads_and_pins_identity():
    wf = yaml.safe_load((CLOUD.parents[2] / ".github/workflows/soak-windows.yml").read_text())
    assert wf[True]["schedule"] == [{"cron": "0 2 * * *"}]        # PyYAML parses `on` as True
    steps = "\n".join(str(s) for s in wf["jobs"]["agent"]["steps"])
    assert "MachineGuid" in steps and "actions/cache/restore" in steps and "--once" in steps


def test_sampler_header_matches_collect_parser():
    header = next(ln for ln in (CLOUD / "sampler.sh").read_text().splitlines() if ln.startswith("HEADER="))
    assert HEADER in header
    # soak.sh collect reads the header out of sampler.sh with this sed expression, then compares each pulled CSV.
    assert "sed -n 's/^HEADER=\"\\(.*\\)\"$/\\1/p'" in (CLOUD / "soak.sh").read_text()


def test_collector_cloud_init_loads_after_ref_substitution():
    raw = (CLOUD / "soak-collector-init.yaml").read_text()
    assert raw.startswith("#cloud-config\n") and "@PQC_REF@" in raw
    doc = yaml.safe_load(raw.replace("@PQC_REF@", "0" * 40))
    assert {"python3.12-venv", "git", "sqlite3", "ufw"} <= set(doc["packages"])
    script = doc["runcmd"][0][2]
    assert "--keep-scans-per-host 12" in script and "subjectAltName=IP:" in script and "/root/READY" in script

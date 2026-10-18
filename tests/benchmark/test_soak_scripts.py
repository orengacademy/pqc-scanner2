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
    # The cache holds agent.token: only the encrypted tarball may go in or come out.
    assert "SOAK_STATE_KEY" in steps
    cache = {s["uses"].split("@")[0]: s["with"]["path"] for s in wf["jobs"]["agent"]["steps"]
             if s.get("uses", "").startswith("actions/cache/")}
    assert cache["actions/cache/save"].endswith(".enc") and cache["actions/cache/restore"].endswith(".enc")
    # agent.log is a public artifact. The agent writes raw output outside it; a separate scrub step writes it, and
    # the upload runs only when that step succeeded (fail closed).
    by_name = {s.get("id") or s.get("name") or s["uses"]: s for s in wf["jobs"]["agent"]["steps"]}
    agent = next(s for s in by_name.values() if "--once" in s.get("run", ""))
    assert "agent-raw.log" in agent["run"] and "::add-mask::" in agent["run"] and "Tee-Object agent.log" not in agent["run"]
    scrub = by_name["scrub"]
    assert scrub["if"] == "always()"
    assert all(k in scrub["run"] for k in ("SOAK_ENROLL_TOKEN", "SOAK_SERVER_URL", "'<server>'", "agent-raw.log"))
    upload = by_name["actions/upload-artifact@v4"]
    assert "steps.scrub.outcome == 'success'" in upload["if"]


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


def test_loadbox_run_takes_its_modes_from_suite():
    # Mode validation happens before any doctl or ssh call, so a bad mode is safe to try here.
    r = subprocess.run(["bash", str(CLOUD / "loadbox.sh"), "run", "no-such-mode"], capture_output=True, text=True)
    assert r.returncode == 2
    assert "before|after|sweep|ratio-baseline|pg-insert" in r.stderr


def test_soak_down_fails_when_doctl_cannot_list(tmp_path):
    # A failed list must not read as "already gone": down exits non-zero and never claims the droplets are gone.
    fake = tmp_path / "doctl"
    fake.write_text("#!/bin/sh\necho 'Error: unable to reach api' >&2\nexit 1\n")
    fake.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path)}
    r = subprocess.run(["bash", str(CLOUD / "soak.sh"), "down"], capture_output=True, text=True, env=env)
    assert r.returncode != 0
    assert "droplet list failed" in r.stderr and "droplets gone" not in r.stdout


def test_soak_up_refuses_a_retired_image_before_creating_anything(tmp_path):
    # The fake doctl lists no droplets and offers no debian-13-x64; it logs every call so a create would show.
    log = tmp_path / "calls"
    fake = tmp_path / "doctl"
    fake.write_text(f"""#!/bin/sh
echo "$*" >> {log}
case "$*" in
  "compute image list-distribution"*) printf 'ubuntu-24-04-x64\\nrockylinux-9-x64\\ndebian-12-x64\\n';;
esac
""")
    fake.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path)}
    r = subprocess.run(["bash", str(CLOUD / "soak.sh"), "up"], capture_output=True, text=True, env=env)
    assert r.returncode == 2
    assert "image debian-13-x64 is not offered" in r.stderr
    assert "create" not in log.read_text()

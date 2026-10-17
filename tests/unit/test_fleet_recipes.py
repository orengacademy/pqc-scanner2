import configparser
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2] / "packaging" / "fleet"
FILES = ("pqcscan-agent.service", "pqcscan-agent.timer", "windows-task.ps1",
         "ansible-playbook.yml", "bigfix-fixlet.md", "osquery-wazuh.md")


def test_recipes_exist_and_reference_report_to():
    for name in FILES:
        assert (ROOT / name).is_file(), name
    for name in ("pqcscan-agent.service", "windows-task.ps1", "ansible-playbook.yml", "bigfix-fixlet.md"):
        assert "--report-to" in (ROOT / name).read_text(), name


def test_systemd_units_parse():
    for name in ("pqcscan-agent.service", "pqcscan-agent.timer"):
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        cp.read_string((ROOT / name).read_text())
        assert "Unit" in cp.sections()
    svc = configparser.ConfigParser(strict=False, interpolation=None)
    svc.read_string((ROOT / "pqcscan-agent.service").read_text())
    assert svc["Service"]["Type"] == "oneshot"


def test_service_is_sandboxed_and_not_root():
    svc = configparser.ConfigParser(strict=False, interpolation=None)
    svc.read_string((ROOT / "pqcscan-agent.service").read_text())
    s = svc["Service"]
    assert s["User"] != "root"
    assert s["ProtectSystem"] == "strict"
    assert s["ReadWritePaths"] == "/var/lib/pqcscan"
    assert s["KillSignal"] == "SIGTERM"


def test_no_recipe_skips_tls_verification():
    for name in FILES:
        assert "--insecure" not in (ROOT / name).read_text(), name


def test_ansible_playbook_is_yaml_with_vaulted_token_hidden():
    play = yaml.safe_load((ROOT / "ansible-playbook.yml").read_text())
    tasks = play[0]["tasks"]
    env_task = next(t for t in tasks if "agent.env" in t["name"])
    assert env_task["no_log"] is True
    assert env_task["ansible.builtin.copy"]["mode"] == "0640"


def test_windows_task_takes_over_folders_and_installs_code_under_program_files():
    ps = (ROOT / "windows-task.ps1").read_text()
    for needle in ("/setowner", "/reset", "Get-Acl", "ProgramFiles"):
        assert needle in ps, needle


def test_windows_task_fails_closed_and_checks_icacls():
    ps = (ROOT / "windows-task.ps1").read_text()
    assert "ReparsePoint" in ps and "LASTEXITCODE" in ps
    for line in ps.splitlines():
        if "icacls" in line:
            assert not re.search(r"\s/C\b", line), line

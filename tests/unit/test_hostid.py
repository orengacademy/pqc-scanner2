import hashlib
from pathlib import Path

from pqcscan import __version__
from pqcscan.util import hostid


def _h(raw: str) -> str:
    return hashlib.sha256(f"pqcscan|{raw}".encode()).hexdigest()


def test_test_machine_id_env_overrides_verbatim(monkeypatch, tmp_path: Path):
    (tmp_path / "machine-id").write_text("abc123\n")
    monkeypatch.setattr(hostid.sys, "platform", "linux")
    monkeypatch.setattr(hostid, "_LINUX_ID_FILES", (tmp_path / "machine-id",))
    monkeypatch.setenv("PQCSCAN_TEST_MACHINE_ID", "m-web01")
    assert hostid.machine_id() == "m-web01"
    monkeypatch.delenv("PQCSCAN_TEST_MACHINE_ID")
    assert hostid.machine_id() == _h("abc123")


def test_linux_machine_id_file(monkeypatch, tmp_path: Path):
    (tmp_path / "machine-id").write_text("abc123\n")
    monkeypatch.setattr(hostid.sys, "platform", "linux")
    monkeypatch.setattr(hostid, "_LINUX_ID_FILES", (tmp_path / "nope", tmp_path / "machine-id"))
    assert hostid.machine_id() == _h("abc123") == hashlib.sha256(b"pqcscan|abc123").hexdigest()


def test_fallback_is_stable_hash(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(hostid.sys, "platform", "linux")
    monkeypatch.setattr(hostid, "_LINUX_ID_FILES", (tmp_path / "nope",))
    monkeypatch.setattr(hostid.socket, "gethostname", lambda: "h1")
    monkeypatch.setattr(hostid.uuid, "getnode", lambda: 0x1234)
    expect = hashlib.sha256(b"pqcscan|h1|4660").hexdigest()
    assert hostid.machine_id() == expect == hostid.machine_id()


def test_unreadable_id_file_falls_back(monkeypatch, tmp_path: Path):
    (tmp_path / "machine-id").write_bytes(b"\xff\xfe")
    monkeypatch.setattr(hostid.sys, "platform", "linux")
    monkeypatch.setattr(hostid, "_LINUX_ID_FILES", (tmp_path / "machine-id",))
    monkeypatch.setattr(hostid.socket, "gethostname", lambda: "h1")
    monkeypatch.setattr(hostid.uuid, "getnode", lambda: 0x1234)
    assert hostid.machine_id() == _h("h1|4660")


def test_darwin_ioreg_parse(monkeypatch):
    monkeypatch.setattr(hostid.sys, "platform", "darwin")
    monkeypatch.setattr(hostid, "_run", lambda argv: '  "IOPlatformUUID" = "AAAA-BBBB"\n')
    assert hostid.machine_id() == _h("AAAA-BBBB")


def test_parse_labels_and_identity(monkeypatch):
    assert hostid.parse_labels(["env=prod,tier=1", "group=web"]) == {"env": "prod", "tier": "1", "group": "web"}
    monkeypatch.setattr(hostid, "machine_id", lambda: "m")
    ident = hostid.host_identity({"env": "prod"})
    assert ident.machine_id == "m" and ident.labels == {"env": "prod"} and ident.agent_version == __version__
    assert ident.os in {"linux", "darwin", "windows", "other"}

"""--path / --target must reach probes built with default roots/host."""
from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Probe, ScanContext
from pqcscan.runner.runner import bind_context


class _FsProbe(Probe):
    id = "fs.test"
    family = ProbeFamily.FILESYSTEM

    def __init__(self) -> None:
        self.roots = [Path("/etc")]

    async def run(self, ctx, emit) -> None: ...


class _NetProbe(Probe):
    id = "net.test"
    family = ProbeFamily.NETWORK

    def __init__(self) -> None:
        self.host = "127.0.0.1"

    async def run(self, ctx, emit) -> None: ...


class _HostProbe(_NetProbe):
    id = "host.test"
    family = ProbeFamily.HOST


def _ctx(**kw) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(), **kw)


def test_scan_paths_replace_default_roots_on_a_copy():
    p = _FsProbe()
    b = bind_context(p, _ctx(scan_paths=[Path("/srv/app")]))
    assert b is not p
    assert b.roots == [Path("/srv/app")]      # --path scopes the scan
    assert p.roots == [Path("/etc")]          # registry singleton untouched


def test_target_host_replaces_default_on_network_probes_only():
    assert bind_context(_NetProbe(), _ctx(server_target="example.com:8443")).host == "example.com"
    assert bind_context(_NetProbe(), _ctx(server_target="[::1]:443")).host == "::1"
    assert bind_context(_HostProbe(), _ctx(server_target="example.com")).host == "127.0.0.1"


def test_no_inputs_returns_same_instance():
    p = _FsProbe()
    assert bind_context(p, _ctx()) is p

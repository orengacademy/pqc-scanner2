from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Probe
from pqcscan.probes._registry import Registry


class _FakeProbe(Probe):
    id = "test.fake"
    family = ProbeFamily.AUX

    async def run(self, ctx, emit):
        return None


def test_registry_register_and_list():
    reg = Registry()
    reg.register(_FakeProbe())
    assert "test.fake" in reg.ids()
    assert isinstance(reg.get("test.fake"), _FakeProbe)


def test_registry_filter_by_family():
    reg = Registry()
    reg.register(_FakeProbe())
    aux = list(reg.by_family(ProbeFamily.AUX))
    assert len(aux) == 1

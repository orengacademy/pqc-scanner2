import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.pqc_alg_normaliser import PqcAlgNormaliser


@pytest.mark.asyncio
async def test_normaliser_emits_zero_findings_in_isolation():
    found = []
    probe = PqcAlgNormaliser()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda x: found.append(x))
    assert found == []

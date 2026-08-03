from pqcscan.daemon.sse import event_for_scan
from pqcscan.runner.event_bus import FindingDiscovered, ScanCompleted, StageStarted


def test_matching_scan_id_passes():
    assert event_for_scan(StageStarted(scan_id=3, stage="host"), 3)
    assert event_for_scan(ScanCompleted(scan_id=3), 3)


def test_other_scans_events_are_filtered_out():
    ev = FindingDiscovered(
        scan_id=4, probe_id="p", title="t", algorithm="A",
        classification="info", severity="info",
    )
    assert not event_for_scan(ev, 3)

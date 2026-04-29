import os

from pqcscan.core.types import Capability
from pqcscan.runner.capabilities import current_mode, detect_capabilities


def test_current_mode_returns_user_or_root():
    mode = current_mode()
    assert mode in {"user", "root"}


def test_detect_capabilities_returns_set():
    caps = detect_capabilities()
    assert isinstance(caps, set)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        assert Capability.ROOT not in caps

from __future__ import annotations

import os
import sys
from shutil import which

from pqcscan.core.types import Capability


def current_mode() -> str:
    """Return 'root' if effective uid is 0 (or Windows admin), else 'user'."""
    if sys.platform == "win32":
        try:
            import ctypes
            return "root" if ctypes.windll.shell32.IsUserAnAdmin() else "user"  # type: ignore[attr-defined]
        except Exception:
            return "user"
    return "root" if os.geteuid() == 0 else "user"


def detect_capabilities() -> set[Capability]:
    """Best-effort detection of what this process can do."""
    caps: set[Capability] = set()
    if current_mode() == "root":
        caps.add(Capability.ROOT)
        caps.add(Capability.NET_RAW)
        caps.add(Capability.DAC_READ_SEARCH)

    if which("kubectl"):
        caps.add(Capability.KUBECTL)
    if which("docker") or which("podman") or which("nerdctl"):
        caps.add(Capability.CONTAINER_RT)

    return caps

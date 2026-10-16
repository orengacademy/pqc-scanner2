"""Stable machine identity for fleet enrollment (no PII beyond hostname).

Ids are keyed sha256 hashes so the systemd machine-id (documented confidential) never reaches the collector.
"""
from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import uuid
from collections.abc import Iterable
from pathlib import Path

from pqcscan import __version__
from pqcscan.store.bundle import HostIdentity

_LINUX_ID_FILES: tuple[Path, ...] = (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id"))


def _run(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _hash(raw: str) -> str:
    return hashlib.sha256(f"pqcscan|{raw}".encode()).hexdigest()


def _raw_machine_id() -> str | None:
    if sys.platform.startswith("linux"):
        for p in _LINUX_ID_FILES:
            try:
                v = p.read_text().strip()
            except (OSError, ValueError):
                continue
            if v:
                return v
    elif sys.platform == "darwin":
        for line in _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]).splitlines():
            if "IOPlatformUUID" in line and '"' in line:
                return line.split('"')[-2]
    elif sys.platform == "win32":
        try:
            import winreg  # type: ignore[import-not-found]
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return str(winreg.QueryValueEx(k, "MachineGuid")[0])
        except (ImportError, OSError):
            pass
    return None


def machine_id() -> str:
    """Stable hashed machine id.

    PQCSCAN_TEST_MACHINE_ID is TEST-ONLY: when set it is returned verbatim (unhashed) so several agents on one
    box enroll as distinct hosts. Never set it in production.
    """
    if v := os.environ.get("PQCSCAN_TEST_MACHINE_ID"):
        return v
    raw = _raw_machine_id()
    if raw is None:
        # Known limit: in a container without /etc/machine-id, hostname and uuid.getnode() can change between runs
        # (deferred follow-up: persist a generated id under the agent state dir).
        raw = f"{socket.gethostname()}|{uuid.getnode()}"
    return _hash(raw)


def parse_labels(raw: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in raw:
        for part in str(item).split(","):
            if "=" in part:
                k, _, v = part.partition("=")
                if k.strip():
                    out[k.strip()] = v.strip()
    return out


def host_identity(labels: dict[str, str] | None = None) -> HostIdentity:
    plat = sys.platform
    os_name = "linux" if plat.startswith("linux") else "darwin" if plat == "darwin" else \
        "windows" if plat == "win32" else "other"
    return HostIdentity(machine_id=machine_id(), hostname=socket.gethostname(), os=os_name,
                        labels=dict(labels or {}), agent_version=__version__)

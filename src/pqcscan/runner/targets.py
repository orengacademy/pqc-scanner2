"""Parse user-supplied scan targets into ScanContext inputs.

A scan can be pointed at three kinds of thing:
- a filesystem path to walk (`--path`),
- a network endpoint for the TLS/STARTTLS probes (`--target host[:port]`),
- an OT/ICS endpoint (`--ot host:port[:proto]`).

These helpers keep the parsing in one place so the CLI, the daemon API, and
the web form all interpret targets identically.
"""
from __future__ import annotations

from pathlib import Path

from pqcscan.probes._base import OTTarget

# Default OT/ICS ports by protocol hint, used when `--ot host` omits a port.
_OT_DEFAULT_PORTS: dict[str, int] = {
    "modbus": 502,
    "s7": 102,
    "opcua": 4840,
    "dnp3": 20000,
    "bacnet": 47808,
    "iec104": 2404,
    "mms": 102,
    "ethernetip": 44818,
    "dicom": 2762,
    "hl7": 2575,
}


def normalise_server_target(raw: str) -> str | None:
    """Return a cleaned `host[:port]` string, or None if unusable.

    Accepts bare hosts, host:port, and full URLs (scheme + path stripped).
    """
    s = raw.strip()
    if not s:
        return None
    # Strip a URL scheme and any path/query so `https://example.com/foo` →
    # `example.com`.
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].strip()
    if not s:
        return None
    return s


def parse_ot_target(raw: str) -> OTTarget | None:
    """Parse `host`, `host:port`, or `host:port:proto` into an OTTarget.

    `host:proto` (a non-numeric second field) is also accepted and the port
    is filled from the protocol's default.
    """
    s = raw.strip()
    if not s:
        return None
    parts = s.split(":")
    host = parts[0].strip()
    if not host:
        return None
    port: int | None = None
    proto: str | None = None

    if len(parts) >= 2 and parts[1].strip():
        second = parts[1].strip()
        if second.isdigit():
            port = int(second)
        else:
            proto = second.lower()
    if len(parts) >= 3 and parts[2].strip():
        proto = parts[2].strip().lower()

    if port is None:
        port = _OT_DEFAULT_PORTS.get(proto or "", 0)
    if port <= 0:
        return None
    return OTTarget(host=host, port=port, proto_hint=proto)


def parse_scan_inputs(
    *,
    target: str | None = None,
    paths: list[str] | None = None,
    ot: list[str] | None = None,
) -> tuple[list[Path], str | None, list[OTTarget]]:
    """Turn raw CLI/API strings into (scan_paths, server_target, ot_targets)."""
    scan_paths = [Path(p) for p in (paths or []) if p and p.strip()]
    server_target = normalise_server_target(target) if target else None
    ot_targets = [t for t in (parse_ot_target(o) for o in (ot or [])) if t is not None]
    return scan_paths, server_target, ot_targets

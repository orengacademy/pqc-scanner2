"""Host-agnostic identity for a finding so two hosts (primary vs DR) can be compared."""
from __future__ import annotations

import re
from typing import Any

from pqcscan.core.types import Classification, Finding, Severity

DRIFT_PROBE = "fleet.drift"

_H16 = r"[0-9a-fA-F]{1,4}"
_IPV6 = rf"(?:(?:{_H16}:){{7}}{_H16}|(?:{_H16}:){{0,6}}:(?:{_H16}(?::{_H16}){{0,5}})?)"
_IPV4 = r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.]*\w)"
_HOSTPORT = re.compile(rf"(?:\[[0-9a-fA-F:]+\]|{_IPV4}|[A-Za-z0-9][A-Za-z0-9._-]*):(\d{{1,5}})\b")
_LITERAL = re.compile(rf"{_IPV4}|(?<![\w:]){_IPV6}(?![\w:])")
_AT_HOST = re.compile(r"\bat\s+(?!<host>)[A-Za-z0-9][\w.-]*")


def _norm_title(title: str, host: str = "") -> str:
    t = title
    if host:
        t = re.sub(rf"(?<![\w.-]){re.escape(host)}(?![\w-])", "<host>", t, flags=re.IGNORECASE)
    t = _HOSTPORT.sub(r"<host>:\1", t)
    t = _LITERAL.sub("<host>", t)
    t = _AT_HOST.sub("at <host>", t)
    return re.sub(r"\s+", " ", t).strip()


def parity_key(probe_id: str, algorithm: str, title: str, evidence: dict[str, Any]) -> tuple[str, str, str]:
    """Identity of a finding that survives a change of host name or address.

    `evidence["host"]` is the scan target and is stripped from the title together with host:port,
    IPv4/IPv6 literals and `at <host>` phrases. A file path is kept verbatim and replaces the title.
    An endpoint contributes only its port. `evidence["_fleet"]` is server-side attribution and is ignored.
    """
    ev = evidence or {}
    if ev.get("path"):
        return probe_id, algorithm, f"path={ev['path']}"
    norm = _norm_title(title, str(ev.get("host") or ""))
    m = _HOSTPORT.search(str(ev["endpoint"])) if ev.get("endpoint") else None
    if m and f":{m.group(1)}" not in norm:
        norm = f"{norm} [:{m.group(1)}]"
    return probe_id, algorithm, norm


def drift_rows(previous: list, current: list) -> list[Finding]:
    """One INFO `fleet.drift` finding per parity key that appeared in or vanished from `current`.

    Rows are FindingRow-like (probe_id, algorithm, title, evidence). Earlier drift rows are ignored.
    """
    def keys(rows: list) -> dict[tuple[str, str, str], Any]:
        return {parity_key(r.probe_id, r.algorithm, r.title, r.evidence or {}): r
                for r in rows if r.probe_id != DRIFT_PROBE}
    prev, cur = keys(previous), keys(current)
    return ([_drift("added", r) for k, r in cur.items() if k not in prev]
            + [_drift("removed", r) for k, r in prev.items() if k not in cur])


def _drift(change: str, r: Any) -> Finding:
    return Finding(probe_id=DRIFT_PROBE, algorithm=r.algorithm, classification=Classification.INFO,
                   severity=Severity.INFO, title=f"drift: {change} {r.probe_id} {r.algorithm}",
                   evidence={"change": change, "probe_id": r.probe_id, "algorithm": r.algorithm, "title": r.title})

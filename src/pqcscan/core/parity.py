"""Host-agnostic identity for a finding so two hosts (primary vs DR) can be compared."""
from __future__ import annotations

import re
from typing import Any

from pqcscan.core.types import Classification, Finding, Severity

DRIFT_PROBE = "fleet.drift"

MAX_TITLE_NORMALISE = 512   # titles and hosts come from agents: bound the work done per finding

_H16 = r"[0-9a-fA-F]{1,4}"
_IPV6 = rf"(?:(?:{_H16}:){{7}}{_H16}|(?:{_H16}:){{0,6}}:(?:{_H16}(?::{_H16}){{0,5}})?)"
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
# Applied with fullmatch to one whitespace-delimited token at a time, so each match is linear in a short token.
_HOSTPORT = re.compile(rf"(?:\[[0-9a-fA-F:]+\]|{_IPV4}|[A-Za-z0-9][A-Za-z0-9._-]*):(\d{{1,5}})")
_LITERAL = re.compile(rf"{_IPV4}|{_IPV6}")
_NAME = re.compile(r"[A-Za-z0-9][\w.-]*")
_OPEN, _CLOSE = "(\"'", ",;.)\"'"


def _norm_token(tok: str, after_at: bool) -> str:
    lead = tok[: len(tok) - len(tok.lstrip(_OPEN))]
    core = tok.lstrip(_OPEN)
    tail = core[len(core.rstrip(_CLOSE)):]
    core = core.rstrip(_CLOSE)
    if (m := _HOSTPORT.fullmatch(core)) is not None:
        core = f"<host>:{m.group(1)}"
    elif _LITERAL.fullmatch(core):
        core = "<host>"
    elif after_at and (m := _NAME.match(core)) is not None:
        core = "<host>" + core[m.end():]
    return lead + core + tail


def _norm_title(title: str, host: str = "") -> str:
    t = title[:MAX_TITLE_NORMALISE]
    if host:
        t = re.sub(rf"(?<![\w.-]){re.escape(host[:253])}(?![\w-])", "<host>", t, flags=re.IGNORECASE)
    out: list[str] = []
    for tok in t.split():
        out.append(_norm_token(tok, bool(out) and out[-1] == "at"))
    return " ".join(out)


def parity_key(probe_id: str, algorithm: str, title: str, evidence: dict[str, Any]) -> tuple[str, str, str]:
    """Identity of a finding that survives a change of host name or address.

    `evidence["host"]` is the scan target and is stripped from the title together with host:port,
    IPv4/IPv6 literals and `at <host>` phrases. A file path is kept verbatim and replaces the title.
    An endpoint adds its port when the title lacks it. `evidence["_fleet"]` is server-side attribution and is ignored.
    Only the first MAX_TITLE_NORMALISE characters of a title are examined.
    """
    ev = evidence or {}
    if ev.get("path"):
        return probe_id, algorithm, f"path={ev['path']}"
    norm = _norm_title(title, str(ev.get("host") or ""))
    port = str(ev.get("endpoint") or "")[:MAX_TITLE_NORMALISE].rpartition(":")[2]
    if port.isascii() and port.isdigit() and len(port) <= 5 and f":{port}" not in norm:
        norm = f"{norm} [:{port}]"
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

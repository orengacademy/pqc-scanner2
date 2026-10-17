"""Host-agnostic identity for a finding so two hosts (primary vs DR) can be compared."""
from __future__ import annotations

import re
from typing import Any

from pqcscan.core.types import Classification, Finding, Severity

DRIFT_PROBE = "fleet.drift"

MAX_TITLE_NORMALISE = 512   # titles and hosts come from agents: bound the work done per finding
MAX_DRIFT_ROWS = 500        # drift rows stored per ingest, plus one summary row when truncated
MAX_DRIFT_NORMALISE = 50_000  # findings on both sides above which drift is counted on raw titles, summary only



def is_drift(row: Any) -> bool:
    """True for a `fleet.drift` change marker: not a finding, so never counted, scored or inventoried."""
    return getattr(row, "probe_id", None) == DRIFT_PROBE


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
    return " ".join(out)[:MAX_TITLE_NORMALISE]   # `<host>` is longer than a one-letter host: the key must not outgrow the cap


def parity_key(probe_id: str, algorithm: str, title: str, evidence: dict[str, Any]) -> tuple[str, str, str]:
    """Identity of a finding that survives a change of host name or address.

    `evidence["host"]` is the scan target and is stripped from the title together with host:port,
    IPv4/IPv6 literals and `at <host>` phrases. A file path is kept verbatim and replaces the title.
    An endpoint adds its port when the title lacks it. `evidence["_fleet"]` is server-side attribution and is ignored.
    Only the first MAX_TITLE_NORMALISE characters of a title are examined, and the normalised title is capped
    at the same length.
    """
    ev = evidence or {}
    if ev.get("path"):
        return probe_id, algorithm, f"path={str(ev['path'])[:MAX_TITLE_NORMALISE]}"
    norm = _norm_title(title, str(ev.get("host") or ""))
    port = str(ev.get("endpoint") or "")[:MAX_TITLE_NORMALISE].rpartition(":")[2]
    if port.isascii() and port.isdigit() and len(port) <= 5 and f":{port}" not in norm:
        norm = f"{norm} [:{port}]"
    return probe_id, algorithm, norm


def drift_rows(previous: list, current: list) -> tuple[list[Finding], int]:
    """INFO `fleet.drift` findings for parity keys that appeared in or vanished from `current`, and the true count.

    Rows are FindingRow-like (probe_id, algorithm, title, evidence). Earlier drift rows are ignored.
    At most MAX_DRIFT_ROWS change rows are kept (sorted by change, then key) plus one summary row with the
    full counts. Above MAX_DRIFT_NORMALISE findings in all, titles are not normalised: changes are counted on
    the raw (probe_id, algorithm, title) triple and only the summary row is returned.
    """
    prev_rows = [r for r in previous if not is_drift(r)]
    cur_rows = [r for r in current if not is_drift(r)]
    if len(prev_rows) + len(cur_rows) > MAX_DRIFT_NORMALISE:
        p = {(r.probe_id, r.algorithm, r.title) for r in prev_rows}
        c = {(r.probe_id, r.algorithm, r.title) for r in cur_rows}
        added, removed = len(c - p), len(p - c)
        return ([_summary(added, removed)] if added or removed else []), added + removed
    prev = {parity_key(r.probe_id, r.algorithm, r.title, r.evidence or {}): r for r in prev_rows}
    cur = {parity_key(r.probe_id, r.algorithm, r.title, r.evidence or {}): r for r in cur_rows}
    changes = sorted([("added", k, r) for k, r in cur.items() if k not in prev]
                     + [("removed", k, r) for k, r in prev.items() if k not in cur], key=lambda x: (x[0], x[1]))
    rows = [_drift(change, r) for change, _, r in changes[:MAX_DRIFT_ROWS]]
    if len(changes) > MAX_DRIFT_ROWS:
        added = sum(1 for x in changes if x[0] == "added")
        rows.append(_summary(added, len(changes) - added))
    return rows, len(changes)


def _summary(added: int, removed: int) -> Finding:
    return Finding(probe_id=DRIFT_PROBE, algorithm="N/A", classification=Classification.INFO,
                   severity=Severity.INFO, title=f"drift: {added} added, {removed} removed (truncated)",
                   evidence={"change": "summary", "added": added, "removed": removed, "truncated": True})


def _drift(change: str, r: Any) -> Finding:
    # algorithm stays N/A: the drifted algorithm is in the title and evidence, never a band or inventory input.
    return Finding(probe_id=DRIFT_PROBE, algorithm="N/A", classification=Classification.INFO,
                   severity=Severity.INFO, title=f"drift: {change} {r.probe_id} {r.algorithm}",
                   evidence={"change": change, "probe_id": r.probe_id, "algorithm": r.algorithm,
                             "title": r.title[:MAX_TITLE_NORMALISE]})

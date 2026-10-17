"""Fuzz parity_key and drift_rows: total, deterministic, bounded in size and in time, with exact change totals."""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest import mock

import pytest

pytest.importorskip("hypothesis")

from hypothesis import example, given
from hypothesis import strategies as st

from pqcscan.core import parity
from pqcscan.core.parity import DRIFT_PROBE, MAX_DRIFT_ROWS, MAX_TITLE_NORMALISE, drift_rows, parity_key

MAX_KEY_PART = 600          # the 512-char title cap plus a ` [:12345]` port suffix, with headroom
SLOW_CASE_S = 0.5           # generous ceiling for CI; the measured worst case is in the task report (< 50 ms)

_T = st.text(max_size=1200)
_pieces = st.sampled_from(["at", "web01", "10.0.0.1", "a:1", "a:443", "[::1]:80", "2001:db8::1", "(x),", "RSA", "'h'",
                           ":", "[", "]", "..", " ", "\t", "é", "<host>", "host", "A"])
_title = st.one_of(_T, st.lists(_pieces, max_size=120).map(" ".join), st.lists(_pieces, max_size=300).map("".join))
_leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(), st.text(max_size=300), st.lists(st.integers()))
_evidence = st.one_of(
    st.none(),
    st.dictionaries(st.sampled_from(["host", "endpoint", "path", "_fleet", "x"]), _leaf, max_size=5),
)


@given(st.text(max_size=30), st.text(max_size=30), _title, _evidence)
def test_parity_key_is_total_deterministic_and_bounded(probe_id, algorithm, title, evidence):
    k1 = parity_key(probe_id, algorithm, title, evidence)
    k2 = parity_key(probe_id, algorithm, title, dict(evidence) if evidence else evidence)
    assert k1 == k2
    assert k1[0] == probe_id and k1[1] == algorithm
    assert isinstance(k1[2], str) and len(k1[2]) <= MAX_KEY_PART


@given(_title, st.text(max_size=300))
@example("a " * 256, "a")                        # every token is the host name: `<host>` is longer than `a`
@example("a:1 " * 128, "")                       # every token becomes `<host>:1`
@example("1.1.1.1 " * 64, "")
def test_normalised_title_never_outgrows_the_cap(title, host):
    assert len(parity_key("p", "A", title, {"host": host})[2]) <= MAX_KEY_PART


@given(_title, _title, _evidence)
def test_server_attribution_and_path_rules(a, b, evidence):
    ev = dict(evidence or {})
    ev.pop("path", None)
    assert parity_key("p", "A", a, {**ev, "_fleet": {"host": "x"}}) == parity_key("p", "A", a, ev)
    pa = parity_key("p", "A", a, {**ev, "path": "/etc/x.pem"})
    assert pa == parity_key("p", "A", b, {**ev, "path": "/etc/x.pem"})      # a path replaces the title
    assert pa[2] == "path=/etc/x.pem"


_ADVERSARIAL = {
    "a:1 runs": "a:1" * 17_000,
    "colon run": ":" * 50_000,
    "a then colon": "a" * 49_999 + ":",
    "bracket run": "[" * 50_000,
    "bracket f:": "[" + "f:" * 25_000,
    "at run": "at " * 16_700,
    "at host run": "at a " * 10_000,
    "ipv4 run": "1.1.1.1 " * 6_250,
    "ipv4 glued": "1.1.1.1" * 7_000,
    "ipv6 run": "f:" * 25_000,
    "ipv6 spaced": "::1 " * 12_500,
    "quotes": "(\"'" * 16_600,
    "dots": "." * 50_000,
    "unicode digits": "١٢٣:" * 12_000,
    "host repeated": "web01 " * 8_000,
}


@pytest.mark.parametrize("name", sorted(_ADVERSARIAL))
def test_parity_key_on_50kb_adversarial_titles_is_fast(name):
    title = _ADVERSARIAL[name]
    assert len(title) >= 40_000
    worst = 0.0
    for ev in ({}, {"host": "web01", "endpoint": title}, {"host": "a" * 300, "endpoint": "h:" + "9" * 50_000}):
        t0 = time.perf_counter()
        key = parity_key("net.tls.https", "RSA-2048", title, ev)
        worst = max(worst, time.perf_counter() - t0)
        assert len(key[2]) <= MAX_KEY_PART
    assert worst < SLOW_CASE_S, f"{name}: {worst * 1000:.1f} ms"


@given(st.lists(_pieces, min_size=1, max_size=40).map(" ".join), st.integers(1, 200))
def test_parity_key_time_does_not_grow_with_title_length(piece, copies):
    long_title = (piece + " ") * copies * 20
    t0 = time.perf_counter()
    parity_key("p", "A", long_title, {"host": "web01"})
    assert time.perf_counter() - t0 < SLOW_CASE_S


# --- drift_rows -----------------------------------------------------------------------------------------------------

_row = st.builds(
    lambda p, a, t, ev: SimpleNamespace(probe_id=p, algorithm=a, title=t, evidence=ev),
    st.sampled_from(["net.tls.https", "fs.cert.x509", DRIFT_PROBE]),
    st.sampled_from(["RSA-2048", "ML-KEM-768", "N/A"]),
    st.lists(_pieces, max_size=6).map(" ".join),
    st.dictionaries(st.sampled_from(["host", "endpoint", "path", "_fleet"]),
                    st.sampled_from(["web01", "dr-02", "web01:443", "/etc/a.pem", "/etc/b.pem", ""]), max_size=3),
)
_rows = st.lists(_row, max_size=30)


def _keys(rows):
    return {parity_key(r.probe_id, r.algorithm, r.title, r.evidence) for r in rows if r.probe_id != DRIFT_PROBE}


def _check(prev, cur, cap, rows, total):
    pk, ck = _keys(prev), _keys(cur)
    assert total == len(pk ^ ck)                                      # the true count, whatever was truncated
    assert all(r.probe_id == DRIFT_PROBE and r.algorithm == "N/A" for r in rows)
    assert len(rows) <= cap + 1
    if total <= cap:
        assert len(rows) == total
        assert sorted(r.evidence["change"] for r in rows) == sorted(["added"] * len(ck - pk) + ["removed"] * len(pk - ck))
    else:
        summary = rows[-1]
        assert summary.evidence["change"] == "summary" and summary.evidence["truncated"] is True
        assert (summary.evidence["added"], summary.evidence["removed"]) == (len(ck - pk), len(pk - ck))
        assert len(rows) == cap + 1


@given(_rows, _rows)
def test_drift_rows_totals_are_exact(prev, cur):
    rows, total = drift_rows(prev, cur)
    _check(prev, cur, MAX_DRIFT_ROWS, rows, total)
    assert drift_rows(prev, cur)[1] == total                          # deterministic


@given(_rows, _rows, st.integers(0, 6))
def test_drift_rows_cap_is_enforced_with_a_summary(prev, cur, cap):
    with mock.patch.object(parity, "MAX_DRIFT_ROWS", cap):
        rows, total = drift_rows(prev, cur)
    _check(prev, cur, cap, rows, total)


@given(_rows, _rows)
def test_drift_rows_tell_the_two_sides_apart(prev, cur):
    assert drift_rows(prev, prev)[1] == 0
    assert drift_rows(prev, [])[1] == len(_keys(prev))
    assert drift_rows([], cur)[1] == len(_keys(cur))
    assert drift_rows(prev, cur)[1] == drift_rows(cur, prev)[1]


@given(_rows, _rows)
def test_drift_rows_above_the_normalise_ceiling_count_raw_titles(prev, cur):
    with mock.patch.object(parity, "MAX_DRIFT_NORMALISE", 0):
        rows, total = drift_rows(prev, cur)
    p = {(r.probe_id, r.algorithm, r.title) for r in prev if r.probe_id != DRIFT_PROBE}
    c = {(r.probe_id, r.algorithm, r.title) for r in cur if r.probe_id != DRIFT_PROBE}
    assert total == len(p ^ c)
    assert len(rows) <= 1
    if rows:
        ev = rows[0].evidence
        assert (ev["added"], ev["removed"]) == (len(c - p), len(p - c))


@given(st.lists(st.text(max_size=900), max_size=8))
def test_drift_row_titles_are_capped(titles):
    cur = [SimpleNamespace(probe_id="p", algorithm="A", title=t, evidence={}) for t in titles]
    rows, _ = drift_rows([], cur)
    assert all(len(r.evidence["title"]) <= MAX_TITLE_NORMALISE for r in rows if "title" in r.evidence)

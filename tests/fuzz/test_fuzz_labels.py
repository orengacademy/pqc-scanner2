"""Fuzz host labels: agents send them, so check_labels may only raise BundleInvalid and mosca_from_labels never raises."""
from __future__ import annotations

import math

import pytest

pytest.importorskip("hypothesis")

from hypothesis import assume, example, given
from hypothesis import strategies as st

from pqcscan.core.mosca import MoscaInputs
from pqcscan.renderers._report_context import _label_years, _mosca_context, mosca_from_labels
from pqcscan.store.bundle import MAX_LABEL_KEY, MAX_LABEL_VALUE, MAX_LABELS, BundleInvalid, check_labels

_KEYS = ("data_lifetime", "migration_years", "threat_years")
_num_text = st.one_of(
    st.floats(allow_nan=True, allow_infinity=True).map(repr), st.integers().map(str),
    st.sampled_from(["", " ", "nan", "inf", "-inf", "1e999", "1e-999", "0", "-0", "0x10", "1_0", "\u0661\u0660", "10 years",
                     "200", "200.0000001", "9" * 5000, "1" + "0" * 400, "+5", " 5 ", "5\n", "\u00b2", "True", "None"]),
    st.text(max_size=300),
)
_any_value = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True), st.text(max_size=300),
                       st.binary(max_size=8), st.lists(st.integers(), max_size=3),
                       st.dictionaries(st.text(max_size=4), st.integers(), max_size=2), _num_text)
_label_dicts = st.one_of(
    st.dictionaries(st.text(max_size=100), _any_value, max_size=80),
    st.dictionaries(st.sampled_from(_KEYS), _any_value | _num_text),
    st.dictionaries(st.sampled_from(_KEYS), _num_text),
)


@given(_label_dicts)
@example({f"k{i}": "v" for i in range(MAX_LABELS + 1)})
@example({"k" * (MAX_LABEL_KEY + 1): "v"})
@example({"k": "v" * (MAX_LABEL_VALUE + 1)})
@example({"k": 1})
@example({"k" * MAX_LABEL_KEY: "v" * MAX_LABEL_VALUE})
def test_check_labels_raises_only_bundle_invalid_and_accepts_only_valid(labels):
    try:
        check_labels(labels)
    except BundleInvalid:
        return
    assert len(labels) <= MAX_LABELS
    for k, v in labels.items():
        assert isinstance(v, str) and len(k) <= MAX_LABEL_KEY and len(v) <= MAX_LABEL_VALUE


@given(st.dictionaries(st.text(max_size=100), st.text(max_size=300), max_size=80))
def test_check_labels_is_exact_for_string_dicts(labels):
    ok = (len(labels) <= MAX_LABELS and all(len(k) <= MAX_LABEL_KEY and len(v) <= MAX_LABEL_VALUE
                                            for k, v in labels.items()))
    if ok:
        check_labels(labels)
    else:
        with pytest.raises(BundleInvalid):
            check_labels(labels)


def _valid(m: MoscaInputs) -> bool:
    return all(math.isfinite(x) and 0 < x <= 200
               for x in (m.data_lifetime_years, m.migration_years, m.threat_years))


@given(st.one_of(_label_dicts, st.none(), st.text(max_size=20), st.lists(st.integers(), max_size=3), st.integers()))
def test_mosca_from_labels_never_raises(labels):
    m = mosca_from_labels(labels)           # type: ignore[arg-type]  # callers pass dicts; the point is it never raises
    assert m is None or (isinstance(m, MoscaInputs) and _valid(m))


@given(st.dictionaries(st.sampled_from(_KEYS), _num_text))
def test_mosca_inputs_are_present_only_for_a_valid_data_lifetime(labels):
    m = mosca_from_labels(labels)
    x = _label_years(labels, "data_lifetime")
    assert (m is None) == (x is None)
    if m is not None:
        assert m.data_lifetime_years == x
        assert m.migration_years == (_label_years(labels, "migration_years") or 5.0)
        assert m.threat_years == (_label_years(labels, "threat_years") or 10.0)


@given(_any_value, st.sampled_from(_KEYS))
def test_label_years_is_total(value, key):
    y = _label_years({key: value}, key)         # type: ignore[arg-type]
    assert y is None or (math.isfinite(y) and 0 < y <= 200)


@given(st.dictionaries(st.sampled_from(_KEYS), _num_text), st.sampled_from(["en", "ms"]))
def test_labels_that_pass_the_gate_render_a_mosca_section(labels, lang):
    assume(all(len(v) <= MAX_LABEL_VALUE for v in labels.values()))
    check_labels(labels)
    ctx = _mosca_context([], lang, mosca_from_labels(labels), "labels")
    assert ctx["verdict"] in ("ok", "at-risk")
    assert math.isfinite(ctx["gap_years"]) and ctx["summary"]

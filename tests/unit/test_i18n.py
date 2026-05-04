"""Tests for pqcscan.ui.i18n — translation table + cookie-based locale."""
from types import SimpleNamespace

from pqcscan.ui.i18n import (
    DEFAULT_LOCALE,
    LOCALE_COOKIE,
    LOCALES,
    SUPPORTED_LOCALES,
    get_locale,
    t,
)


def _fake_request(cookie_value: str | None) -> SimpleNamespace:
    cookies = {LOCALE_COOKIE: cookie_value} if cookie_value else {}
    return SimpleNamespace(cookies=cookies)


def test_default_locale_is_en():
    assert DEFAULT_LOCALE == "en"
    assert "en" in SUPPORTED_LOCALES and "ms" in SUPPORTED_LOCALES


def test_translation_keys_match_across_locales():
    """Every English key must have a Bahasa translation, and vice versa.
    Catches drift when adding a new string in one locale only."""
    en_keys = set(LOCALES["en"].keys())
    ms_keys = set(LOCALES["ms"].keys())
    assert en_keys == ms_keys, (
        f"missing in ms: {en_keys - ms_keys}; "
        f"missing in en: {ms_keys - en_keys}"
    )


def test_t_returns_translated_string():
    assert t("nav.dashboard", "en") == "Dashboard"
    assert t("nav.dashboard", "ms") == "Papan Pemuka"


def test_t_falls_back_to_en_when_locale_missing():
    assert t("nav.dashboard", "fr") == "Dashboard"


def test_t_returns_key_for_unknown_string():
    assert t("does.not.exist", "en") == "does.not.exist"


def test_get_locale_default_when_no_cookie():
    assert get_locale(_fake_request(None)) == "en"


def test_get_locale_reads_cookie():
    assert get_locale(_fake_request("ms")) == "ms"


def test_get_locale_rejects_unsupported_value():
    """Untrusted cookie input must not produce arbitrary locale lookups."""
    assert get_locale(_fake_request("../../etc/passwd")) == "en"
    assert get_locale(_fake_request("xx")) == "en"

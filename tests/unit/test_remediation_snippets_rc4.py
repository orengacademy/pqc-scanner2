from pqcscan.core.remediation_snippets import snippet_for


def test_rc4_has_a_migration_snippet():
    s = snippet_for("RC4", None)
    assert s is not None
    assert "AES-256" in s["after"]


def test_arcfour_alias_maps_to_rc4_snippet():
    s = snippet_for("ARCFOUR-128", "python")
    assert s is not None
    assert "AES" in s["after"]

"""liboqs-python logs to stdout at import; the helper must keep stdout clean
so `pqcscan scan --json` stays parseable on hosts with the [active] extras."""
import importlib
import logging
import sys
import textwrap


def test_oqs_import_never_writes_stdout(monkeypatch, capsys, tmp_path):
    # A stand-in for oqs/oqs.py's import-time behaviour: a StreamHandler bound
    # to *the* sys.stdout plus an INFO line, executed when `import oqs` runs.
    (tmp_path / "oqs.py").write_text(textwrap.dedent("""
        import logging
        from sys import stdout
        logger = logging.getLogger("oqs.oqs")
        logger.setLevel(logging.INFO)
        logger.addHandler(logging.StreamHandler(stdout))
        logger.info("liboqs-python faulthandler is disabled")
        def get_enabled_kem_mechanisms():
            return ["ML-KEM-768"]
    """))
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "oqs", raising=False)
    lg = logging.getLogger("oqs.oqs")
    lg.handlers.clear()

    from pqcscan.probes import _oqs_helper
    importlib.reload(_oqs_helper)
    try:
        assert _oqs_helper.oqs_available()
        assert _oqs_helper.supported_kems() == ["ML-KEM-768"]
        lg.info("later chatter must not reach stdout either")
        out, err = capsys.readouterr()
        assert "faulthandler" not in out and "chatter" not in out
        assert "faulthandler" in err            # redirected, not swallowed
    finally:
        lg.handlers.clear()
        monkeypatch.delitem(sys.modules, "oqs", raising=False)
        importlib.reload(_oqs_helper)

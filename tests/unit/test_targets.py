from pathlib import Path

from pqcscan.runner.targets import (
    normalise_server_target,
    parse_ot_target,
    parse_scan_inputs,
)


def test_normalise_bare_host():
    assert normalise_server_target("example.com") == "example.com"


def test_normalise_host_port():
    assert normalise_server_target("example.com:8443") == "example.com:8443"


def test_normalise_strips_scheme_and_path():
    assert normalise_server_target("https://example.com/foo?bar=1") == "example.com"


def test_normalise_empty_is_none():
    assert normalise_server_target("   ") is None


def test_parse_ot_host_port_proto():
    t = parse_ot_target("plc.local:502:modbus")
    assert t is not None
    assert (t.host, t.port, t.proto_hint) == ("plc.local", 502, "modbus")


def test_parse_ot_host_proto_default_port():
    t = parse_ot_target("plc.local:modbus")
    assert t is not None
    assert (t.host, t.port, t.proto_hint) == ("plc.local", 502, "modbus")


def test_parse_ot_no_port_no_proto_is_none():
    assert parse_ot_target("plc.local") is None


def test_parse_scan_inputs_all():
    paths, server, ots = parse_scan_inputs(
        target="example.com:443",
        paths=["/etc/ssl", "  ", "/opt"],
        ot=["a:502:modbus", "b:4840:opcua"],
    )
    assert paths == [Path("/etc/ssl"), Path("/opt")]
    assert server == "example.com:443"
    assert len(ots) == 2
    assert ots[1].proto_hint == "opcua"


def test_parse_scan_inputs_empty():
    paths, server, ots = parse_scan_inputs()
    assert paths == [] and server is None and ots == []

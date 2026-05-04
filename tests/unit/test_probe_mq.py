"""Tests for Plan G batch 2 — MQ broker probes (Kafka, RabbitMQ, NATS, MQTT)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.mq_kafka_tls import MqKafkaTls
from pqcscan.probes.mq_mqtt_broker import MqMqttBroker
from pqcscan.probes.mq_nats_tls import MqNatsTls
from pqcscan.probes.mq_rabbitmq_tls import MqRabbitmqTls


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (MqKafkaTls,    "mq.kafka.tls"),
        (MqRabbitmqTls, "mq.rabbitmq.tls"),
        (MqNatsTls,     "mq.nats.tls"),
        (MqMqttBroker,  "mq.mqtt.broker"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.STORAGE
    assert any("mq" in tag for tag in p.framework_tags)


@pytest.mark.asyncio
async def test_kafka_flags_tls10_and_plaintext_broker(tmp_path: Path):
    cfg = tmp_path / "server.properties"
    cfg.write_text(
        "ssl.enabled.protocols=TLSv1,TLSv1.2\n"
        "security.inter.broker.protocol=PLAINTEXT\n"
    )
    found: list = []
    p = MqKafkaTls(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "TLSv1"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)
    assert not any(f.algorithm == "TLSv1.2" for f in found)
    assert any(f.algorithm == "Kafka-PLAINTEXT-broker" for f in found)


@pytest.mark.asyncio
async def test_rabbitmq_flags_tls11(tmp_path: Path):
    cfg = tmp_path / "rabbitmq.conf"
    cfg.write_text(
        "listeners.ssl.1 = 5671\n"
        "ssl_options.versions.1 = tlsv1.1\n"
        "ssl_options.versions.2 = tlsv1.2\n"
    )
    found: list = []
    p = MqRabbitmqTls(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "tlsv1.1"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)
    assert any(f.algorithm == "RabbitMQ-TLS-listener" for f in found)
    assert not any(f.algorithm == "tlsv1.2" for f in found)


@pytest.mark.asyncio
async def test_nats_flags_weak_cipher(tmp_path: Path):
    cfg = tmp_path / "nats-server.conf"
    cfg.write_text(
        'tls {\n'
        '  cert_file: "/etc/nats/server.crt"\n'
        '  cipher_suites: ["TLS_RSA_WITH_RC4_128_SHA",'
        ' "TLS_AES_256_GCM_SHA384"]\n'
        '}\n'
    )
    found: list = []
    p = MqNatsTls(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "NATS-TLS-block" for f in found)
    weak = [f for f in found if "RC4" in f.algorithm]
    assert weak and weak[0].classification in {
        Classification.SANGAT_TINGGI, Classification.TINGGI
    }


@pytest.mark.asyncio
async def test_mosquitto_flags_tls11_and_anonymous(tmp_path: Path):
    cfg = tmp_path / "mosquitto.conf"
    cfg.write_text(
        "listener 1883\n"
        "tls_version tlsv1.1\n"
        "allow_anonymous true\n"
    )
    found: list = []
    p = MqMqttBroker(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "tlsv1.1"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)
    assert any(f.algorithm == "MQTT-anonymous"
               and f.classification is Classification.TINGGI
               for f in found)


def test_registry_includes_mq_probes():
    from pqcscan.probes._registry import default_registry
    reg = default_registry()
    ids = set(reg.ids())
    expected = {
        "mq.kafka.tls", "mq.rabbitmq.tls", "mq.nats.tls", "mq.mqtt.broker",
    }
    assert expected <= ids

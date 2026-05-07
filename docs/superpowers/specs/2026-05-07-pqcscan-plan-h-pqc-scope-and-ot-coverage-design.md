# pqcscan — Plan H: PQC scope sharpening + OT/ICS T4 coverage

| | |
|---|---|
| **Date** | 2026-05-07 |
| **Author** | brainstorming session (Claude Opus 4.7) |
| **Project** | pqcscan v2 (`pqc-scanner2`) |
| **Predecessor spec** | `docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md` |
| **Predecessor plans** | A, B, C, D, E, F, G — all shipped (109 / 102 probes) |
| **Status** | Design approved, awaiting implementation plan |
| **Target tags** | v0.2.0 (H.1) → v0.3.0 (H.2) → v0.4.0 / v0.4.1 / v0.4.2 (H.3a / b / c) |

---

## 1. Overview

Plan H is the next phase after Plans A–G shipped pqcscan v2's 109-probe baseline. The current baseline scans broad cryptographic surface but suffers from two opposing problems:

1. **Scope drift.** Eleven probes do work that is not aligned with the project's stated purpose ("automate PQC check"). They detect generic CVEs, generic secrets, generic system-hardening findings, and generic Python lint warnings — none of which reveal quantum-vulnerable cryptographic algorithms.
2. **Coverage gaps for NCII operators.** NACSA Arahan KE No. 9 applies to all NCII (national critical information infrastructure) entities. NCII covers power grid, telco mobile core, healthcare, transport, and manufacturing — sectors where OT/ICS protocols dominate and where pqcscan currently has zero coverage. UDP-bearing protocols are also unscored because pqcscan only port-scans TCP.

Plan H sharpens scope and adds coverage in three sub-plans:

| Sub-plan | Theme | Effect on probe count | Target tag |
|---|---|---:|---|
| H.1 | YAGNI trim — drop 11 probes that drift from PQC focus | 109 → 98 | v0.2.0 |
| H.2 | UDP port scan + DTLS handshake foundation | 98 → 99 | v0.3.0 |
| H.3a | OT/ICS family: TCP binary parsers (Modbus / S7 / DNP3 / IEC-104 / IEC-61850-MMS / EtherNet/IP / Modbus-Secure) | 99 → 106 | v0.4.0 |
| H.3b | OT/ICS family: TLS-wrapped + OPC UA + CIP Security + BACnet/SC | 106 → 110 | v0.4.1 |
| H.3c | OT/ICS family: telco (GTP) + health (DICOM, HL7-MLLP) + IoT (CoAP-DTLS) | 110 → 114 | v0.4.2 |

Plan H is additive at the runner / web UI / store / renderer layers. No schema migrations. No new top-level subsystems.

---

## 2. Architecture & integration

```
ProbeRunner (unchanged)
   ├─ Registry.default_registry()  ◄─ H.1 trims 11; H.2 adds 1; H.3 adds 15
   │
   ├─ ProbeFamily enum  ◄─ H.3 adds OT = "ot"
   │
   ├─ ScanContext.available_capabilities  ◄─ H.2 honors NET_RAW for raw UDP
   ├─ ScanContext.ot_targets (new)        ◄─ H.3 adds list[OTTarget]
   │
   ├─ probes/_dtls_probe.py     ◄─ H.2 new helper (mirrors _tls_probe.py)
   ├─ probes/_binary_proto.py   ◄─ H.3 new helper (length-prefix TCP framing)
   ├─ probes/_udp_payloads.py   ◄─ H.2 new (targeted-mode payload registry)
   │
   ├─ compliance/frameworks/nacsa-arahan-ke-9.yaml  ◄─ H.3 adds OT clauses
   ├─ compliance/frameworks/bukukerja.yaml          ◄─ H.3 adds OT clauses
   │
   └─ ui/templates/probes.html  ◄─ adds OT family card
```

### Probe-ID convention

- UDP scan: `net.ports.udp`
- OT family: `ot.<protocol>.<aspect>`
  e.g. `ot.modbus.tcp`, `ot.s7comm.handshake`, `ot.opc_ua.endpoint_security`,
  `ot.iec_104.startdt`, `ot.iec_61850.mms`, `ot.bacnet.bvlc`,
  `ot.cip_security.tls`, `ot.dicom.tls`, `ot.hl7.tls`,
  `ot.gtp.cu`, `ot.coap.dtls`, `ot.bacnet_sc.tls`,
  `ot.modbus_secure.tls`, `ot.dnp3.tcp`, `ot.ethernet_ip.list_id`

### Capability gates

- **H.2 raw UDP** → `Capability.NET_RAW`. Fallback: targeted UDP probe-list (per-port protocol payload, no raw socket needed).
- **H.3 OT probes** → no special capability. Pure outbound TCP / TLS / UDP / DTLS. Probes self-skip with INFO finding when target socket unreachable.

### ScanContext extension

`src/pqcscan/probes/_base.py`:

```python
@dataclass(slots=True)
class OTTarget:
    host: str
    port: int
    proto_hint: str | None = None   # "modbus" | "s7" | "opcua" | None

@dataclass(slots=True)
class ScanContext:
    scan_id: int
    mode: str
    available_capabilities: set[Capability]
    scan_paths: list[Path] = field(default_factory=list)
    server_target: str | None = None
    ot_targets: list[OTTarget] = field(default_factory=list)   # ← new in H.3
```

CLI flag `--ot-target host:port[:proto]` (repeatable). Empty list defaults each OT probe to scan host with the protocol's well-known port.

### Web UI

`/probes` gains an OT family card showing the 15 new probes. `/settings` gains an OT-target editor (saves to a settings JSON, propagated into `ScanContext.ot_targets`). No new pages.

### Compliance YAMLs

NACSA and BUKUKERJA YAMLs gain rules that match `probe_family: ot` and specific OPC UA legacy security policies. No other framework YAMLs change in Plan H.

---

## 3. H.1 — YAGNI trim

### Probes to delete (11)

| Probe id | File | Reason |
|---|---|---|
| `cve.grype` | `probes/cve_grype.py` | All-CVE scope, not crypto-specific |
| `cve.trivy_fs` | `probes/cve_trivy_fs.py` | Same |
| `cve.pip_audit` | `probes/cve_pip_audit.py` | Same |
| `cve.npm_audit` | `probes/cve_npm_audit.py` | Same |
| `cve.cargo_audit` | `probes/cve_cargo_audit.py` | Same |
| `cve.govulncheck` | `probes/cve_govulncheck.py` | Same |
| `cve.osv_offline` | `probes/cve_osv_offline.py` | Same — also drops 10-ecosystem matcher |
| `secrets.gitleaks` | `probes/secrets_gitleaks.py` | Secrets ≠ crypto algorithm |
| `app.dotenv_secrets` | `probes/app_dotenv_secrets.py` | Same |
| `host.lynis` | `probes/host_lynis.py` | Broad system-hardening audit, mostly non-crypto |
| `code.bandit` | `probes/code_bandit.py` | Generic Python security lint, overlaps semgrep PQC ruleset |

### Files deleted

```
src/pqcscan/probes/cve_grype.py
src/pqcscan/probes/cve_trivy_fs.py
src/pqcscan/probes/cve_pip_audit.py
src/pqcscan/probes/cve_npm_audit.py
src/pqcscan/probes/cve_cargo_audit.py
src/pqcscan/probes/cve_govulncheck.py
src/pqcscan/probes/cve_osv_offline.py
src/pqcscan/probes/secrets_gitleaks.py
src/pqcscan/probes/app_dotenv_secrets.py
src/pqcscan/probes/host_lynis.py
src/pqcscan/probes/code_bandit.py

tests/probes/test_cve_*.py             (× ~7)
tests/probes/test_secrets_gitleaks.py
tests/probes/test_app_dotenv_secrets.py
tests/probes/test_host_lynis.py
tests/probes/test_code_bandit.py
```

### Offline-pack tools dropped

`grype`, `trivy`, `pip-audit`, `npm`, `cargo-audit`, `govulncheck`, `lynis`, `bandit`, `gitleaks` removed from `scripts/fetch-offline-tools.sh`. Kept: `syft`, `semgrep`, `testssl`, `sslyze`, `nmap`. Bundled-binary build (PyInstaller pack) shrinks 40–60%.

### Registry update

`src/pqcscan/probes/_registry.py::default_registry()` removes 11 instantiations.

### Status / README delta

`docs/STATUS.md` and `README.md` update probe counts:

```
- 109 / 102 probes  →  98 / 102 probes (target re-baselined; deferral §13.1 closed)
- Plan F batch 4 (Grype-DB bundle) — REMOVED, no longer applicable (grype dropped)
- B17 OSV matcher — REMOVED (osv_offline dropped)
- Plan B (batches 1–15) probe count drops by 9
```

### Compliance YAML impact

No rule in `compliance/frameworks/*.yaml` references `cve.*` or `secrets.*` probe ids directly. Rules match on `algorithm` / `classification` / `probe_family`. No YAML edits required for H.1.

### Migration / breaking-change

Existing users running `pqcscan scan` for CVE output **lose CVE findings**. Migration note in status doc: "for CVE workflow, run `grype` standalone — pqcscan now focuses on PQC algorithm coverage." Tag `v0.2.0` (project < 1.0; minor bump signals breaking change).

---

## 4. H.2 — UDP port scan + DTLS foundation

### New probe: `net.ports.udp`

File: `src/pqcscan/probes/net_ports_udp.py`

**Purpose.** Discover UDP services for OT / legacy / DTLS-bearing protocols. PQC1 had this; PQC2 dropped it during the rewrite. Restore.

**Two modes:**

| Mode | When | Behavior |
|---|---|---|
| Raw | `Capability.NET_RAW` available | Send empty UDP datagram per port; ICMP port-unreachable = closed; no reply within 2 s = open\|filtered |
| Targeted | No NET_RAW | Send protocol-specific payload (NTP request, SNMP get, IKE init, DNS query, BACnet who-is, DNP3 link-status, etc.) per port from probe-list |

**Default targeted port-list:**

| Port | Service | Probe payload |
|---|---|---|
| 53 | DNS | A-query for `.` |
| 123 | NTP | NTPv4 client packet |
| 161 | SNMP | v2c GetRequest sysDescr |
| 500 | IKEv1/2 | ISAKMP init |
| 514 | syslog | empty |
| 1812 | RADIUS auth | Access-Request stub |
| 1813 | RADIUS acct | empty |
| 4500 | IKE NAT-T | ISAKMP non-ESP |
| 4789 | VXLAN | empty |
| 5060 | SIP | OPTIONS |
| 5353 | mDNS | A-query |
| 5683 | CoAP | GET /.well-known/core |
| 5684 | CoAPS / DTLS | DTLS ClientHello |
| 6343 | sFlow | empty |
| 47808 | BACnet | Who-Is BVLC |
| 20000 | DNP3 | Link Status |
| 2123 | GTP-C | GTPv2 echo req |
| 2152 | GTP-U | GTPv1 echo req |

**Output.** Finding per port — `port`, `state` (open\|closed\|filtered), `protocol_guess`, `evidence` (raw response bytes hex). Classification `INFO`. Severity `INFO` for closed, `LOW` for open.

**Class skeleton:**

```python
class NetPortsUDP(Probe):
    id = "net.ports.udp"
    family = ProbeFamily.NETWORK
    framework_tags = ("nacsa-9:port-discovery", "bukukerja:port-discovery")
    requires = frozenset()  # raw mode prefers NET_RAW; targeted mode needs no caps

    def __init__(
        self,
        host: str = "127.0.0.1",
        ports: list[int] | None = None,
        timeout_s: float = 2.0,
        mode: str = "auto",  # "raw" | "targeted" | "auto"
    ): ...

    async def applies(self, ctx: ScanContext) -> bool:
        return True  # mode adapts to caps

    async def run(self, ctx, emit):
        mode = self._resolve_mode(ctx)
        ports = self.ports or DEFAULT_UDP_PORTS
        for p in ports:
            state, evidence = await self._probe_port(p, mode)
            emit(Finding(...))
```

### New helper: `_dtls_probe.py`

File: `src/pqcscan/probes/_dtls_probe.py`

Mirrors `_tls_probe.py` API but uses DTLS over UDP. Extracts:

- DTLS version (1.0 / 1.2 / 1.3)
- Cipher suites offered / selected
- Cert chain (if server sends Certificate)
- KEX group
- Signature algorithm
- ALPN (rare in DTLS, optional)

Reused by H.3 `ot.coap.dtls`, optionally by `ot.bacnet_sc.tls` (DTLS variant), and any future SIP-DTLS / WebRTC-DTLS probe.

**Implementation note.** Python stdlib `ssl` module gained DTLS support in 3.12+. The project pins 3.11. Two options:

1. Add `pyOpenSSL` dependency and use its DTLS API.
2. Shell out to `openssl s_client -dtls1_2 -connect host:port`.

Pick **shell-out** — mirrors PQC1 pattern, no new pip dep, consistent with existing `host.openssl.ciphers` probe approach. `applies()` gates on `shutil.which("openssl")` and INFO-skips otherwise.

```python
async def run_dtls_probe(
    *,
    host: str,
    port: int,
    version: str = "1.2",
    probe_id: str,
    emit: Emitter,
) -> None:
    args = [
        "openssl", "s_client",
        f"-dtls{version.replace('.', '_')}",
        "-connect", f"{host}:{port}",
        "-msg", "-state",
    ]
    proc = await asyncio.create_subprocess_exec(*args, ...)
    out, _ = await asyncio.wait_for(proc.communicate(input=b"\n"), timeout=10.0)
    parsed = _parse_dtls_handshake(out.decode())
    for alg in parsed.algorithms:
        emit(Finding(probe_id=probe_id, algorithm=alg, ...))
```

### Files added

```
src/pqcscan/probes/net_ports_udp.py
src/pqcscan/probes/_dtls_probe.py
src/pqcscan/probes/_udp_payloads.py
tests/probes/test_net_ports_udp.py
tests/probes/test_dtls_probe.py
```

### Registry update

`default_registry()` += `NetPortsUDP()`. Probe count 98 → 99.

### Risks

- DTLS shell-out fragile on minimal containers (no `openssl` binary). Mitigation: `applies()` gates, INFO-skip with explicit message.
- Raw UDP scan needs root / `NET_RAW`. Mitigation: targeted mode is the documented default; raw mode is opt-in.
- UDP scan slow on filtered ports (timeout-driven). Mitigation: parallel asyncio probe per port; cap default port-list at 18.

### Tag

`v0.3.0` — additive minor bump.

---

## 5. H.3 — OT/ICS T4 family

### New family

`src/pqcscan/core/types.py`:

```python
class ProbeFamily(str, Enum):
    ...
    OT = "ot"
```

### New helper

`src/pqcscan/probes/_binary_proto.py` — generic length-prefix TCP framing helper. Read N bytes, parse fixed-length header, decode TLV / sub-PDU. Shared by Modbus / S7 / IEC-104 / DNP3 / IEC-61850-MMS / CIP.

```python
async def read_frame(
    reader: asyncio.StreamReader,
    *,
    header_len: int,
    len_offset: int,
    len_size: int,
    max_size: int = 65535,
) -> bytes:
    """Read one length-prefixed frame from an asyncio stream."""
```

### H.3a — TCP binary parsers (7 probes)

For each: open TCP, send protocol probe, parse response, extract security-capability indicator (auth mode / cipher / cert presence / "no security"), classify, emit.

| Probe id | Port | What we detect for PQC |
|---|---|---|
| `ot.modbus.tcp` | 502 | Read Device Identification (FC=43/14). Plain Modbus = `classification=info, severity=high` (no crypto at all). Flag absence of Modbus-Secure as risk. |
| `ot.modbus_secure.tls` | 802 | If 802 open: TLS handshake → cert chain + cipher; classify per `_tls_probe`. |
| `ot.s7comm` | 102 | TPKT + COTP + S7. Read S7 ID. Plain S7 (v3/v4) = no crypto → flag. S7-Plus has TLS — wrap with `_tls_probe` if detected. |
| `ot.dnp3.tcp` | 20000 | DNP3 Link Status (CTRL=09). DNP3-SAv5 (Secure Authentication) markers in challenge frame → classify HMAC-SHA1 / SHA-256 / AES-GMAC. SAv2 deprecated. Flag if SA absent. |
| `ot.iec_104.startdt` | 2404 | STARTDT_act → STARTDT_con. Plain 60870-5-104 = no crypto. IEC 62351-3 wraps with TLS — probe TLS variant; flag when absent. |
| `ot.iec_61850.mms` | 102 | MMS Initiate-Request. Plain ISO/IEC 9506 = no crypto. IEC 62351-4 = TLS-wrapped MMS → probe TLS variant. R-GOOSE / R-SV multicast not in scope (out-of-band PCAP needed). |
| `ot.ethernet_ip.list_id` | 44818 | List Identity (cmd 0x63). EtherNet/IP plain = no crypto. CIP Security adds TLS — flag absence. |

### H.3b — TLS-wrapped / mixed (4 probes)

| Probe id | Port | What we detect |
|---|---|---|
| `ot.opc_ua.endpoint_security` | 4840 / 4843 | OPC UA `GetEndpoints`. Each endpoint advertises `SecurityPolicyUri`: `None`, `Basic128Rsa15`, `Basic256`, `Basic256Sha256`, `Aes128_Sha256_RsaOaep`, `Aes256_Sha256_RsaPss`. Classify each: Basic128Rsa15 + Basic256 = Sangat-tinggi (deprecated SHA-1 / RSA-1.5). Aes256_Sha256_RsaPss = Sederhana (RSA-PSS not PQC). Detect `EccNistP256` / `EccNistP384` / Aes128_Sha256_nistP256 (PQC-curve adjacent but not PQC). Detect OPC UA-over-QUIC variant via ALPN. |
| `ot.cip_security.tls` | 2222 | TLS handshake on EtherNet/IP CIP-Security port (Volume 8). Cipher + cert chain via `_tls_probe`. |
| `ot.bacnet.bvlc` | 47808 / UDP | BVLC Who-Is. Plain BACnet = no crypto. Flag. (BACnet/SC handled by next probe.) |
| `ot.bacnet_sc.tls` | 47808 (BACnet/SC hub on TLS, often 443) | TLS to BACnet/SC hub. Cipher + cert + WebSocket subprotocol. |

### H.3c — Telco / health / IoT (4 probes)

| Probe id | Port | What we detect |
|---|---|---|
| `ot.gtp.cu` | 2123 / 2152 UDP | GTPv2-C echo (2123) / GTPv1-U echo (2152). Plain GTP = no crypto. IPsec usually wraps S1-U / N3 — flag if no IPsec marker; rely on `net.ike.v1v2` for IPsec-tunnel detection. |
| `ot.dicom.tls` | 2762 (or 11112 with TLS upgrade) | DICOM A-ASSOCIATE-RQ over TLS → `_tls_probe`. Plain DICOM 11112 = no crypto → flag. |
| `ot.hl7.tls` | 2575 (MLLPS) | MLLP over TLS handshake. Cipher + cert via `_tls_probe`. Plain MLLP 2575 = no crypto → flag. |
| `ot.coap.dtls` | 5684 UDP | DTLS handshake via `_dtls_probe` helper. Cipher + PSK detection (CoAP often PSK-only). Plain CoAP 5683 covered separately by `net.ports.udp` targeted mode. |

### Total: 15 probes

| Sub-batch | Probe count |
|---|---:|
| H.3a TCP binary parsers | 7 |
| H.3b TLS-wrapped / mixed | 4 |
| H.3c Telco / health / IoT | 4 |

### Files added

```
src/pqcscan/probes/_binary_proto.py
src/pqcscan/probes/ot_modbus_tcp.py
src/pqcscan/probes/ot_modbus_secure.py
src/pqcscan/probes/ot_s7comm.py
src/pqcscan/probes/ot_dnp3_tcp.py
src/pqcscan/probes/ot_iec_104.py
src/pqcscan/probes/ot_iec_61850_mms.py
src/pqcscan/probes/ot_ethernet_ip.py
src/pqcscan/probes/ot_opc_ua.py
src/pqcscan/probes/ot_cip_security.py
src/pqcscan/probes/ot_bacnet.py
src/pqcscan/probes/ot_bacnet_sc.py
src/pqcscan/probes/ot_gtp.py
src/pqcscan/probes/ot_dicom_tls.py
src/pqcscan/probes/ot_hl7_tls.py
src/pqcscan/probes/ot_coap_dtls.py
tests/probes/test_ot_*.py    # × 15
tests/fixtures/ot/*.bin      # canned protocol responses
tests/fixtures/ot/*.pcap     # for handshake replay tests
```

### Registry update

`default_registry()` += 15 OT probes. Count 99 → 114.

---

## 6. Compliance framework extension

### NACSA Arahan KE No. 9 YAML — added rules

`src/pqcscan/compliance/frameworks/nacsa-arahan-ke-9.yaml`:

```yaml
  # ───── OT/ICS clauses (Plan H.3) ─────
  - match: { probe_family: ot, classification: info }
    clause: NACSA-9:ot-no-crypto
    verdict: non-compliant
    deadline: 2027-06-30
    note: "Protokol OT tanpa kriptografi (Modbus/S7/DNP3/IEC-104/EtherNet-IP/BACnet plain). Wajib dilindungi (TLS-wrap atau IEC 62351 / CIP Security / BACnet-SC) menjelang Fasa 4 (Jun 2027)."

  - match: { probe_id_prefix: ot.opc_ua, algorithm: Basic128Rsa15 }
    clause: NACSA-9:opcua-deprecated
    verdict: non-compliant
    note: "OPC UA Basic128Rsa15 menggunakan SHA-1 + RSA-PKCS#1 v1.5 (terlarang). Wajib gantikan dengan Aes256_Sha256_RsaPss atau profil PQC (apabila tersedia)."

  - match: { probe_id_prefix: ot.opc_ua, algorithm: Basic256 }
    clause: NACSA-9:opcua-deprecated
    verdict: non-compliant
    note: "OPC UA Basic256 (SHA-1) terlarang. Gunakan Basic256Sha256 atau lebih baik."

  - match: { probe_id: ot.dnp3.tcp, algorithm: HMAC-SHA1 }
    clause: NACSA-9:dnp3-sa-deprecated
    verdict: non-compliant
    note: "DNP3-SA HMAC-SHA1 dilarang. Gunakan SHA-256 atau AES-GMAC dalam SAv5."
```

### BUKUKERJA YAML — added rules

`src/pqcscan/compliance/frameworks/bukukerja.yaml` adds parallel OT entries so the BUKUKERJA Excel workbook's Sheet `2_CBOM` includes OT findings, and Sheet `3_RiskRegister` produces a Bahasa Malaysia risk row per OT plain-protocol finding.

### No other YAMLs change

CNSA / BSI / ANSSI / ENISA / MAS / MyKripto / NIST IR 8547 / NIST SP 800-227 base rules continue to match on `algorithm` / `classification`. They will pick up OT findings automatically because OT probes emit standard `algorithm` / `classification` fields.

---

## 7. Testing strategy

### Coverage targets

| Batch | Test type | Target |
|---|---|---|
| H.1 | Regression | Drop 11 probe test files; existing 365+ tests stay green; new total ≈ 340 |
| H.2 | Unit + integration | UDP probe ≥ 85% line cov; DTLS helper integration via local `openssl s_server -dtls1_2` fixture |
| H.3 | Unit + fixture-replay | Each OT probe ≥ 80% line cov; protocol parsing fixture from canned bytes; one integration test per probe via mini async server |

### Fixtures

```
tests/fixtures/ot/
  modbus_read_device_id_response.bin
  s7comm_setup_communication.bin
  dnp3_link_status_sav5.bin
  iec104_startdt_con.bin
  iec61850_initiate_response.bin
  ethernet_ip_list_identity_response.bin
  opc_ua_get_endpoints_response.bin     # multiple SecurityPolicyUri entries
  bacnet_who_is_response.bin
  cip_security_handshake.pcap
  gtpv2c_echo_response.bin
  hl7_mllp_tls_handshake.pcap
  dicom_a_associate_rq_tls.pcap
  coap_dtls_clienthello.bin
```

### Mini async fixture servers

For probes needing a live socket: spin asyncio TCP/UDP server in test, replay canned response per request match. Pattern:

```python
@pytest.fixture
async def modbus_server():
    async def handler(reader, writer):
        await reader.read(12)
        writer.write(MODBUS_READ_DEVID_RESPONSE)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield "127.0.0.1", port
    server.close()
```

### DTLS test fixture

Subprocess `openssl s_server -dtls1_2 -cert test.pem -key test.key -port <random>`. Parse `_dtls_probe.py` output. Skip test (xfail-strict=false) if openssl missing; CI image must include openssl.

### Compliance engine tests

- Unit: NACSA OT clause matches `probe_family=ot, classification=info` → non-compliant + deadline 2027-06-30.
- Unit: `ot.opc_ua` finding with `algorithm=Basic128Rsa15` → matches `NACSA-9:opcua-deprecated`.
- Integration: full scan against fixture target → `/frameworks/nacsa-arahan-ke-9` view shows OT findings with correct verdicts.

### CI gate

Per batch: `pytest -q` must pass before tag. `ruff check` + `mypy` clean. Coverage report committed to `docs/v0.X.Y/coverage.txt`.

---

## 8. Migration & breaking-change notes

### H.1 — breaking

- `pqcscan scan` no longer emits CVE findings. Migration: run `grype` / `trivy` standalone for CVE workflow.
- `pqcscan scan` no longer emits gitleaks / dotenv-secrets findings. Migration: run `gitleaks` standalone.
- `pqcscan scan` no longer runs `lynis` / `bandit`. Migration: run those tools standalone.
- Offline-pack `fetch-offline-tools.sh` shrinks. Re-run to refresh local pack.

### H.2 — additive only

`net.ports.udp` enabled by default. Increases scan time by ~10 s on default port-list. To skip: `pqcscan scan --skip-probe net.ports.udp`.

### H.3 — additive only

15 OT probes enabled by default. Each probe self-skips with INFO finding when target socket unreachable, so default behaviour on a typical IT host is fast (15 quick connect-attempts that all return INFO). To target an actual OT segment: `pqcscan scan --ot-target 10.0.5.1:502 --ot-target 10.0.5.10:4840:opcua`.

---

## 9. Probe-count progression

| Stage | Probe count | Tag |
|---|---:|---|
| Pre-Plan-H baseline | 109 | v0.1.0 |
| After H.1 trim | 98 | v0.2.0 |
| After H.2 UDP+DTLS | 99 | v0.3.0 |
| After H.3a TCP binary | 106 | v0.4.0 |
| After H.3b TLS-wrapped | 110 | v0.4.1 |
| After H.3c telco/health/IoT | 114 | v0.4.2 |

---

## 10. Open issues / future work

The brainstorming session 2026-05-07 identified ten distinct gaps that block "fully automate PQC check": scope drift (YAGNI probes), UDP coverage, OT/ICS coverage, asset auto-discovery, phase state machine, submission packager, multi-tenant registry, continuous monitoring, signed audit trail, and PQC active validation. Plan H closes only the first three (scope drift + UDP + OT). The remaining seven are listed here so they are not forgotten and so a future Plan I can pick them up cleanly.

| Future plan | Theme |
|---|---|
| Plan I.1 | Asset auto-discovery + fleet rollup (multi-host scan orchestration) |
| Plan I.2 | Phase state machine + deadline scheduler (NACSA Fasa 1–5 tracking) |
| Plan I.3 | Submission packager — compose Lampiran A bundle, sign, deliver to PTPKM/NACSA |
| Plan I.4 | Multi-tenant NCII registry — per-entity isolation in store + UI |
| Plan I.5 | Continuous monitoring (Fasa 5 cron, recurring scan diffs, alerts) |
| Plan I.6 | Signed audit trail — CBOM signing (cosign / Ed25519), tamper-evident scan log |
| Plan I.7 | **PQC active validation via OQS** — see §10.1 below |
| Plan I.8 | Additional protocol coverage if needed (BGP TCP-MD5, OSPF MD5, RADIUS, TACACS+, NTPv4 MAC + NTS, SIP-TLS / SRTP / ZRTP, iSCSI CHAP, NFSv4 sec=krb5, WPA2/3, BLE, 5G NAS) |

### 10.1 — Plan I.7: PQC active validation via Open Quantum Safe

pqcscan v2 (post-Plan H) is **detection-only**. It reads cipher names, parses cert OIDs, classifies algorithms by string/structural pattern. It does not synthesize PQC primitives, does not actively negotiate hybrid KEX, and does not run NIST KATs. The Open Quantum Safe project (`liboqs`, `liboqs-python`, `oqs-provider` for OpenSSL 3.x) provides the missing primitives. Plan I.7 wires OQS in as an **opt-in** capability so pqcscan can move from passive observation to active probing without becoming an active prober by default (IDS / OT-network impact).

#### Capability gain matrix

| Capability | Without OQS (Plan H baseline) | With OQS (Plan I.7) |
|---|---|---|
| Detect ML-KEM / ML-DSA / SLH-DSA names in TLS / cert | ✅ string match | ✅ + cryptographic verification of advertised primitive |
| Detect ML-DSA cert | ✅ OID parse via `cryptography` (post-OpenSSL 3.5 OIDs) | ✅ + signature verification using liboqs |
| Active hybrid-KEX probe of remote server | ❌ passive only | ✅ send hybrid ClientHello (`X25519MLKEM768`, `SecP256r1MLKEM768`) via `oqs-provider` OpenSSL build, capture `ServerHello` group selection |
| HNDL "Tinggi" vendor-readiness check | ❌ relies on docs | ✅ live "is server PQC-ready in practice?" |
| Generate ephemeral PQC test certs (ML-DSA-44/65/87) for fixtures | ❌ uses static stubs | ✅ generate on the fly during tests |
| Run NIST FIPS 203/204/205 Known-Answer Tests against local crypto stack | ❌ | ✅ KAT runner per primitive |

#### Proposed Plan I.7 sub-batches

| Sub-plan | Scope | Probe count delta |
|---|---|---:|
| I.7.a | OQS optional dependency wiring — add `pqcscan[active]` extras (`liboqs-python>=0.10`); add `probes/_oqs_helper.py` wrapping ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA-SHA2-128s/192s/256s, Falcon-512/1024 | 0 |
| I.7.b | Active hybrid-KEX TLS probe — extend `_tls_probe.py` to accept `oqs_groups=[...]`; new probe `net.tls.pqc_handshake` builds hybrid ClientHello against target | +1 |
| I.7.c | X.509 PQC cert profile probe — `fs.cert.pqc_x509` (file-based ML-DSA cert detect via OID + signature verify); `net.tls.pqc_cert_chain` (active server cert chain ML-DSA verify) | +2 |
| I.7.d | Local crypto stack PQC support inventory — `host.openssl.oqs_provider` (check `OQS-OpenSSL` provider loaded), `host.bouncycastle.pqc` (Java BC-PQC version detect), `host.pqcrypto_rs` (Rust pqcrypto crate detect), `host.libcrypto_pqc_features` (libcrypto / libssl FIPS-203/204/205 symbol table inspection), `app.crypto_lib_pqc_support` (scan deps for `liboqs`, `bouncycastle-pqc`, `pqcrypto-rs`, `pqcrypto`, `pqclean`, `kyber-py`, `dilithium-py`) | +5 |
| I.7.e | NIST FIPS 203/204/205 KAT runner — `pqc.kat.fips_203_ml_kem`, `pqc.kat.fips_204_ml_dsa`, `pqc.kat.fips_205_slh_dsa` (run vector files from NIST CAVP / project_pqc test vectors against liboqs primitives) | +3 |

**Total Plan I.7 probe delta: +11.** Family: existing `NETWORK` + `FILESYSTEM` + `HOST` + `APP` + new `ProbeFamily.PQC_KAT` (or reuse existing `PQC_META`).

#### Default behaviour

- `pip install pqcscan` — default install, no `liboqs-python`, no OQS probes registered.
- `pip install pqcscan[active]` — registers all 11 OQS-dependent probes. `applies()` on each gates on `import oqs` succeeding.
- CLI `--active` flag required to actually run active hybrid-KEX probes (avoid surprise IDS pings on production OT networks). Without `--active`, OQS-dependent probes self-skip with INFO finding "active probe gated; pass --active".

#### Risk

- `liboqs-python` requires native `liboqs` shared library on the host. Mitigation: document install via `apt install liboqs-dev` / Homebrew / `vcpkg` per platform; document Docker image variant `pqcscan:active` with liboqs pre-baked.
- `oqs-provider` requires OpenSSL 3.0+ with provider API. Mitigation: `host.openssl.oqs_provider` probe self-detects; gate active hybrid-KEX probe on its availability.
- Active probing on OT networks may trigger IDS alerts, ICS controller faults, SCADA HMI alarms. Mitigation: `--active` flag required; default off; documentation warns NCII operators to test in IT segment first; CLI prompt "active probe will send unsolicited TLS hybrid-KEX ClientHello to <target>; continue? [y/N]" unless `--yes` given.
- liboqs API may change between releases. Mitigation: pin `liboqs-python>=0.10,<0.12`; per-release smoke test in CI matrix.

---

## 11. Implementation plan (next step)

This spec is the brainstorming artifact. The next step is the implementation plan, produced by the `superpowers:writing-plans` skill, which will break each sub-plan (H.1, H.2, H.3a, H.3b, H.3c) into ordered tasks with TDD test gates per probe.

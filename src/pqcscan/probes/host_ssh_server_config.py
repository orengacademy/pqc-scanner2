from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_PATHS = [Path("/etc/ssh/sshd_config")]

_SSH_ALG_ALIASES: dict[str, str] = {
    "diffie-hellman-group1-sha1": "DH-1024",
    "diffie-hellman-group14-sha1": "DH-2048",
    "diffie-hellman-group14-sha256": "DH-2048",
    "diffie-hellman-group16-sha512": "DH-4096",
    "diffie-hellman-group18-sha512": "DH-8192",
    "ssh-rsa": "RSA-2048",
    "ssh-dss": "DSA",
    "rsa-sha2-256": "RSA-SHA256",
    "rsa-sha2-512": "RSA-SHA512",
    "ecdsa-sha2-nistp256": "ECDSA-SHA256",
    "ecdsa-sha2-nistp384": "ECDSA-SHA384",
    "ecdsa-sha2-nistp521": "ECDSA-SHA512",
    "ssh-ed25519": "Ed25519",
    "hmac-md5": "MD5",
    "hmac-sha1": "SHA-1",
    "hmac-sha2-256": "SHA-256",
    "hmac-sha2-512": "SHA-512",
}

_KEYWORDS = ("Ciphers", "KexAlgorithms", "MACs", "HostKeyAlgorithms",
             "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes")


class HostSshServerConfig(Probe):
    id = "host.ssh.server_config"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:ssh", "bukukerja:ssh", "mykripto:ssh")

    def __init__(self, config_paths: list[Path] | None = None):
        self.config_paths = (
            config_paths if config_paths is not None else _DEFAULT_PATHS
        )

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.config_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in self.config_paths:
            if not path.exists():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        for line_no, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            for kw in _KEYWORDS:
                m = re.match(rf"^{kw}\s+(.+)$", line, re.IGNORECASE)
                if not m:
                    continue
                values = m.group(1).strip()
                if values[:1] in {"+", "-", "^"}:
                    values = values[1:]
                for token in values.split(","):
                    token = token.strip()
                    if not token:
                        continue
                    canonical = _SSH_ALG_ALIASES.get(token, normalise(token))
                    cls = classify(canonical)
                    sev = _sev(cls)
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=canonical,
                        classification=cls,
                        severity=sev,
                        title=f"sshd_config {kw} contains {token}",
                        evidence={
                            "path": str(path),
                            "line": line_no,
                            "keyword": kw,
                            "token": token,
                        },
                        remediation={
                            "snippet": f"# Review {kw} list; remove tokens flagged Tinggi/Sangat Tinggi",
                        },
                    ))


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]

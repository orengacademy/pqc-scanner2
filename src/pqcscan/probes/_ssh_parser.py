"""Shared sshd_config / ssh_config parser used by host.ssh.* and fs.conf.sshd probes."""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, Severity


SSH_ALG_ALIASES: dict[str, str] = {
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

SSH_KEYWORDS = (
    "Ciphers", "KexAlgorithms", "MACs", "HostKeyAlgorithms",
    "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes",
)


def parse_ssh_config(text: str, path: Path, probe_id: str) -> Iterator[Finding]:
    """Yield Findings for each algorithm token in Ciphers/KexAlgorithms/MACs/etc."""
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for kw in SSH_KEYWORDS:
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
                canonical = SSH_ALG_ALIASES.get(token, normalise(token))
                cls = classify(canonical)
                yield Finding(
                    probe_id=probe_id,
                    algorithm=canonical,
                    classification=cls,
                    severity=_sev(cls),
                    title=f"{path.name} {kw} contains {token}",
                    evidence={
                        "path": str(path),
                        "line": line_no,
                        "keyword": kw,
                        "token": token,
                    },
                    remediation={
                        "snippet": f"# Review {kw} list; remove tokens flagged Tinggi/Sangat Tinggi",
                    },
                )


def parse_paths(paths: Iterable[Path], probe_id: str) -> Iterator[Finding]:
    """Iterate over file paths and yield findings."""
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        yield from parse_ssh_config(text, path, probe_id)


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

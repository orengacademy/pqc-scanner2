"""fs.ssh.host_keys — inventory on-disk SSH public keys.

Parses `*.pub` files and `authorized_keys` under the SSH directories, decoding
the key-type field (and, for RSA, the modulus bit length from the base64 blob).
Every SSH host/user key is classical and therefore quantum-vulnerable; this
surfaces the actual key inventory (RSA-1024 vs Ed25519 vs ECDSA, CA-signed
certs) that config parsing alone cannot see.
"""
from __future__ import annotations

import base64
import struct
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_ROOTS = [Path("/etc/ssh")]
_KEY_FILENAMES = ("authorized_keys", "authorized_keys2")
_CERT_SUFFIX = "-cert-v01@openssh.com"

# Base SSH key type -> (canonical algorithm, classification). RSA is sized at
# runtime; everything here is classical (quantum-vulnerable) so the weak ones
# (DSA, short RSA) are HIGH and the modern ones MED.
_ECDSA_CURVE = {
    "ecdsa-sha2-nistp256": "ECDSA-P256",
    "ecdsa-sha2-nistp384": "ECDSA-P384",
    "ecdsa-sha2-nistp521": "ECDSA-P521",
    "sk-ecdsa-sha2-nistp256@openssh.com": "FIDO-ECDSA-P256",
}


def _severity(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]


def _is_key_type(token: str) -> bool:
    base = token[: -len(_CERT_SUFFIX)] if token.endswith(_CERT_SUFFIX) else token
    return base.startswith(("ssh-", "ecdsa-", "sk-"))


def _rsa_bits(blob_b64: str) -> int | None:
    try:
        raw = base64.b64decode(blob_b64, validate=True)
    except Exception:
        # Any malformed-base64 / decode failure -> unknown bit length.
        return None
    fields: list[bytes] = []
    off = 0
    while off + 4 <= len(raw) and len(fields) < 3:
        (ln,) = struct.unpack(">I", raw[off:off + 4])
        off += 4
        if ln > len(raw) - off:
            break
        fields.append(raw[off:off + ln])
        off += ln
    if len(fields) >= 3 and fields[0] == b"ssh-rsa":
        return int.from_bytes(fields[2], "big").bit_length()
    return None


def _classify(key_type: str, blob_b64: str | None) -> tuple[str, Classification]:
    is_cert = key_type.endswith(_CERT_SUFFIX)
    base = key_type[: -len(_CERT_SUFFIX)] if is_cert else key_type

    if base == "ssh-dss":
        return "DSA", Classification.TINGGI
    if base == "ssh-rsa":
        bits = _rsa_bits(blob_b64) if blob_b64 else None
        if bits is None:
            return "RSA", Classification.SEDERHANA
        cls = Classification.TINGGI if bits < 2048 else Classification.SEDERHANA
        return f"RSA-{bits}", cls
    if base in _ECDSA_CURVE:
        return _ECDSA_CURVE[base], Classification.SEDERHANA
    if base in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        return ("FIDO-Ed25519" if base.startswith("sk-") else "Ed25519",
                Classification.SEDERHANA)
    return base, Classification.INFO


class FsSshHostKeys(Probe):
    """Inventory on-disk SSH public keys (type + RSA bit length)."""

    id = "fs.ssh.host_keys"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:ssh", "bukukerja:ssh", "mykripto:ssh")

    def __init__(self, roots: list[Path] | None = None) -> None:
        self.roots = roots if roots is not None else _DEFAULT_ROOTS

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                if not (path.name.endswith(".pub") or path.name in _KEY_FILENAMES):
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        for line_no, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parsed = self._parse_line(line)
            if parsed is None:
                continue
            key_type, blob, comment = parsed
            algorithm, cls = _classify(key_type, blob)
            is_cert = key_type.endswith(_CERT_SUFFIX)
            label = f"{algorithm}{' (CA-signed cert)' if is_cert else ''}"
            emit(Finding(
                probe_id=self.id,
                algorithm=algorithm,
                classification=cls,
                severity=_severity(cls),
                title=f"SSH public key in {path.name}: {key_type} ({label})",
                evidence={
                    "path": str(path),
                    "line": line_no,
                    "key_type": key_type,
                    "comment": comment,
                    "is_certificate": is_cert,
                },
            ))

    @staticmethod
    def _parse_line(line: str) -> tuple[str, str | None, str] | None:
        # `<type> <base64> [comment]`, optionally with an authorized_keys
        # options prefix before <type>. Find the first key-type token.
        parts = line.split()
        for i, tok in enumerate(parts):
            if _is_key_type(tok):
                blob = parts[i + 1] if i + 1 < len(parts) else None
                comment = " ".join(parts[i + 2:]) if i + 2 < len(parts) else ""
                return tok, blob, comment
        return None

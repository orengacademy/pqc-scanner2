"""host.pam.hashing — system password-hash algorithm posture.

The crypt scheme configured for local accounts decides how well stolen shadow
hashes resist offline cracking: DES-crypt and MD5-crypt are broken, SHA-256 is
tolerable, SHA-512 / yescrypt / bcrypt are fine. Three sources are checked:
ENCRYPT_METHOD in /etc/login.defs, `md5` options on pam_unix.so lines under
/etc/pam.d, and the hash prefixes actually present in /etc/shadow (readable
only as root; a PermissionError simply skips that check). Evidence carries the
scheme only — never usernames or hash material.
"""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


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


# ENCRYPT_METHOD value -> classification; safe methods are omitted (no finding).
_LOGIN_DEFS_WEAK: dict[str, Classification] = {
    "DES": Classification.SANGAT_TINGGI,
    "MD5": Classification.SANGAT_TINGGI,
    "SHA256": Classification.SEDERHANA,
}

# Shadow hash prefix -> (scheme name, classification). Safe schemes ($2*,
# $6$, $y$, $7$) are omitted; a field with no `$` at all is legacy DES-crypt.
_SHADOW_WEAK_PREFIXES: tuple[tuple[str, str, Classification], ...] = (
    ("$1$", "MD5", Classification.SANGAT_TINGGI),
    ("$5$", "SHA256", Classification.SEDERHANA),
)
_SHADOW_SAFE_PREFIXES = ("$2", "$6$", "$y$", "$7$")


class HostPamHashing(Probe):
    """Flag weak password-hash schemes in login.defs, pam.d and shadow."""

    id = "host.pam.hashing"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(
        self,
        login_defs: Path | None = None,
        pam_dir: Path | None = None,
        shadow: Path | None = None,
    ) -> None:
        self.login_defs = login_defs or Path("/etc/login.defs")
        self.pam_dir = pam_dir or Path("/etc/pam.d")
        self.shadow = shadow or Path("/etc/shadow")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.login_defs.exists() or self.pam_dir.exists() or self.shadow.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        self._check_login_defs(emit)
        self._check_pam_dir(emit)
        self._check_shadow(emit)

    def _check_login_defs(self, emit: Emitter) -> None:
        try:
            text = self.login_defs.read_text(errors="replace")
        except OSError:
            return
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2 or parts[0].upper() != "ENCRYPT_METHOD":
                continue
            method = parts[1].upper()
            classification = _LOGIN_DEFS_WEAK.get(method)
            if classification is None:
                continue  # SHA512 / YESCRYPT / BCRYPT (or unknown) — safe.
            emit(Finding(
                probe_id=self.id,
                algorithm=f"crypt/{method}",
                classification=classification,
                severity=_sev(classification),
                title=f"login.defs ENCRYPT_METHOD is {method}",
                evidence={"path": str(self.login_defs), "encrypt_method": method},
                remediation={"snippet": "ENCRYPT_METHOD YESCRYPT   # or SHA512"},
            ))

    def _check_pam_dir(self, emit: Emitter) -> None:
        if not self.pam_dir.is_dir():
            return
        for path in sorted(self.pam_dir.iterdir()):
            if not path.is_file():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "pam_unix.so" not in line:
                    continue
                if "md5" in line.split():
                    emit(Finding(
                        probe_id=self.id,
                        algorithm="crypt/MD5",
                        classification=Classification.SANGAT_TINGGI,
                        severity=_sev(Classification.SANGAT_TINGGI),
                        title=f"pam_unix.so uses md5 password hashing in {path.name}",
                        evidence={"path": str(path), "module": "pam_unix.so", "option": "md5"},
                        remediation={
                            "snippet": "# Replace `md5` with `yescrypt` (or `sha512`) on the pam_unix.so line",
                        },
                    ))

    def _check_shadow(self, emit: Emitter) -> None:
        try:
            text = self.shadow.read_text(errors="replace")
        except OSError:  # unreadable without root (PermissionError) — skip.
            return
        counts: dict[str, tuple[Classification, int]] = {}
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) < 2:
                continue
            scheme = self._classify_hash(fields[1])
            if scheme is None:
                continue
            name, classification = scheme
            _, seen = counts.get(name, (classification, 0))
            counts[name] = (classification, seen + 1)
        for name, (classification, seen) in counts.items():
            emit(Finding(
                probe_id=self.id,
                algorithm=f"crypt/{name}",
                classification=classification,
                severity=_sev(classification),
                title=f"shadow contains {name}-crypt password hashes",
                evidence={"path": str(self.shadow), "scheme": name, "accounts": seen},
                remediation={
                    "snippet": "# Re-hash on next login after fixing ENCRYPT_METHOD, or force with:\n"
                               "sudo passwd --expire <user>",
                },
            ))

    @staticmethod
    def _classify_hash(field: str) -> tuple[str, Classification] | None:
        """Map a shadow password field to a weak scheme, or None if safe/N.A."""
        value = field.lstrip("!")  # locked accounts keep their hash prefix.
        if not value or value.startswith("*"):
            return None  # no password set / login disabled.
        for prefix, name, classification in _SHADOW_WEAK_PREFIXES:
            if value.startswith(prefix):
                return name, classification
        if value.startswith(_SHADOW_SAFE_PREFIXES):
            return None
        if not value.startswith("$"):
            return "DES", Classification.SANGAT_TINGGI
        return None  # unrecognised $scheme$ — don't guess.

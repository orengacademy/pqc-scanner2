from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# F5 stores TLS config in `ltm profile client-ssl` / `server-ssl` stanzas.
_PROFILE_RE = re.compile(
    r"ltm\s+profile\s+(client-ssl|server-ssl)\s+(\S+)\s*\{",
    re.IGNORECASE,
)
_CIPHERS_RE = re.compile(r"^\s*ciphers\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_OPTIONS_RE = re.compile(r"options\s*\{([^}]*)\}", re.IGNORECASE)

# tmsh cipher-string alias words that name no concrete primitive.
_ALIAS_WORDS = {"DEFAULT", "ALL", "NATIVE", "HIGH", "MEDIUM", "LOW", "NONE"}

# Literal weak tokens an F5 cipher string may name that classify() does not
# score as a concrete algorithm (protocol families, keyword groups). RC4/DES/
# 3DES/MD5 are also here for an unambiguous SANGAT_TINGGI verdict.
_WEAK_CIPHER_LITERALS = {
    "SSLV3": "SSLV3",
    "TLSV1": "TLSV1",
    "TLSV1_1": "TLSV1.1",
    "TLSV1.1": "TLSV1.1",
    "RC4": "RC4",
    "DES": "DES",
    "3DES": "3DES",
    "MD5": "MD5",
    "EXPORT": "EXPORT",
    "NULL": "NULL",
}

# `options` tokens that force a regression to an older TLS floor.
_WEAK_OPTIONS = {
    "no-tlsv1.3": "TLSV1.3",
    "no-tlsv1.2": "TLSV1.2",
}


class FsConfF5(Probe):
    id = "fs.conf.f5"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/config/bigip.conf"),
            Path("/config/partitions"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else list(root.rglob("bigip.conf"))
            for path in files:
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        for profile, body in _iter_profiles(text):
            self._scan_options(body, path, profile, emit)
            self._scan_ciphers(body, path, profile, emit)

    def _scan_options(self, body: str, path: Path, profile: str, emit: Emitter) -> None:
        om = _OPTIONS_RE.search(body)
        if not om:
            return
        opts = om.group(1)
        for token in opts.split():
            weak = _WEAK_OPTIONS.get(token.lower())
            if weak is None:
                continue
            emit(Finding(
                probe_id=self.id,
                algorithm=weak,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"F5 client-ssl profile {profile} option {token} weakens TLS protocol negotiation",
                evidence={"path": str(path), "profile": profile, "directive": f"options {token}"},
                remediation={"snippet": "remove no-tlsv1.3/no-tlsv1.2 from options"},
            ))

    def _scan_ciphers(self, body: str, path: Path, profile: str, emit: Emitter) -> None:
        for m in _CIPHERS_RE.finditer(body):
            cipher_str = m.group(1).strip().strip('"').strip("'")
            for raw in cipher_str.split(":"):
                token = raw.strip().lstrip("!").lstrip("+").lstrip("-")
                if not token or token.upper() in _ALIAS_WORDS:
                    continue
                literal = _WEAK_CIPHER_LITERALS.get(token.upper())
                if literal is not None:
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=literal,
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=f"F5 ciphers includes weak token {token}",
                        evidence={
                            "path": str(path),
                            "profile": profile,
                            "directive": "ciphers",
                            "list": cipher_str,
                        },
                    ))
                    continue
                cls = classify(token)
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=normalise(token),
                        classification=cls,
                        severity=_sev(cls),
                        title=f"F5 ciphers includes {token}",
                        evidence={
                            "path": str(path),
                            "profile": profile,
                            "directive": "ciphers",
                            "list": cipher_str,
                        },
                    ))


def _iter_profiles(text: str) -> list[tuple[str, str]]:
    """Return (profile-name, brace-delimited body) for each client/server-ssl
    stanza. Uses bracket-depth so nested `{ ... }` blocks are captured whole."""
    out: list[tuple[str, str]] = []
    for m in _PROFILE_RE.finditer(text):
        profile = m.group(2)
        start = m.end()  # first char after the opening brace
        depth = 1
        i = start
        n = len(text)
        while i < n and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        body = text[start:i - 1] if depth == 0 else text[start:i]
        out.append((profile, body))
    return out


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

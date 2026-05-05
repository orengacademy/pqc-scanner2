"""sign.repo.aptdnf_keys — inspect apt/dnf repository signing keys."""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_APT_DIRS = (
    Path("/etc/apt/trusted.gpg.d"),
    Path("/usr/share/keyrings"),
)
_DNF_DIRS = (
    Path("/etc/pki/rpm-gpg"),
)


class SignRepoAptdnfKeys(Probe):
    id = "sign.repo.aptdnf_keys"
    family = ProbeFamily.SIGN
    framework_tags = ("bukukerja:sign", "mykripto:sign")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(d.exists() for d in _APT_DIRS + _DNF_DIRS)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for d in _APT_DIRS + _DNF_DIRS:
            if not d.exists():
                continue
            for path in d.iterdir():
                if not path.is_file():
                    continue
                emit(Finding(
                    probe_id=self.id,
                    algorithm="GPG-REPO-KEY",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"repo signing key: {path.name}",
                    evidence={"path": str(path), "size_bytes": path.stat().st_size,
                              "manager": "apt" if "apt" in str(d) or "keyrings" in str(d)
                                          else "dnf"},
                ))

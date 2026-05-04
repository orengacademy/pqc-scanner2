"""sign.git.signing_keys — git user.signingKey + commit.gpgsign config."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class SignGitSigningKeys(Probe):
    id = "sign.git.signing_keys"
    family = ProbeFamily.SIGN
    framework_tags = ("bukukerja:sign", "mykripto:sign")

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which("git") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        # Read global git config — same approach the user would take.
        for key in ("user.signingkey", "commit.gpgsign", "tag.gpgsign", "gpg.format"):
            proc = await asyncio.create_subprocess_exec(
                "git", "config", "--global", key,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            except asyncio.TimeoutError:
                proc.kill()
                continue
            value = stdout.decode("utf-8", errors="replace").strip()
            if not value:
                continue
            # gpg.format == "ssh" means ssh-key signing; flag to encourage Ed25519.
            cls = Classification.INFO
            sev = Severity.INFO
            if key == "gpg.format" and value.lower() == "openpgp":
                # OpenPGP default — typically RSA, surface it.
                cls = Classification.TINGGI
                sev = Severity.MED
            emit(Finding(
                probe_id=self.id,
                algorithm=f"git-{key}",
                classification=cls, severity=sev,
                title=f"git config {key} = {value}",
                evidence={"key": key, "value": value},
            ))

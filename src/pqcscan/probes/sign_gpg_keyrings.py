"""sign.gpg.keyrings — list GPG keys via `gpg --list-keys --with-colons`."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


# GPG colon-format pubkey-algorithm IDs (RFC 4880 + 6637 + 9580 draft):
#   1  = RSA (encrypt + sign)
#   2  = RSA (encrypt only)
#   3  = RSA (sign only)
#   16 = ElGamal (encrypt only)
#   17 = DSA
#   18 = ECDH
#   19 = ECDSA
#   22 = EdDSA
#   23 = X25519 (KEM)
#   24 = Ed25519
#   25 = Ed448
_PUBKEY_ALGO = {
    "1": "RSA", "2": "RSA", "3": "RSA",
    "16": "ElGamal", "17": "DSA",
    "18": "ECDH", "19": "ECDSA", "22": "EdDSA",
    "23": "X25519", "24": "Ed25519", "25": "Ed448",
}


class SignGpgKeyrings(Probe):
    id = "sign.gpg.keyrings"
    family = ProbeFamily.SIGN
    framework_tags = ("bukukerja:sign", "mykripto:sign", "nist-ir-8547:sign")

    def __init__(self, gpg_bin: str | None = None, timeout_s: float = 30.0):
        self.gpg_bin = gpg_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.gpg_bin or "gpg") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.gpg_bin or "gpg"
        proc = await asyncio.create_subprocess_exec(
            bin_path, "--list-keys", "--with-colons",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            return
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            cols = line.split(":")
            if len(cols) < 5 or cols[0] not in {"pub", "sub"}:
                continue
            length = cols[2]            # key length in bits (e.g. "2048")
            algo_id = cols[3]            # numeric pubkey algo id
            keyid = cols[4]              # 16-char keyid
            algo_name = _PUBKEY_ALGO.get(algo_id, f"alg-id-{algo_id}")
            canonical = (f"{algo_name}-{length}" if algo_name == "RSA" or algo_name == "DSA"
                         or algo_name == "ElGamal" else algo_name)
            cls = classify(canonical)
            emit(Finding(
                probe_id=self.id,
                algorithm=canonical,
                classification=cls, severity=sev_for(cls),
                title=f"GPG {cols[0]} key {keyid[-16:]} {canonical}",
                evidence={"keyid": keyid, "kind": cols[0],
                          "algo_id": algo_id, "length": length},
            ))

"""host.cloud_kms — live cloud KMS / Key Vault key enumeration + classification.

Complements ``fs.keyref.cloud`` (which regex-finds KMS ARNs / ``pkcs11:`` URIs
in config/IaC text): this probe queries the *live* cloud control plane via the
provider CLI — the same shell-out-to-an-installed-host-tool pattern used by
``host.openssl.version`` — to enumerate the actual keys and their algorithm
specs. Managed keys are overwhelmingly classical RSA/ECC (quantum-vulnerable)
and that fact is invisible to a file scanner, so authoritative enumeration
closes the cloud-KMS blind spot.

No new dependencies: it shells out to ``aws`` / ``az`` / ``gcloud`` (stdlib
``subprocess`` + ``json``) only when the CLI is installed and authenticated.
Every provider call is guarded — a CLI that is present but unauthenticated
returns an error, and that provider is silently skipped rather than raising.

GCP KMS enumeration is intentionally not attempted: ``gcloud kms keys list``
requires ``--keyring`` and ``--location`` (which are not discoverable without
first enumerating key rings per location per project), so there is no trivial
best-effort listing. It is documented here and left out.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

from pqcscan.core.alg import classify
from pqcscan.core.types import Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

# runner(argv) -> stdout string, or None when the command is missing / fails /
# the CLI is unauthenticated. This is the test seam.
Runner = Callable[[list[str]], "str | None"]

_TIMEOUT = 15.0

# AWS KMS KeySpec -> (algorithm we classify(), human note).
_AWS_SPEC_MAP: dict[str, tuple[str, str]] = {
    "RSA_2048": ("RSA-2048", "Classical RSA-2048 — quantum-vulnerable (Shor); migrate to ML-DSA/ML-KEM."),
    "RSA_3072": ("RSA-3072", "Classical RSA-3072 — quantum-vulnerable (Shor); migrate to ML-DSA/ML-KEM."),
    "RSA_4096": ("RSA-4096", "Classical RSA-4096 — quantum-vulnerable (Shor); migrate to ML-DSA/ML-KEM."),
    "ECC_NIST_P256": ("ECDSA-P256", "Classical NIST P-256 ECC — quantum-vulnerable (Shor); migrate to ML-DSA."),
    "ECC_NIST_P384": ("ECDSA-P384", "Classical NIST P-384 ECC — quantum-vulnerable (Shor); migrate to ML-DSA."),
    "ECC_NIST_P521": ("ECDSA-P521", "Classical NIST P-521 ECC — quantum-vulnerable (Shor); migrate to ML-DSA."),
    "ECC_SECG_P256K1": ("ECDSA-secp256k1", "Classical secp256k1 ECC — quantum-vulnerable (Shor); migrate to ML-DSA."),
    "SYMMETRIC_DEFAULT": ("AES-256", "Symmetric AES-256 — quantum-resistant (Grover halves strength; still ~128-bit)."),
    "AES_256": ("AES-256", "Symmetric AES-256 — quantum-resistant (Grover halves strength; still ~128-bit)."),
}

# Azure Key Vault key type (kty) -> (algorithm we classify(), human note).
_AZ_KTY_MAP: dict[str, tuple[str, str]] = {
    "RSA": ("RSA", "Classical RSA — quantum-vulnerable (Shor); migrate to ML-DSA/ML-KEM."),
    "RSA-HSM": ("RSA", "Classical RSA (HSM-backed) — quantum-vulnerable (Shor); migrate to ML-DSA/ML-KEM."),
    "EC": ("ECDSA", "Classical EC — quantum-vulnerable (Shor); migrate to ML-DSA."),
    "EC-HSM": ("ECDSA", "Classical EC (HSM-backed) — quantum-vulnerable (Shor); migrate to ML-DSA."),
    "OCT": ("AES-256", "Symmetric key — quantum-resistant (Grover halves strength)."),
    "OCT-HSM": ("AES-256", "Symmetric key (HSM-backed) — quantum-resistant (Grover halves strength)."),
}


def _subprocess_runner(argv: list[str]) -> str | None:
    """Default runner: run the real CLI, guarded, with a short timeout."""
    if not argv or shutil.which(argv[0]) is None:
        return None
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            timeout=_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="replace")


def _parse_json(out: str | None) -> Any:
    if not out:
        return None
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None


def _region_from_arn(arn: str | None) -> str | None:
    # arn:aws:kms:<region>:<account>:key/<id>
    if not arn:
        return None
    parts = arn.split(":")
    if len(parts) >= 4 and parts[0] == "arn" and parts[2] == "kms":
        return parts[3] or None
    return None


class HostCloudKms(Probe):
    """Enumerate live cloud KMS / Key Vault keys and classify their algorithms."""

    id = "host.cloud_kms"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:kms", "mykripto:kms")

    def __init__(
        self,
        runner: Runner | None = None,
        aws: str = "aws",
        az: str = "az",
        gcloud: str = "gcloud",
    ) -> None:
        self._injected = runner is not None
        self.runner: Runner = runner or _subprocess_runner
        self.aws = aws
        self.az = az
        self.gcloud = gcloud

    async def applies(self, ctx: ScanContext) -> bool:
        if self._injected:
            return True
        return any(shutil.which(cli) is not None for cli in (self.aws, self.az, self.gcloud))

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        self._run_aws(emit)
        self._run_azure(emit)
        # GCP KMS is intentionally skipped (see module docstring).

    # -- AWS KMS ----------------------------------------------------------
    def _run_aws(self, emit: Emitter) -> None:
        listing = _parse_json(self.runner([self.aws, "kms", "list-keys", "--output", "json"]))
        if not isinstance(listing, dict):
            return
        for entry in listing.get("Keys", []) or []:
            if not isinstance(entry, dict):
                continue
            key_id = entry.get("KeyId")
            if not key_id:
                continue
            described = _parse_json(
                self.runner([self.aws, "kms", "describe-key", "--key-id", str(key_id), "--output", "json"])
            )
            if not isinstance(described, dict):
                continue
            meta = described.get("KeyMetadata")
            if not isinstance(meta, dict):
                continue
            key_spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")
            algorithm, note = self._map_aws_spec(key_spec)
            region = _region_from_arn(meta.get("Arn"))
            cls = classify(algorithm)
            if key_spec and str(key_spec).upper().startswith("HMAC"):
                note = "Symmetric HMAC key — quantum-resistant with an adequate key length."
            evidence: dict[str, Any] = {
                "provider": "aws",
                "key_id": str(key_id),
                "key_spec": key_spec,
                "note": note,
            }
            if region:
                evidence["region"] = region
            emit(Finding(
                probe_id=self.id,
                algorithm=algorithm,
                classification=cls,
                severity=sev_for(cls),
                title=f"AWS KMS key {key_id} uses {algorithm}",
                evidence=evidence,
            ))

    @staticmethod
    def _map_aws_spec(spec: Any) -> tuple[str, str]:
        s = str(spec or "").upper()
        if s in _AWS_SPEC_MAP:
            return _AWS_SPEC_MAP[s]
        if s.startswith("HMAC"):
            return "HMAC", "Symmetric HMAC key — quantum-resistant with an adequate key length."
        # Unknown/opaque spec: hand the raw name to classify() (yields INFO).
        return s or "unknown", "Unrecognised KMS key spec; confirm the algorithm and PQC exposure."

    # -- Azure Key Vault --------------------------------------------------
    def _run_azure(self, emit: Emitter) -> None:
        vaults = _parse_json(self.runner([self.az, "keyvault", "list", "--output", "json"]))
        if not isinstance(vaults, list):
            return
        for vault in vaults:
            if not isinstance(vault, dict):
                continue
            vault_name = vault.get("name")
            if not vault_name:
                continue
            keys = _parse_json(
                self.runner([self.az, "keyvault", "key", "list", "--vault-name", str(vault_name), "--output", "json"])
            )
            if not isinstance(keys, list):
                continue
            for key in keys:
                if not isinstance(key, dict):
                    continue
                key_name = self._azure_key_name(key)
                if not key_name:
                    continue
                shown = _parse_json(self.runner([
                    self.az, "keyvault", "key", "show",
                    "--vault-name", str(vault_name), "--name", key_name, "--output", "json",
                ]))
                if not isinstance(shown, dict):
                    continue
                key_obj = shown.get("key")
                if not isinstance(key_obj, dict):
                    continue
                kty = key_obj.get("kty")
                algorithm, note = self._map_azure_kty(kty, key_obj.get("crv"))
                cls = classify(algorithm)
                emit(Finding(
                    probe_id=self.id,
                    algorithm=algorithm,
                    classification=cls,
                    severity=sev_for(cls),
                    title=f"Azure Key Vault key {vault_name}/{key_name} uses {algorithm}",
                    evidence={
                        "provider": "azure",
                        "vault": str(vault_name),
                        "key_id": key_name,
                        "key_spec": kty,
                        "note": note,
                    },
                ))

    @staticmethod
    def _azure_key_name(key: dict[str, Any]) -> str | None:
        name = key.get("name")
        if name:
            return str(name)
        kid = key.get("kid")
        if not kid:
            return None
        # https://<vault>.vault.azure.net/keys/<name>[/<version>]
        parts = str(kid).rstrip("/").split("/")
        if "keys" in parts:
            idx = parts.index("keys")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return parts[-1] or None

    @staticmethod
    def _map_azure_kty(kty: Any, crv: Any) -> tuple[str, str]:
        k = str(kty or "").upper()
        algorithm, note = _AZ_KTY_MAP.get(k, ("", ""))
        if not algorithm:
            return (str(kty or "unknown"), "Unrecognised Key Vault key type; confirm the algorithm and PQC exposure.")
        if algorithm == "ECDSA" and crv:
            algorithm = f"ECDSA-{crv}"
        return algorithm, note

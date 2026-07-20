"""host.windows.schannel — Windows SCHANNEL TLS/crypto posture (registry).

Windows applications that use the OS TLS stack (IIS, RDP, WinRM, SQL Server,
.NET, Edge/Chrome fall back to it) are governed by the SCHANNEL registry hive
under `HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL`.
Enabling a weak protocol / cipher / hash there re-opens it host-wide regardless
of any per-app config.

This probe walks that hive and flags every ENABLED weak primitive:
  * Protocols  — SSL 2.0/3.0, TLS 1.0/1.1 (broken now).
  * Ciphers    — RC4, DES, NULL, export (broken now); Triple DES (3DES) weak;
                 AES sized via the shared classifier.
  * Hashes     — MD5 (broken), SHA-1 (weak).
  * KeyExchangeAlgorithms — PKCS (RSA), ECDH, DH: classical, quantum-vulnerable.

The live read uses the stdlib `winreg` module and therefore only runs on
Windows; on every other platform (and in CI) the caller injects a config dict,
so the module imports and tests cleanly on Linux with no `winreg` present.
"""
from __future__ import annotations

import re
import sys
from typing import Any

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

# SCHANNEL protocol subkey names that are broken and must never be enabled.
_WEAK_PROTOCOLS: frozenset[str] = frozenset({
    "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1",
    "PCT 1.0", "MULTI-PROTOCOL UNIFIED HELLO",
})

_AES_BITS_RE = re.compile(r"AES\s*(\d+)")


def _is_enabled(value: Any) -> bool:
    """SCHANNEL `Enabled` is a DWORD: 0 = disabled, non-zero (0xffffffff) = on."""
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return False


class HostWindowsSchannel(Probe):
    """Report enabled weak primitives in the Windows SCHANNEL registry hive."""

    id = "host.windows.schannel"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, schannel_config: dict[str, Any] | None = None) -> None:
        # An injected dict is the test/offline seam; a live registry read only
        # happens on Windows (see _read_registry). None here means "read live".
        self._config = schannel_config

    async def applies(self, ctx: ScanContext) -> bool:
        return self._config is not None or sys.platform == "win32"

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        config = self._config
        if config is None:
            config = self._read_registry()
        if not config or not isinstance(config, dict):
            return

        self._walk_protocols(config.get("Protocols"), emit)
        self._walk_ciphers(config.get("Ciphers"), emit)
        self._walk_hashes(config.get("Hashes"), emit)
        self._walk_key_exchange(config.get("KeyExchangeAlgorithms"), emit)

    # --- section walkers -------------------------------------------------

    def _walk_protocols(self, section: Any, emit: Emitter) -> None:
        if not isinstance(section, dict):
            return
        for name, entry in section.items():
            sides = _protocol_enabled_sides(entry)
            if not sides:
                continue
            if str(name).strip().upper() not in _WEAK_PROTOCOLS:
                continue  # TLS 1.2/1.3 etc. — enabled is correct, not a finding.
            emit(self._finding(
                "Protocols", name, Classification.SANGAT_TINGGI,
                title=f"SCHANNEL protocol {name} is enabled ({', '.join(sides)})",
                note=(
                    f"{name} is cryptographically broken and enabled host-wide; "
                    "any app using the OS TLS stack can negotiate it."
                ),
                extra={"sides": sides},
            ))

    def _walk_ciphers(self, section: Any, emit: Emitter) -> None:
        if not isinstance(section, dict):
            return
        for name, entry in section.items():
            if not _entry_enabled(entry):
                continue
            classification = _classify_cipher(str(name))
            if classification is None:
                continue  # strong (AES-256/ChaCha) — not a weakness.
            emit(self._finding(
                "Ciphers", name, classification,
                title=f"SCHANNEL cipher {name} is enabled",
                note=f"Enabled cipher {name} classified {classification.value}.",
            ))

    def _walk_hashes(self, section: Any, emit: Emitter) -> None:
        if not isinstance(section, dict):
            return
        for name, entry in section.items():
            if not _entry_enabled(entry):
                continue
            classification = _classify_hash(str(name))
            if classification is None:
                continue
            emit(self._finding(
                "Hashes", name, classification,
                title=f"SCHANNEL hash {name} is enabled",
                note=f"Enabled hash {name} classified {classification.value}.",
            ))

    def _walk_key_exchange(self, section: Any, emit: Emitter) -> None:
        if not isinstance(section, dict):
            return
        for name, entry in section.items():
            if not _entry_enabled(entry):
                continue
            # PKCS (RSA), ECDH, DH — all classical, all quantum-vulnerable.
            emit(self._finding(
                "KeyExchangeAlgorithms", name, Classification.TINGGI,
                title=f"SCHANNEL key exchange {name} is classical (quantum-vulnerable)",
                note=(
                    f"{name} is a classical key-establishment primitive with no "
                    "PQC hybrid — harvest-now-decrypt-later exposed."
                ),
            ))

    # --- helpers ---------------------------------------------------------

    def _finding(
        self,
        section: str,
        name: Any,
        classification: Classification,
        *,
        title: str,
        note: str,
        extra: dict[str, Any] | None = None,
    ) -> Finding:
        algorithm = f"SCHANNEL/{section}/{name}"
        evidence: dict[str, Any] = {
            "registry_key": algorithm,
            "section": section,
            "name": str(name),
            "note": note,
        }
        if extra:
            evidence.update(extra)
        return Finding(
            probe_id=self.id,
            algorithm=algorithm,
            classification=classification,
            severity=sev_for(classification),
            title=title,
            evidence=evidence,
            remediation={
                "snippet": (
                    "# Disable in the SCHANNEL registry hive (reboot to apply):\n"
                    "# HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"
                    f"\\SCHANNEL\\{section}\\{name}\n"
                    "# set Enabled = 0x00000000 (DWORD)"
                ),
            },
        )

    # --- live registry read (Windows only) -------------------------------

    def _read_registry(self) -> dict[str, Any] | None:
        """Read the SCHANNEL hive on Windows. Returns None elsewhere / on error.

        `winreg` is Windows-only stdlib; the import lives under the platform
        guard so importing this module on Linux never touches it.
        """
        if sys.platform != "win32":
            return None
        try:
            import winreg
        except ImportError:
            return None

        base = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
        config: dict[str, Any] = {}
        for section in ("Protocols", "Ciphers", "Hashes", "KeyExchangeAlgorithms"):
            try:
                sub = _read_key(winreg, winreg.HKEY_LOCAL_MACHINE, f"{base}\\{section}")
            except OSError:
                continue
            if sub:
                config[section] = sub
        return config or None


# --- module-level classification helpers ---------------------------------


def _entry_enabled(entry: Any) -> bool:
    """A Cipher/Hash/KeyExchange leaf: {"Enabled": <dword>}."""
    if not isinstance(entry, dict):
        return False
    return _is_enabled(entry.get("Enabled"))


def _protocol_enabled_sides(entry: Any) -> list[str]:
    """Protocol entries nest Client/Server subkeys (each with Enabled); some
    hives also carry a bare Enabled at the protocol level."""
    if not isinstance(entry, dict):
        return []
    sides: list[str] = []
    if _is_enabled(entry.get("Enabled")):
        sides.append("Root")
    for side in ("Client", "Server"):
        sub = entry.get(side)
        if isinstance(sub, dict) and _is_enabled(sub.get("Enabled")):
            sides.append(side)
    return sides


def _classify_cipher(name: str) -> Classification | None:
    """Map a SCHANNEL cipher subkey name to a classification, or None if the
    cipher is strong enough not to warrant a finding."""
    up = name.upper()
    if "RC4" in up or "RC2" in up:
        return Classification.SANGAT_TINGGI
    if "TRIPLE DES" in up or "3DES" in up:
        return Classification.TINGGI  # 3DES: weak but not trivially broken.
    if "DES" in up:  # plain single DES (e.g. "DES 56/56").
        return Classification.SANGAT_TINGGI
    if "NULL" in up:
        return Classification.SANGAT_TINGGI
    if "EXPORT" in up or up.startswith("EXP"):
        return Classification.SANGAT_TINGGI
    if "AES" in up:
        m = _AES_BITS_RE.search(up)
        cls = classify(f"AES-{m.group(1)}" if m else "AES")
        return cls if cls in _CIPHER_WORTH else None
    cls = classify(normalise(name))
    return cls if cls in _CIPHER_WORTH else None


def _classify_hash(name: str) -> Classification | None:
    up = name.strip().upper()
    if up == "MD5":
        return Classification.SANGAT_TINGGI
    if up in ("SHA", "SHA1", "SHA-1", "SHA 1"):
        return Classification.TINGGI  # SHA-1 in the SCHANNEL hive is named "SHA".
    return None


# Classifications weak enough that an enabled cipher is worth reporting.
_CIPHER_WORTH: frozenset[Classification] = frozenset({
    Classification.SANGAT_TINGGI,
    Classification.TINGGI,
    Classification.SEDERHANA,
})


def _read_key(winreg: Any, root: Any, path: str) -> dict[str, Any]:
    """Recursively read a registry key into a nested dict of values + subkeys.

    Windows-only (invoked solely from _read_registry under the platform guard).
    """
    result: dict[str, Any] = {}
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return result
    try:
        i = 0
        while True:
            try:
                value_name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            result[value_name] = value
            i += 1
        j = 0
        while True:
            try:
                sub_name = winreg.EnumKey(key, j)
            except OSError:
                break
            result[sub_name] = _read_key(winreg, root, f"{path}\\{sub_name}")
            j += 1
    finally:
        winreg.CloseKey(key)
    return result

"""Shared SBOM helper — emit a 'package: <name> <version>' Finding."""
from __future__ import annotations

from collections.abc import Callable

from pqcscan.core.types import Classification, Finding, Severity


def emit_package(
    probe_id: str,
    emit: Callable[[Finding], None],
    *,
    name: str,
    version: str,
    manager: str,
    purl_type: str,
    extra_evidence: dict | None = None,
) -> None:
    """Emit an INFO-level Finding describing one installed package."""
    purl = f"pkg:{purl_type}/{name}@{version}" if version else f"pkg:{purl_type}/{name}"
    evidence: dict = {"name": name, "version": version, "manager": manager, "purl": purl}
    if extra_evidence:
        evidence.update(extra_evidence)
    emit(Finding(
        probe_id=probe_id,
        algorithm="N/A",
        classification=Classification.INFO,
        severity=Severity.INFO,
        title=f"package: {name} {version}".strip(),
        evidence=evidence,
    ))

"""cve.cargo_audit — `cargo audit --json` for Rust crate CVEs."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none


class CveCargoAudit(Probe):
    id = "cve.cargo_audit"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    def __init__(self, roots: list[Path] | None = None,
                 cargo_bin: str | None = None, timeout_s: float = 120.0):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]
        self.cargo_bin = cargo_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        resolved = resolve_or_none(self.cargo_bin, "cargo")
        if resolved is None:
            return False
        # cargo-audit subcommand existence:
        proc = await asyncio.create_subprocess_exec(
            str(resolved), "audit", "--version",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            return (await asyncio.wait_for(proc.wait(), timeout=5)) == 0
        except asyncio.TimeoutError:
            proc.kill()
            return False

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        resolved = resolve_or_none(self.cargo_bin, "cargo")
        if resolved is None:
            return
        bin_path = str(resolved)
        for root in self.roots:
            if not root.exists():
                continue
            for cargo_lock in root.rglob("Cargo.lock"):
                proc = await asyncio.create_subprocess_exec(
                    bin_path, "audit", "--json",
                    cwd=str(cargo_lock.parent),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
                except asyncio.TimeoutError:
                    proc.kill()
                    continue
                try:
                    doc = json.loads(stdout)
                except json.JSONDecodeError:
                    continue
                for v in (doc.get("vulnerabilities", {}) or {}).get("list", []):
                    advisory = v.get("advisory", {}) or {}
                    pkg = (v.get("package", {}) or {})
                    emit(Finding(
                        probe_id=self.id,
                        algorithm="N/A",
                        classification=Classification.TINGGI,
                        severity=Severity.HIGH,
                        title=f"{advisory.get('id', '?')} in Rust crate {pkg.get('name', '?')} {pkg.get('version', '?')}",
                        evidence={"advisory_id": advisory.get("id", ""),
                                  "package": pkg.get("name", ""),
                                  "version": pkg.get("version", ""),
                                  "lockfile": str(cargo_lock)},
                    ))

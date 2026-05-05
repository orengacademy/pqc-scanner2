"""code.semgrep.pqc — runs Semgrep with the bundled pqc-readiness ruleset.

Detects:
  - Python: hashlib.md5/sha1, RSA/DSA generate(), AES-CBC, DES.new()
  - JS/TS:  crypto.createHash("md5"|"sha1"), jwt.sign HS256
  - Go:     md5.New() / sha1.New()

Each Semgrep finding is mapped via its `metadata.pqcscan_classification`
to a pqcscan Classification, severity is taken from Semgrep, and the
algorithm + framework_tags ride along in the Finding's evidence so the
compliance engine can attach framework verdicts the same way it does
for native probes.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none

_BUNDLED_RULES = Path(__file__).parent / "_semgrep_rules" / "pqc-readiness.yaml"

_SEMGREP_TO_SEV = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MED,
    "INFO": Severity.INFO,
}


class CodeSemgrepPqc(Probe):
    id = "code.semgrep.pqc"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code")

    def __init__(self, roots: list[Path] | None = None,
                 semgrep_bin: str | None = None,
                 rules_path: Path | None = None,
                 timeout_s: float = 180.0):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]
        self.semgrep_bin = semgrep_bin
        self.rules_path = rules_path or _BUNDLED_RULES
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return (
            resolve_or_none(self.semgrep_bin, "semgrep") is not None
            and self.rules_path.exists()
            and any(r.exists() for r in self.roots)
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        resolved = resolve_or_none(self.semgrep_bin, "semgrep")
        if resolved is None:
            return
        bin_path = str(resolved)
        for root in self.roots:
            if not root.exists():
                continue
            proc = await asyncio.create_subprocess_exec(
                bin_path, "scan", "--config", str(self.rules_path),
                "--json", "--no-git-ignore", "--quiet", str(root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout_s,
                )
            except TimeoutError:
                proc.kill()
                continue
            try:
                doc = json.loads(stdout)
            except json.JSONDecodeError:
                continue
            for r in doc.get("results", []) or []:
                self._emit_one(r, emit)

    def _emit_one(self, r: dict, emit: Emitter) -> None:
        path = r.get("path", "")
        start_line = (r.get("start") or {}).get("line", 0)
        rule_id = r.get("check_id", "")
        sev_label = (r.get("extra", {}) or {}).get("severity", "WARNING")
        meta = ((r.get("extra", {}) or {}).get("metadata", {}) or {})
        classification_str = meta.get("pqcscan_classification", "info")
        algorithm = meta.get("pqcscan_algorithm", "N/A")
        message = (r.get("extra", {}) or {}).get("message", "")
        try:
            cls = Classification(classification_str)
        except ValueError:
            cls = Classification.INFO
        emit(Finding(
            probe_id=self.id,
            algorithm=algorithm,
            classification=cls,
            severity=_SEMGREP_TO_SEV.get(sev_label, Severity.MED),
            title=f"{rule_id} at {path}:{start_line}",
            evidence={
                "rule_id": rule_id,
                "path": path,
                "line": start_line,
                "snippet": (r.get("extra", {}) or {}).get("lines", "")[:200],
                "message": message,
                "framework_tags": meta.get("framework_tags", []),
            },
            remediation={"snippet": message},
        ))

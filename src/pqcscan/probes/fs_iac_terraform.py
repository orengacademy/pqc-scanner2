"""fs.iac.terraform — scan Terraform (*.tf / *.tf.json) for quantum-vulnerable
or weak crypto configuration.

HCL is treated as text and parsed by regex (no HCL library); *.tf.json files use
the same field regexes since the string values are identical. Each resource is
sliced into a block by locating provider-prefixed resource declarations, then the
relevant crypto fields inside the block are classified.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_EXCLUDE_DIRS = frozenset({".git", ".terraform", "node_modules", "vendor"})
_MAX_PER_FILE = 200

# Provider-prefixed resource/data declarations. Matches HCL
# `resource "aws_kms_key" "x" {` and the JSON key `"aws_kms_key":`.
_RESOURCE_RE = re.compile(
    r'(?:resource\s+"|data\s+"|")((?:aws|google|azurerm|tls)_[a-z0-9_]+)"',
    re.IGNORECASE,
)

# Legacy AWS ELB/ALB TLS security policies that still permit TLS 1.0/1.1.
_LEGACY_SSL_POLICY = "ELBSECURITYPOLICY-2016-08"

_field_cache: dict[str, re.Pattern[str]] = {}


def _field_re(field: str) -> re.Pattern[str]:
    pat = _field_cache.get(field)
    if pat is None:
        pat = re.compile(
            r"(?<![A-Za-z0-9_])" + re.escape(field) + r'\s*"?\s*[:=]\s*"?([A-Za-z0-9_.\-]+)',
            re.IGNORECASE,
        )
        _field_cache[field] = pat
    return pat


def _digits(value: str) -> int | None:
    m = re.search(r"\d+", value)
    return int(m.group()) if m else None


def _rsa_cls(bits: int | None) -> Classification:
    return Classification.SANGAT_TINGGI if bits is not None and bits < 3072 else Classification.TINGGI


class FsIacTerraform(Probe):
    id = "fs.iac.terraform"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path.cwd()]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else self._iter_files(root)
            for path in files:
                if path in seen:
                    continue
                seen.add(path)
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                self._scan_text(text, path, emit)

    @staticmethod
    def _iter_files(root: Path) -> list[Path]:
        out: list[Path] = []
        for pattern in ("*.tf", "*.tf.json"):
            for p in root.rglob(pattern):
                if any(part in _EXCLUDE_DIRS for part in p.parts):
                    continue
                if p.is_file():
                    out.append(p)
        return out

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        decls = [(m.start(), m.group(1).lower()) for m in _RESOURCE_RE.finditer(text)]
        count = 0
        for i, (start, rtype) in enumerate(decls):
            end = decls[i + 1][0] if i + 1 < len(decls) else len(text)
            block = text[start:end]
            for finding in self._scan_block(rtype, block, start, text, path):
                if count >= _MAX_PER_FILE:
                    return
                emit(finding)
                count += 1

    def _scan_block(
        self, rtype: str, block: str, base: int, text: str, path: Path
    ) -> list[Finding]:
        out: list[Finding] = []

        def add(field: str, value: str, algorithm: str, cls: Classification, pos: int) -> None:
            line = text[: base + pos].count("\n") + 1
            out.append(Finding(
                probe_id=self.id,
                algorithm=algorithm,
                classification=cls,
                severity=sev_for(cls),
                title=f"terraform {rtype} {field}={value} ({algorithm}) in {path}:{line}",
                evidence={
                    "path": str(path),
                    "line": line,
                    "resource": rtype,
                    "field": field,
                    "value": value,
                    "snippet": _snippet(text, base + pos),
                },
            ))

        if rtype == "aws_kms_key":
            for m in _field_re("customer_master_key_spec").finditer(block):
                v = m.group(1).upper()
                if v.startswith("SYMMETRIC"):
                    continue  # AES-256 symmetric CMK — quantum-safe, not flagged
                if v.startswith("RSA"):
                    bits = _digits(v)
                    add("customer_master_key_spec", m.group(1),
                        f"RSA-{bits}" if bits else "RSA", _rsa_cls(bits), m.start(1))
                elif v.startswith("ECC"):
                    add("customer_master_key_spec", m.group(1),
                        normalise("ECDSA"), Classification.TINGGI, m.start(1))

        elif rtype in {"aws_lb_listener", "aws_alb_listener"}:
            for m in _field_re("ssl_policy").finditer(block):
                v = m.group(1).upper()
                if "TLS-1-0" in v or "TLS-1-1" in v or v == _LEGACY_SSL_POLICY:
                    add("ssl_policy", m.group(1), "TLS-LEGACY",
                        Classification.TINGGI, m.start(1))

        elif rtype == "tls_private_key":
            am = _field_re("algorithm").search(block)
            algo = am.group(1).upper() if am else "RSA"  # provider default is RSA
            pos = am.start(1) if am else 0
            if algo.startswith("RSA"):
                bm = _field_re("rsa_bits").search(block)
                bits = _digits(bm.group(1)) if bm else 2048  # provider default 2048
                add("algorithm", am.group(1) if am else "RSA",
                    f"RSA-{bits}", _rsa_cls(bits), pos)
            elif algo.startswith("ECDSA"):
                add("algorithm", am.group(1) if am else "ECDSA",
                    normalise("ECDSA"), Classification.TINGGI, pos)

        elif rtype == "aws_acm_certificate":
            for m in _field_re("key_algorithm").finditer(block):
                v = m.group(1).upper()
                if v.startswith("RSA"):
                    bits = _digits(v)
                    add("key_algorithm", m.group(1),
                        f"RSA-{bits}" if bits else "RSA", _rsa_cls(bits), m.start(1))
                elif v.startswith("EC"):
                    add("key_algorithm", m.group(1),
                        normalise("ECDSA"), Classification.TINGGI, m.start(1))

        elif rtype.startswith("google_privateca"):
            for m in _field_re("algorithm").finditer(block):
                v = m.group(1).upper()
                if "RSA" in v:
                    bits = _digits(v)
                    add("algorithm", m.group(1),
                        f"RSA-{bits}" if bits else "RSA", _rsa_cls(bits), m.start(1))
                elif v.startswith("EC"):
                    add("algorithm", m.group(1),
                        normalise("ECDSA"), Classification.TINGGI, m.start(1))

        elif rtype == "azurerm_key_vault_key":
            km = _field_re("key_type").search(block)
            if km:
                kt = km.group(1).upper()
                if kt.startswith("RSA"):
                    sm = _field_re("key_size").search(block)
                    bits = _digits(sm.group(1)) if sm else None
                    add("key_type", km.group(1),
                        f"RSA-{bits}" if bits else "RSA", _rsa_cls(bits), km.start(1))
                elif kt.startswith("EC"):
                    add("key_type", km.group(1),
                        normalise("ECDSA"), Classification.TINGGI, km.start(1))

        return out


def _snippet(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start: end if end != -1 else len(text)]
    return line.strip()[:160]

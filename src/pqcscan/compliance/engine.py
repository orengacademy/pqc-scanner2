"""Compliance engine — loads framework YAML rules and decorates Findings.

Rule shape (one YAML per framework):

    framework: cnsa2
    title: Commercial National Security Algorithm Suite 2.0
    rules:
      - match:
          algorithm: RSA
          key_size_lt: 3072
        clause: CNSA2:RSA-deprecated
        verdict: non-compliant
        deadline: 2030-12-31
      - match:
          algorithm: ML-KEM-768
        clause: CNSA2:KEM-approved
        verdict: compliant

`match` predicates supported in v0.1:
  algorithm                : substring match against the canonical algorithm
                             name (case-insensitive). e.g. "RSA" matches
                             RSA-2048, RSA-SHA256, RSA-3072.
  algorithm_exact          : exact case-insensitive match.
  key_size_lt / key_size_ge: parses trailing digits from the algorithm name
                             and compares numerically (e.g. RSA-2048 -> 2048).
  classification           : one of sangat-tinggi/tinggi/sederhana/rendah/
                             pqc-ready/info/error.
  classification_in        : list of classifications.

A rule fires for a Finding when ALL declared `match` keys evaluate true.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from pqcscan.core.types import Finding


_KEY_SIZE_RE = re.compile(r"(\d+)")


@dataclass(frozen=True, slots=True)
class FrameworkVerdict:
    framework: str
    clause: str
    verdict: str
    deadline: date | None
    note: str = ""


@dataclass(frozen=True, slots=True)
class _Rule:
    match: dict[str, Any]
    clause: str
    verdict: str
    deadline: date | None
    note: str

    def applies(self, f: Finding) -> bool:
        for key, expected in self.match.items():
            if not _matches(key, expected, f):
                return False
        return True


@dataclass(frozen=True, slots=True)
class FrameworkRules:
    framework: str
    title: str
    rules: tuple[_Rule, ...]


def _matches(key: str, expected: Any, f: Finding) -> bool:
    a = f.algorithm.upper()
    if key == "algorithm":
        return str(expected).upper() in a
    if key == "algorithm_exact":
        return a == str(expected).upper()
    if key in {"key_size_lt", "key_size_ge"}:
        m = _KEY_SIZE_RE.search(f.algorithm)
        if not m:
            return False
        bits = int(m.group(1))
        return bits < int(expected) if key == "key_size_lt" else bits >= int(expected)
    if key == "classification":
        return f.classification.value == str(expected)
    if key == "classification_in":
        return f.classification.value in {str(x) for x in expected}
    return False


def _parse_deadline(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def load_framework(path: Path) -> FrameworkRules:
    with path.open() as f:
        doc = yaml.safe_load(f) or {}
    raw_rules = doc.get("rules", []) or []
    rules: list[_Rule] = []
    for r in raw_rules:
        rules.append(_Rule(
            match=r.get("match", {}) or {},
            clause=r.get("clause", ""),
            verdict=r.get("verdict", "advisory"),
            deadline=_parse_deadline(r.get("deadline")),
            note=r.get("note", ""),
        ))
    return FrameworkRules(
        framework=doc.get("framework", path.stem),
        title=doc.get("title", path.stem),
        rules=tuple(rules),
    )


_DEFAULT_FRAMEWORK_DIR = Path(__file__).parent / "frameworks"


class ComplianceEngine:
    """Evaluates a Finding against every loaded framework's rules."""

    def __init__(self, frameworks: list[FrameworkRules] | None = None):
        if frameworks is None:
            frameworks = [
                load_framework(p)
                for p in sorted(_DEFAULT_FRAMEWORK_DIR.glob("*.yaml"))
            ]
        self.frameworks = frameworks

    def evaluate(self, f: Finding) -> Iterator[FrameworkVerdict]:
        """Yield a FrameworkVerdict for each rule that fires across all frameworks."""
        for fw in self.frameworks:
            for rule in fw.rules:
                if rule.applies(f):
                    yield FrameworkVerdict(
                        framework=fw.framework,
                        clause=rule.clause,
                        verdict=rule.verdict,
                        deadline=rule.deadline,
                        note=rule.note,
                    )

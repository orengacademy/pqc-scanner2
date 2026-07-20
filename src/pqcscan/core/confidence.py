"""Per-finding detection confidence.

Not every finding is equally certain. A parsed X.509 signature algorithm or a
completed TLS handshake is a *fact*; a regex hit on the string "MD5" in a source
file might be a comment, a variable name, or a test fixture. Attaching a
confidence lets the UI/report/SARIF/CBOM down-rank probabilistic detections and
lets operators triage — the false-positive-reduction technique the mature tools
(cbomkit-theia's executability confidence, cryptoscan's comment/test downgrade)
use. No PQC vendor documents a formal model, so this is deliberately explicit.

Levels: "high" (structured parse / live handshake), "medium" (regex/keyword
source match or name/version inference), "low" (heuristic sniff, advertised-only,
or a source match inside a comment / test / vendored file).
"""
from __future__ import annotations

import re

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Path fragments that mark a source hit as low-signal (tests, examples,
# vendored/third-party trees, minified bundles, docs).
_LOW_SIGNAL_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|examples?|fixtures?|testdata|"
    r"vendor|third[_-]?party|node_modules|site-packages|dist|build)(/|$)"
    r"|\.(spec|test)\.[a-z]+$|\.min\.(js|css)$|\.(md|rst|txt)$",
    re.IGNORECASE,
)
# A snippet that is (starts as) a comment in a common language.
_COMMENT_START = re.compile(r"^\s*(#|//|/\*|\*|--|;|<!--|\"\"\"|''')")


def _is_low_signal_source(evidence: dict) -> bool:
    path = str(evidence.get("file") or evidence.get("path") or "")
    if path and _LOW_SIGNAL_PATH.search(path):
        return True
    snippet = str(evidence.get("snippet") or "")
    return bool(snippet and _COMMENT_START.match(snippet))


def assess(probe_id: str, evidence: dict | None = None) -> str:
    """Return the detection confidence for a finding.

    Central so the ~160 probes don't each duplicate the logic; a probe may
    still override by setting `evidence["confidence"]` itself.
    """
    ev = evidence or {}
    forced = ev.get("confidence")
    if forced in (HIGH, MEDIUM, LOW):
        return str(forced)

    pid = probe_id or ""

    # A completed handshake / decrypt confirmed the fact on the wire.
    if ev.get("verified"):
        return HIGH

    # Source-code scans are regex/keyword based → medium, and low inside
    # comments / tests / vendored trees.
    if pid.startswith("code."):
        return LOW if _is_low_signal_source(ev) else MEDIUM

    # Name/version inference (dependency → crypto posture, CVE match).
    if pid.startswith(("sbom.", "cve.")):
        return MEDIUM

    # Content sniffing of unlabelled files, or advertised-but-not-negotiated.
    if pid.endswith((".sniff",)) or "sniff" in pid or ev.get("advertised"):
        return LOW

    # Everything else is a structured parse (cert, config directive, host
    # tool output, registry, live protocol handshake) → high.
    return HIGH

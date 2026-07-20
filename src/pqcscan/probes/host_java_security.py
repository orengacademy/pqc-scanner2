"""host.java.security — JVM crypto POSTURE from the java.security policy file.

The JDK ships a `java.security` properties file whose `jdk.*.disabledAlgorithms`
constraints tell the runtime which protocols / ciphers / key sizes to refuse.
Crypto the JVM disables is effectively unreachable at runtime, so this file is a
reachability / mitigating-control signal — the exact cross-reference CBOMkit-
theia's javasecurity executability check performs against
`jdk.tls.disabledAlgorithms`.

This probe reports the posture: an INFO inventory of what the policy disables,
plus conservative GAP findings for weak protocols / ciphers / key-size floors a
hardened policy would constrain but this one leaves enabled. A final INFO note
records that every classical KEX/signature the JVM offers stays quantum-
vulnerable regardless of policy — this is a PQC scanner.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

# Properties whose comma-separated value lists carry the disable constraints.
_PROP_TLS = "jdk.tls.disabledAlgorithms"
_PROP_CERTPATH = "jdk.certpath.disabledAlgorithms"
_PROP_JAR = "jdk.jar.disabledAlgorithms"
_PROP_LEGACY = "jdk.security.legacyAlgorithms"

_WANTED_PROPS = frozenset({_PROP_TLS, _PROP_CERTPATH, _PROP_JAR, _PROP_LEGACY})

# Legacy TLS protocol tokens a hardened JVM policy disables (TLS 1.0 / 1.1).
_EXPECTED_PROTOCOLS: tuple[tuple[str, str], ...] = (
    ("TLSV1", "TLSv1.0"),
    ("TLSV1.1", "TLSv1.1"),
)

# Broken symmetric / hash primitives a hardened policy disables. Detected by
# substring on the joined disabled list (unambiguous tokens).
_EXPECTED_WEAK: tuple[tuple[str, str], ...] = (
    ("RC4", "RC4"),
    ("3DES", "3DES"),
    ("MD5", "MD5"),
)

# Minimum acceptable key-size floor per family (a policy that disables sizes
# BELOW this value is safe; a missing or lower floor is a gap).
_KEYSIZE_FLOORS: tuple[tuple[str, int], ...] = (
    ("RSA", 2048),
    ("DH", 2048),
    ("EC", 224),
)

_KEYSIZE_RE = re.compile(r"\b(RSA|DH|DSA|EC)\s+KEYSIZE\s*<\s*(\d+)")

# Per-file finding cap (never let a pathological file flood the report).
_MAX_FINDINGS = 50
# Cap on java.security files discovered under a directory root.
_MAX_FILES = 40


def _has_continuation(line: str) -> bool:
    """True when a properties line ends with an odd number of backslashes
    (a line continuation that folds the next physical line into this value)."""
    count = 0
    j = len(line) - 1
    while j >= 0 and line[j] == "\\":
        count += 1
        j -= 1
    return count % 2 == 1


def _logical_lines(text: str) -> list[str]:
    """Fold physical lines into logical ones, honouring `\\` continuation and
    dropping comment / blank lines (Java `.properties` semantics)."""
    result: list[str] = []
    acc: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if acc:
            # Continuation lines have their leading whitespace stripped.
            line = line.lstrip()
        else:
            stripped = line.lstrip()
            if not stripped or stripped[0] in ("#", "!"):
                continue
        if _has_continuation(line):
            acc.append(line[:-1])  # drop the trailing continuation backslash
            continue
        acc.append(line)
        result.append("".join(acc))
        acc = []
    if acc:
        result.append("".join(acc))
    return result


def _split_kv(line: str) -> tuple[str, str] | None:
    """Split a logical properties line at the first `=` or `:` separator."""
    for idx, ch in enumerate(line):
        if ch in ("=", ":"):
            return line[:idx].strip(), line[idx + 1 :].strip()
    return None


def _tokens(value: str) -> list[str]:
    return [t.strip() for t in value.split(",") if t.strip()]


def _parse(text: str) -> dict[str, list[str]]:
    """Return {property -> token list} for the disabled-algorithm properties."""
    out: dict[str, list[str]] = {}
    for line in _logical_lines(text):
        kv = _split_kv(line)
        if kv is None:
            continue
        key, value = kv
        if key in _WANTED_PROPS:
            out[key] = _tokens(value)
    return out


def _default_roots() -> list[Path]:
    """System + JAVA_HOME locations of java.security. Directory roots are
    walked for `java.security`; file roots are read directly."""
    roots: list[Path] = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        base = Path(java_home)
        roots.append(base / "conf" / "security" / "java.security")  # JDK 9+
        roots.append(base / "lib" / "security" / "java.security")   # JDK 8
    roots.append(Path("/usr/lib/jvm"))          # walk for **/java.security
    roots.append(Path("/opt/java"))             # walk for **/java.security
    roots.append(Path("/etc/alternatives/java.security"))
    return roots


class HostJavaSecurity(Probe):
    """Report the JVM's java.security crypto posture (disabled-algorithm sets)."""

    id = "host.java.security"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None) -> None:
        self.roots = roots if roots is not None else _default_roots()

    async def applies(self, ctx: ScanContext) -> bool:
        return any(self._exists(r) for r in self.roots)

    @staticmethod
    def _exists(path: Path) -> bool:
        try:
            return path.exists()
        except OSError:
            return False

    def _discover(self) -> list[Path]:
        """Resolve roots to a de-duplicated list of java.security files."""
        seen: set[str] = set()
        files: list[Path] = []
        for root in self.roots:
            try:
                if root.is_dir():
                    for p in sorted(root.rglob("java.security")):
                        self._add(p, seen, files)
                        if len(files) >= _MAX_FILES:
                            return files
                elif root.is_file():
                    self._add(root, seen, files)
            except OSError:
                continue
            if len(files) >= _MAX_FILES:
                break
        return files

    @staticmethod
    def _add(path: Path, seen: set[str], files: list[Path]) -> None:
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key not in seen:
            seen.add(key)
            files.append(path)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in self._discover():
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan_file(text, path, emit)

    def _scan_file(self, text: str, path: Path, emit: Emitter) -> None:
        props = _parse(text)
        disabled_tls = props.get(_PROP_TLS, [])
        disabled_certpath = props.get(_PROP_CERTPATH, [])
        disabled_jar = props.get(_PROP_JAR, [])

        count = 0

        def send(finding: Finding) -> None:
            nonlocal count
            if count < _MAX_FINDINGS:
                emit(finding)
                count += 1

        n_disabled = len(disabled_tls) + len(disabled_certpath) + len(disabled_jar)

        # 1. INFO inventory of the disabled sets.
        send(Finding(
            probe_id=self.id,
            algorithm="jvm-crypto-policy",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"JVM crypto policy at {path}: {n_disabled} algorithms disabled",
            evidence={
                "path": str(path),
                "disabled_tls": disabled_tls,
                "disabled_certpath": disabled_certpath,
                "disabled_jar": disabled_jar,
            },
        ))

        # 2. Gap findings — weak crypto the TLS policy leaves enabled.
        self._emit_gaps(disabled_tls, path, send)

        # 3. One PQC reminder: classical crypto stays quantum-vulnerable.
        send(Finding(
            probe_id=self.id,
            algorithm="classical-kex-quantum",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title="JVM classical KEX/signatures remain quantum-vulnerable regardless of policy",
            evidence={
                "path": str(path),
                "note": (
                    "disabledAlgorithms constrains weak/legacy crypto but does not add "
                    "PQC; all RSA/DH/ECDH key establishment stays harvest-now-decrypt-later "
                    "exposed. Migrate to ML-KEM hybrid key exchange."
                ),
                "confidence": "medium",
            },
        ))

    def _emit_gaps(self, disabled_tls: list[str], path: Path, send: Emitter) -> None:
        token_set = {t.upper() for t in disabled_tls}
        join = " ".join(disabled_tls).upper()

        # Legacy TLS protocols not disabled.
        for tok, label in _EXPECTED_PROTOCOLS:
            if tok not in token_set:
                send(Finding(
                    probe_id=self.id,
                    algorithm=label,
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"{label} not disabled in JVM policy ({path})",
                    evidence={
                        "path": str(path),
                        "property": _PROP_TLS,
                        "value": disabled_tls,
                        "note": f"{label} is not present in {_PROP_TLS}; the JVM may negotiate it.",
                    },
                ))

        # Broken symmetric / hash primitives not disabled.
        for needle, label in _EXPECTED_WEAK:
            if needle not in join:
                cls = classify(label)
                send(Finding(
                    probe_id=self.id,
                    algorithm=label,
                    classification=cls,
                    severity=sev_for(cls),
                    title=f"{label} not disabled in JVM policy ({path})",
                    evidence={
                        "path": str(path),
                        "property": _PROP_TLS,
                        "value": disabled_tls,
                        "note": f"{label} is not constrained by {_PROP_TLS}.",
                    },
                ))

        # Key-size floors: absent -> SEDERHANA note; present-but-too-low -> TINGGI.
        floors: dict[str, int] = {m.group(1): int(m.group(2)) for m in _KEYSIZE_RE.finditer(join)}
        for family, minimum in _KEYSIZE_FLOORS:
            found = floors.get(family)
            if found is None:
                send(Finding(
                    probe_id=self.id,
                    algorithm=family,
                    classification=Classification.SEDERHANA,
                    severity=Severity.MED,
                    title=f"No {family} keySize floor in JVM policy ({path})",
                    evidence={
                        "path": str(path),
                        "property": _PROP_TLS,
                        "value": disabled_tls,
                        "note": (
                            f"{_PROP_TLS} has no '{family} keySize < N' constraint; weak "
                            f"{family} key sizes (< {minimum}) are not refused."
                        ),
                        "confidence": "medium",
                    },
                ))
            elif found < minimum:
                send(Finding(
                    probe_id=self.id,
                    algorithm=family,
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"{family} keySize floor too low in JVM policy ({path})",
                    evidence={
                        "path": str(path),
                        "property": _PROP_TLS,
                        "value": disabled_tls,
                        "note": (
                            f"policy disables {family} keySize < {found}, but the safe "
                            f"floor is {minimum}; sizes {found}..{minimum - 1} stay enabled."
                        ),
                    },
                ))

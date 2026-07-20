"""sbom.crypto_map — map dependency components to the crypto primitives they ship.

The deferred "SBOM → crypto-primitive mapping" item. Complementary to
app.crypto_lib_pqc_support (which only flags *PQC* libraries): this probe
carries a curated corpus of well-known crypto libraries across ecosystems and
classifies, for each matched dependency, the *worst* primitive it exposes by
default and whether it is quantum-vulnerable.

Walks ctx.scan_paths for dependency manifests (Python requirements.txt /
pyproject.toml, npm package.json, Go go.mod, Rust Cargo.toml, Java pom.xml),
parses package names + versions with the standard library only, looks each
dependency up in CRYPTO_LIBRARY_MAP, and emits one Finding per match. Unknown
dependencies produce no finding.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import TypedDict
from xml.etree import ElementTree as ET

from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


class LibInfo(TypedDict):
    primitives: list[str]
    classification: Classification
    note: str
    pqc: bool


_TINGGI = Classification.TINGGI
_PQC = Classification.PQC_READY
_RENDAH = Classification.RENDAH
_INFO = Classification.INFO

# --- curated corpus: ecosystem -> normalised-name -> LibInfo ---------------
# Keys are lower-cased, `_`->`-` normalised. Go keys are full module paths;
# Maven keys are artifactId *prefixes* (matched with startswith so JDK-variant
# suffixes like `-jdk18on` still hit). `classification` is the worst primitive
# the library exposes by default; `pqc` marks a post-quantum library.
CRYPTO_LIBRARY_MAP: dict[str, dict[str, LibInfo]] = {
    "pypi": {
        "cryptography": {"primitives": ["RSA", "ECDSA", "Ed25519", "AES"],
                         "classification": _TINGGI, "pqc": False,
                         "note": "provides RSA/ECDSA (Shor-breakable)"},
        "pycryptodome": {"primitives": ["RSA", "AES", "DES", "3DES"],
                         "classification": _TINGGI, "pqc": False,
                         "note": "RSA plus legacy DES/3DES available"},
        "pycryptodomex": {"primitives": ["RSA", "AES", "DES", "3DES"],
                          "classification": _TINGGI, "pqc": False,
                          "note": "RSA plus legacy DES/3DES available"},
        "pyopenssl": {"primitives": ["RSA", "ECDSA", "DH"],
                      "classification": _TINGGI, "pqc": False,
                      "note": "OpenSSL binding: RSA/ECDSA/DH"},
        "pynacl": {"primitives": ["X25519", "Ed25519"],
                   "classification": _TINGGI, "pqc": False,
                   "note": "libsodium binding: X25519/Ed25519 (Shor-breakable)"},
        "paramiko": {"primitives": ["RSA", "ECDSA", "Ed25519"],
                     "classification": _TINGGI, "pqc": False,
                     "note": "SSH client keys: RSA/ECDSA/Ed25519"},
        "rsa": {"primitives": ["RSA"], "classification": _TINGGI, "pqc": False,
                "note": "pure-Python RSA"},
        "ecdsa": {"primitives": ["ECDSA", "ECDH"], "classification": _TINGGI, "pqc": False,
                  "note": "pure-Python ECDSA/ECDH"},
        "bcrypt": {"primitives": ["bcrypt"], "classification": _RENDAH, "pqc": False,
                   "note": "password hashing (not quantum-critical)"},
        "argon2-cffi": {"primitives": ["Argon2"], "classification": _INFO, "pqc": False,
                        "note": "password hashing (not quantum-critical)"},
        "passlib": {"primitives": ["bcrypt", "PBKDF2"], "classification": _RENDAH, "pqc": False,
                    "note": "password hashing toolkit"},
        "oqs": {"primitives": ["ML-KEM", "ML-DSA"], "classification": _PQC, "pqc": True,
                "note": "liboqs binding: ML-KEM/ML-DSA"},
        "liboqs-python": {"primitives": ["ML-KEM", "ML-DSA"], "classification": _PQC, "pqc": True,
                          "note": "liboqs binding: ML-KEM/ML-DSA"},
        "pqcrypto": {"primitives": ["ML-KEM", "ML-DSA", "SPHINCS+"], "classification": _PQC, "pqc": True,
                     "note": "PQClean binding"},
        "kyber-py": {"primitives": ["ML-KEM"], "classification": _PQC, "pqc": True,
                     "note": "pure-Python ML-KEM (Kyber)"},
        "dilithium-py": {"primitives": ["ML-DSA"], "classification": _PQC, "pqc": True,
                         "note": "pure-Python ML-DSA (Dilithium)"},
    },
    "npm": {
        "node-forge": {"primitives": ["RSA", "AES", "DES", "3DES"],
                       "classification": _TINGGI, "pqc": False,
                       "note": "RSA plus legacy DES/3DES available"},
        "crypto-js": {"primitives": ["MD5", "DES", "RC4", "AES"],
                      "classification": _TINGGI, "pqc": False,
                      "note": "broken MD5/DES/RC4 available"},
        "elliptic": {"primitives": ["ECDSA", "ECDH"], "classification": _TINGGI, "pqc": False,
                     "note": "secp256k1/EC (Shor-breakable)"},
        "tweetnacl": {"primitives": ["X25519", "Ed25519"], "classification": _TINGGI, "pqc": False,
                      "note": "NaCl port: X25519/Ed25519"},
        "jsrsasign": {"primitives": ["RSA", "ECDSA"], "classification": _TINGGI, "pqc": False,
                      "note": "RSA/ECDSA JWT+X.509 toolkit"},
        "bcryptjs": {"primitives": ["bcrypt"], "classification": _INFO, "pqc": False,
                     "note": "password hashing (not quantum-critical)"},
        "bcrypt": {"primitives": ["bcrypt"], "classification": _INFO, "pqc": False,
                   "note": "password hashing (not quantum-critical)"},
        "pqclean": {"primitives": ["ML-KEM", "ML-DSA", "SPHINCS+"], "classification": _PQC, "pqc": True,
                    "note": "PQClean WASM/native bindings"},
        "kyber-crystals": {"primitives": ["ML-KEM"], "classification": _PQC, "pqc": True,
                           "note": "ML-KEM (Kyber)"},
        "@noble/post-quantum": {"primitives": ["ML-KEM", "ML-DSA", "SLH-DSA"],
                                "classification": _PQC, "pqc": True,
                                "note": "audited PQC: ML-KEM/ML-DSA/SLH-DSA"},
    },
    "golang": {
        "golang.org/x/crypto": {"primitives": ["curve25519", "ed25519"],
                                "classification": _TINGGI, "pqc": False,
                                "note": "curve25519/ed25519 (Shor-breakable)"},
        "github.com/cloudflare/circl": {"primitives": ["ML-KEM", "ML-DSA", "X25519", "ECDSA"],
                                        "classification": _PQC, "pqc": True,
                                        "note": "PQC (ML-KEM/ML-DSA) plus classical curves"},
        "filippo.io/edwards25519": {"primitives": ["ed25519"], "classification": _TINGGI, "pqc": False,
                                    "note": "edwards25519 group ops (Shor-breakable)"},
        "filippo.io/mlkem768": {"primitives": ["ML-KEM"], "classification": _PQC, "pqc": True,
                                "note": "ML-KEM-768"},
    },
    "cargo": {
        "ring": {"primitives": ["RSA", "ECDSA", "Ed25519", "AES"], "classification": _TINGGI, "pqc": False,
                 "note": "RSA/ECDSA/Ed25519 (Shor-breakable)"},
        "openssl": {"primitives": ["RSA", "ECDSA", "DH"], "classification": _TINGGI, "pqc": False,
                    "note": "OpenSSL binding: RSA/ECDSA/DH"},
        "rsa": {"primitives": ["RSA"], "classification": _TINGGI, "pqc": False,
                "note": "pure-Rust RSA"},
        "ed25519-dalek": {"primitives": ["Ed25519"], "classification": _TINGGI, "pqc": False,
                          "note": "Ed25519 signatures (Shor-breakable)"},
        "x25519-dalek": {"primitives": ["X25519"], "classification": _TINGGI, "pqc": False,
                         "note": "X25519 key agreement (Shor-breakable)"},
        "p256": {"primitives": ["ECDSA", "ECDH"], "classification": _TINGGI, "pqc": False,
                 "note": "NIST P-256 ECDSA/ECDH"},
        "pqcrypto": {"primitives": ["ML-KEM", "ML-DSA", "SPHINCS+"], "classification": _PQC, "pqc": True,
                     "note": "PQClean crates: ML-KEM/ML-DSA"},
        "oqs": {"primitives": ["ML-KEM", "ML-DSA"], "classification": _PQC, "pqc": True,
                "note": "liboqs binding: ML-KEM/ML-DSA"},
        "ml-kem": {"primitives": ["ML-KEM"], "classification": _PQC, "pqc": True,
                   "note": "RustCrypto ML-KEM"},
    },
    "maven": {
        # Maven keys are artifactId prefixes (startswith match).
        "bcpqc": {"primitives": ["ML-KEM", "ML-DSA", "SPHINCS+"], "classification": _PQC, "pqc": True,
                  "note": "BouncyCastle PQC provider"},
        "bcprov": {"primitives": ["RSA", "ECDSA", "DH", "AES"], "classification": _TINGGI, "pqc": False,
                   "note": "RSA/ECDSA by default; PQC available only via the bcpqc provider"},
        "bcpkix": {"primitives": ["RSA", "ECDSA"], "classification": _TINGGI, "pqc": False,
                   "note": "X.509/CMS over RSA/ECDSA"},
        "bctls": {"primitives": ["RSA", "ECDSA", "DH"], "classification": _TINGGI, "pqc": False,
                  "note": "TLS over RSA/ECDSA/DH"},
        "bouncycastle": {"primitives": ["RSA", "ECDSA", "DH"], "classification": _TINGGI, "pqc": False,
                         "note": "RSA/ECDSA by default; PQC available only via the bcpqc provider"},
    },
}

# --- manifest discovery ----------------------------------------------------
_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_REQ_VER_RE = re.compile(r"==\s*([A-Za-z0-9][A-Za-z0-9.\-_+*]*)")
_PEP508_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_GOMOD_RE = re.compile(r"^([a-zA-Z0-9.\-_/]+\.[a-zA-Z0-9.\-_/]+)\s+v(\S+)")

# purl namespace per ecosystem
_PURL_TYPE = {"pypi": "pypi", "npm": "npm", "golang": "golang", "cargo": "cargo", "maven": "maven"}


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _lookup(ecosystem: str, name: str) -> tuple[str, LibInfo] | None:
    table = CRYPTO_LIBRARY_MAP.get(ecosystem)
    if not table:
        return None
    n = _norm(name)
    hit = table.get(n)
    if hit is not None:
        return n, hit
    if ecosystem == "maven":
        for key, info in table.items():
            if n.startswith(key):
                return key, info
    return None


def _parse_requirements(text: str) -> list[tuple[str, str | None]]:
    deps: list[tuple[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line:
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        vm = _REQ_VER_RE.search(m.group(2))
        deps.append((m.group(1), vm.group(1) if vm else None))
    return deps


def _parse_pep508_list(items: list[object]) -> list[tuple[str, str | None]]:
    deps: list[tuple[str, str | None]] = []
    for item in items:
        if not isinstance(item, str):
            continue
        m = _PEP508_RE.match(item.strip())
        if not m:
            continue
        vm = _REQ_VER_RE.search(m.group(2))
        deps.append((m.group(1), vm.group(1) if vm else None))
    return deps


def _parse_pyproject(text: str) -> list[tuple[str, str | None]]:
    data = tomllib.loads(text)
    deps: list[tuple[str, str | None]] = []
    project = data.get("project")
    if isinstance(project, dict):
        pdeps = project.get("dependencies")
        if isinstance(pdeps, list):
            deps.extend(_parse_pep508_list(pdeps))
        opt = project.get("optional-dependencies")
        if isinstance(opt, dict):
            for group in opt.values():
                if isinstance(group, list):
                    deps.extend(_parse_pep508_list(group))
    poetry = data.get("tool", {})
    if isinstance(poetry, dict):
        pd = poetry.get("poetry", {})
        if isinstance(pd, dict):
            table = pd.get("dependencies")
            if isinstance(table, dict):
                for name, spec in table.items():
                    ver = spec if isinstance(spec, str) else None
                    deps.append((name, ver))
    return deps


def _parse_package_json(text: str) -> list[tuple[str, str | None]]:
    data = json.loads(text)
    deps: list[tuple[str, str | None]] = []
    if not isinstance(data, dict):
        return deps
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        table = data.get(key)
        if isinstance(table, dict):
            for name, ver in table.items():
                deps.append((name, ver if isinstance(ver, str) else None))
    return deps


def _parse_go_mod(text: str) -> list[tuple[str, str | None]]:
    deps: list[tuple[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line or line in ("require (", ")"):
            continue
        line = line.removeprefix("require ").strip()
        m = _GOMOD_RE.match(line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _cargo_dep_version(spec: object) -> str | None:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        ver = spec.get("version")
        return ver if isinstance(ver, str) else None
    return None


def _parse_cargo_toml(text: str) -> list[tuple[str, str | None]]:
    data = tomllib.loads(text)
    deps: list[tuple[str, str | None]] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = data.get(key)
        if isinstance(table, dict):
            for name, spec in table.items():
                deps.append((name, _cargo_dep_version(spec)))
    return deps


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_pom(text: str) -> list[tuple[str, str | None]]:
    deps: list[tuple[str, str | None]] = []
    root = ET.fromstring(text)
    for el in root.iter():
        if _local_tag(el.tag) != "dependency":
            continue
        artifact_id: str | None = None
        version: str | None = None
        for child in el:
            lt = _local_tag(child.tag)
            if lt == "artifactId":
                artifact_id = (child.text or "").strip()
            elif lt == "version":
                version = (child.text or "").strip() or None
        if artifact_id:
            deps.append((artifact_id, version))
    return deps


# filename -> (ecosystem, parser)
_MANIFESTS: tuple[tuple[str, str, object], ...] = (
    ("requirements.txt", "pypi", _parse_requirements),
    ("pyproject.toml", "pypi", _parse_pyproject),
    ("package.json", "npm", _parse_package_json),
    ("go.mod", "golang", _parse_go_mod),
    ("Cargo.toml", "cargo", _parse_cargo_toml),
    ("pom.xml", "maven", _parse_pom),
)


class SbomCryptoMap(Probe):
    id = "sbom.crypto_map"
    family = ProbeFamily.SBOM
    framework_tags = ("nist-ir-8547:sbom", "mykripto:sbom")

    def __init__(self, roots: list[Path] | None = None):
        self._roots = roots

    async def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.scan_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        roots = self._roots if self._roots is not None else ctx.scan_paths
        seen: set[tuple[str, str]] = set()
        for root in roots:
            if not root.is_dir():
                continue
            for fname, ecosystem, parser in _MANIFESTS:
                for path in root.rglob(fname):
                    try:
                        text = path.read_text(encoding="utf-8", errors="replace")
                        deps = parser(text)  # type: ignore[operator]
                    except Exception:
                        continue
                    for name, version in deps:
                        match = _lookup(ecosystem, name)
                        if match is None:
                            continue
                        _canonical, info = match
                        purl = f"pkg:{_PURL_TYPE[ecosystem]}/{name}"
                        key = (str(path), purl)
                        if key in seen:
                            continue
                        seen.add(key)
                        cls = info["classification"]
                        primitives = "/".join(info["primitives"])
                        kind = "post-quantum" if info["pqc"] else "classical"
                        emit(Finding(
                            probe_id=self.id,
                            algorithm=purl,
                            classification=cls,
                            severity=sev_for(cls),
                            title=f"dependency `{name}` provides {kind} crypto primitives ({primitives})",
                            component_purl=purl,
                            evidence={
                                "path": str(path),
                                "ecosystem": ecosystem,
                                "version": version,
                                "primitives": info["primitives"],
                                "note": info["note"],
                                "pqc": info["pqc"],
                            },
                        ))

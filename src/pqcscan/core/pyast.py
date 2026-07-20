"""Stdlib-`ast` crypto analyzer for Python source (zero native deps).

Unlike a regex scan, this walks the parsed abstract syntax tree, so matches
inside comments and string literals are *invisible* to it — that is the whole
point. A `# hashlib.md5()` comment or `x = "hashlib.md5()"` literal produces
zero hits because neither is a real Call/Attribute node.

Detection is *name-accurate*, not *string-accurate*: imports and aliases are
resolved first (`import hashlib as h`, `from hashlib import md5`,
`from Crypto.Cipher import DES`, …) so that a call is only flagged when the
name genuinely resolves to the crypto symbol we care about.

The analyzer is deliberately decoupled from the finding model: it returns
`AstHit` records carrying a machine `kind` + `algorithm` + human `detail`, and
leaves the `kind → (Classification, Severity)` mapping to the probe.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

# hashlib.new("<name>") string arguments we treat as weak digests.
_WEAK_NEW_HASHES = {"md5", "sha1", "md4", "md2"}

# PyCryptodome cipher class -> (algorithm, kind).
_PYCRYPTO_CIPHERS = {
    "DES": ("DES", "des_cipher"),
    "DES3": ("3DES", "des_cipher"),
    "ARC4": ("RC4", "rc4_cipher"),
    "Blowfish": ("Blowfish", "blowfish_cipher"),
}

# cryptography `algorithms.<X>` classical cipher primitives.
_HAZMAT_ALGORITHMS = {
    "TripleDES": ("3DES", "des_cipher"),
    "ARC4": ("RC4", "rc4_cipher"),
    "Blowfish": ("Blowfish", "blowfish_cipher"),
}

# ssl.PROTOCOL_* legacy/weak protocol constants -> algorithm label.
_WEAK_TLS_PROTOCOLS = {
    "PROTOCOL_TLSv1": "TLSv1",
    "PROTOCOL_TLSv1_1": "TLSv1.1",
    "PROTOCOL_SSLv3": "SSLv3",
    "PROTOCOL_SSLv23": "SSLv23",
}


@dataclass(frozen=True)
class AstHit:
    lineno: int
    algorithm: str  # e.g. "MD5", "RSA-2048", "DES", "TLSv1"
    kind: str  # short machine tag, e.g. "weak_hash", "rsa_keygen", "des_cipher"
    detail: str  # human sentence for the finding title
    weak: bool  # True if this is a finding (all returned hits are weak)


class _Analyzer:
    """Resolves imports, then walks the tree collecting weak-crypto hits."""

    def __init__(self) -> None:
        # Local name -> canonical dotted symbol, built from the import table.
        #   import hashlib            -> {"hashlib": "hashlib"}
        #   import hashlib as h       -> {"h": "hashlib"}
        #   from hashlib import md5   -> {"md5": "hashlib.md5"}
        #   from Crypto.Cipher import DES -> {"DES": "Crypto.Cipher.DES"}
        self._symbols: dict[str, str] = {}
        self.hits: list[AstHit] = []

    # -- import resolution ------------------------------------------------

    def collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    self._symbols[local] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self._symbols[local] = f"{node.module}.{alias.name}"

    def _resolve(self, node: ast.expr) -> str | None:
        """Return the canonical dotted symbol for an attribute/name chain."""
        if isinstance(node, ast.Name):
            return self._symbols.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            prefix = self._resolve(node.value)
            if prefix is None:
                return None
            return f"{prefix}.{node.attr}"
        return None

    # -- walk -------------------------------------------------------------

    def walk(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._visit_call(node)
            elif isinstance(node, ast.Attribute):
                self._visit_attribute(node)

    def _visit_attribute(self, node: ast.Attribute) -> None:
        # Weak/legacy TLS protocol constants: attribute access is enough.
        if node.attr in _WEAK_TLS_PROTOCOLS:
            canon = self._resolve(node)
            if canon and _tail(canon, 2) == ("ssl", node.attr):
                algo = _WEAK_TLS_PROTOCOLS[node.attr]
                self.hits.append(AstHit(
                    lineno=node.lineno, algorithm=algo, kind="weak_tls_proto",
                    detail=f"legacy TLS/SSL protocol constant ssl.{node.attr} ({algo})",
                    weak=True,
                ))

    def _visit_call(self, node: ast.Call) -> None:
        canon = self._resolve(node.func)
        if canon is None:
            return
        parts = canon.split(".")
        last = parts[-1]
        obj = parts[-2] if len(parts) >= 2 else ""

        # -- weak hashes --------------------------------------------------
        if canon in ("hashlib.md5", "hashlib.sha1"):
            algo = last.upper()
            self.hits.append(AstHit(
                node.lineno, algo, "weak_hash",
                f"{algo} weak hash via hashlib.{last}()", True,
            ))
            return
        if canon == "hashlib.new":
            name = _const_str(node.args[0]) if node.args else None
            if name and name.lower() in _WEAK_NEW_HASHES:
                algo = name.upper()
                self.hits.append(AstHit(
                    node.lineno, algo, "weak_hash",
                    f'{algo} weak hash via hashlib.new("{name}")', True,
                ))
            return

        # -- RSA keygen ---------------------------------------------------
        if obj == "rsa" and last == "generate_private_key":
            self._emit_rsa(node, keyword="key_size")
            return
        if obj == "RSA" and last == "generate":
            self._emit_rsa(node, positional=0)
            return

        # -- DSA keygen ---------------------------------------------------
        if obj == "dsa" and last == "generate_private_key":
            self.hits.append(AstHit(node.lineno, "DSA", "dsa_keygen",
                                    "DSA key generation (cryptography)", True))
            return
        if obj == "DSA" and last == "generate":
            self.hits.append(AstHit(node.lineno, "DSA", "dsa_keygen",
                                    "DSA key generation (PyCryptodome)", True))
            return

        # -- EC keygen (classical, quantum-vulnerable) --------------------
        if obj == "ec" and last == "generate_private_key":
            curve = self._ec_curve(node)
            algo = f"EC-{curve}" if curve else "EC"
            self.hits.append(AstHit(
                node.lineno, algo, "ecdsa_keygen",
                f"classical EC key generation ({algo}) — quantum-vulnerable", True,
            ))
            return

        # -- PyCryptodome DES/3DES/RC4/Blowfish .new() --------------------
        if last == "new" and obj in _PYCRYPTO_CIPHERS:
            algo, kind = _PYCRYPTO_CIPHERS[obj]
            self.hits.append(AstHit(node.lineno, algo, kind,
                                    f"{algo} cipher via {obj}.new()", True))
            return

        # -- PyCryptodome AES.new(..., AES.MODE_CBC, ...) -----------------
        if last == "new" and obj == "AES":
            if self._has_mode_cbc(node):
                self.hits.append(AstHit(node.lineno, "AES-CBC", "aes_cbc",
                                        "AES-CBC mode (prefer AES-GCM)", True))
            return

        # -- cryptography algorithms.<cipher>(...) ------------------------
        if obj == "algorithms" and last in _HAZMAT_ALGORITHMS:
            algo, kind = _HAZMAT_ALGORITHMS[last]
            self.hits.append(AstHit(node.lineno, algo, kind,
                                    f"{algo} cipher via algorithms.{last}()", True))
            return

        # -- cryptography modes.CBC(...) ----------------------------------
        if obj == "modes" and last == "CBC":
            self.hits.append(AstHit(node.lineno, "AES-CBC", "aes_cbc",
                                    "AES-CBC mode via modes.CBC() (prefer AES-GCM)", True))
            return

    # -- helpers ----------------------------------------------------------

    def _emit_rsa(self, node: ast.Call, *, keyword: str | None = None,
                  positional: int | None = None) -> None:
        bits: int | None = None
        if keyword is not None:
            for kw in node.keywords:
                if kw.arg == keyword:
                    bits = _const_int(kw.value)
        if bits is None and positional is not None and len(node.args) > positional:
            bits = _const_int(node.args[positional])
        if bits is not None:
            self.hits.append(AstHit(node.lineno, f"RSA-{bits}", "rsa_keygen",
                                    f"RSA key generation, key_size={bits}", True))
        else:
            self.hits.append(AstHit(node.lineno, "RSA", "rsa_keygen",
                                    "RSA key generation (non-literal key_size)", True))

    def _ec_curve(self, node: ast.Call) -> str | None:
        if not node.args:
            return None
        arg = node.args[0]
        func = arg.func if isinstance(arg, ast.Call) else arg
        if isinstance(func, ast.Attribute):
            return func.attr
        if isinstance(func, ast.Name):
            return func.id
        return None

    def _has_mode_cbc(self, node: ast.Call) -> bool:
        candidates: list[ast.expr] = list(node.args) + [kw.value for kw in node.keywords]
        return any(isinstance(arg, ast.Attribute) and arg.attr == "MODE_CBC" for arg in candidates)


def _const_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _const_int(node: ast.expr) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _tail(canon: str, n: int) -> tuple[str, ...]:
    return tuple(canon.split(".")[-n:])


def analyze(source: str) -> list[AstHit]:
    """Parse `source` and return the weak-crypto hits found in the AST.

    Raises `SyntaxError` (propagated from `ast.parse`) when the source is not
    valid Python — callers should catch it and fall back to a regex scan.
    """
    tree = ast.parse(source)
    analyzer = _Analyzer()
    analyzer.collect_imports(tree)
    analyzer.walk(tree)
    return analyzer.hits

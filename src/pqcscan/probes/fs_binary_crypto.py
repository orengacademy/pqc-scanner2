"""fs.binary.crypto — crypto-library scanner for compiled binaries (no source).

Closes the "binary scanning" gap that commercial PQC tools (InfoSec Global /
Keyfactor, open-quantum-secure's binary-scanner) cover: given a stripped
executable or shared library with no accompanying source or package manifest,
work out which cryptographic library it ships or links against.

Walks ctx.scan_paths for regular files, sniffs each file's first bytes for an
executable magic, and — using only the standard library, parsing the container
formats by hand with `struct` — pulls out:

- ELF   (`\\x7fELF`) — the `.dynamic` section's DT_NEEDED entries (needed shared
          libraries) resolved through the `.dynstr` string table. ELFCLASS32 and
          ELFCLASS64, little-endian primarily, big-endian best-effort.
- PE     (`MZ` … `PE\\x00\\x00`) — the import directory's imported DLL names.
- Mach-O (`\\xcf\\xfa\\xed\\xfe` / `\\xfe\\xed\\xfa\\xcf` / fat `\\xca\\xfe\\xba\\xbe`)
          — LC_LOAD_DYLIB (and weak/reexport/upward variants) linked dylib names.

Linked library names are matched against a curated crypto-library table
(OpenSSL, GnuTLS, NSS, libsodium, mbed TLS, wolfSSL, libgcrypt, Botan, and the
Windows CNG / macOS Security stacks) — those matches are high-confidence.

In addition a bounded string scan of the first ~2 MiB looks for embedded crypto
version banners (`OpenSSL 3.0.x`, `BoringSSL`, `GnuTLS`, `libsodium`, `mbed TLS`,
`wolfSSL`) so a *statically* linked crypto stack is still caught — those matches
are medium-confidence.

Classification: a pre-PQC crypto stack (OpenSSL < 3.5, or an unknown version) →
SEDERHANA ("classical crypto stack, no PQC by default"); OpenSSL >= 3.5, which
ships the hybrid X25519MLKEM768 group by default, → PQC_READY (a positive).

Every read/parse is guarded — a truncated, malformed, or non-binary file yields
no findings and never raises. Findings are de-duplicated per (path, library) and
capped per scan; when the cap is hit a truncation note is emitted.
"""
from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

# Cap total findings so a directory full of binaries can't emit unbounded rows.
_MAX_FINDINGS = 500

# Read at most this many bytes of any one file (structural parse + string scan).
# Keeps memory bounded on a self-contained scanner; larger files are truncated,
# and the guarded parsers simply yield less rather than raising.
_MAX_FILE_BYTES = 96 * 1024 * 1024
# Bounded window for the printable-string banner scan.
_STRING_SCAN_BYTES = 2 * 1024 * 1024

# Directories never worth walking for shipped binaries.
_EXCLUDE_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".gradle", ".m2", ".cargo", ".bundle",
})

# --- crypto-library table -------------------------------------------------
# Ordered (needle, library-id) rules, matched as substrings against the
# lower-cased linked-library / DLL / dylib name (or full dylib path for the
# framework entries). First hit wins; order matters where one needle is a
# prefix of another.
_LIB_RULES: tuple[tuple[str, str], ...] = (
    ("libssl", "openssl"),
    ("libcrypto", "openssl"),      # incl. Windows libcrypto-3-x64.dll
    ("libeay32", "openssl"),
    ("ssleay32", "openssl"),
    ("boringssl", "boringssl"),
    ("gnutls", "gnutls"),
    ("libnss3", "nss"),
    ("nss3.dll", "nss"),
    ("libnss", "nss"),
    ("libsodium", "libsodium"),
    ("mbedcrypto", "mbedtls"),
    ("mbedtls", "mbedtls"),
    ("libwolfssl", "wolfssl"),
    ("wolfssl", "wolfssl"),
    ("libgcrypt", "libgcrypt"),
    ("libbotan", "botan"),
    ("botan", "botan"),
    ("commoncrypto", "commoncrypto"),
    ("security.framework", "security-framework"),
    ("bcrypt.dll", "bcrypt"),
    ("ncrypt.dll", "ncrypt"),
    ("crypt32.dll", "crypt32"),
)


def _match_lib(raw: str) -> str | None:
    """Return the crypto-library id for a linked-library name, or None."""
    low = raw.lower()
    for needle, lib_id in _LIB_RULES:
        if needle in low:
            return lib_id
    return None


# --- embedded version-banner patterns -------------------------------------
# Each entry: (library-id, compiled regex). group(1), when present, captures a
# dotted version. These only match printable ASCII, so scanning the decoded
# byte window is equivalent to scanning extracted string runs.
_BANNER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openssl", re.compile(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")),
    ("boringssl", re.compile(r"BoringSSL")),
    ("gnutls", re.compile(r"GnuTLS(?:[ /]?(\d+\.\d+\.\d+))?")),
    ("libsodium", re.compile(r"libsodium(?:[ /]?(\d+\.\d+\.\d+))?")),
    ("mbedtls", re.compile(r"[Mm]bed ?TLS(?:[ /]?(\d+\.\d+\.\d+))?")),
    ("wolfssl", re.compile(r"wolfSSL(?:[ /]?(\d+\.\d+\.\d+))?")),
)


@dataclass(slots=True)
class _Hit:
    library: str
    fmt: str
    origin: str          # "linked" | "embedded"
    confidence: str      # "high" | "medium"
    version: str | None = None
    detail: str | None = None   # the raw soname/DLL/dylib that matched


# --- version helpers ------------------------------------------------------


def _parse_ver(v: str) -> tuple[int, int]:
    """Best-effort (major, minor) from a dotted version; (0, 0) on failure."""
    parts = re.findall(r"\d+", v)
    major = int(parts[0]) if parts else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    return major, minor


def _classify_lib(lib_id: str, version: str | None) -> tuple[Classification, str]:
    """Map a detected crypto library (+ optional version) to a classification."""
    if lib_id == "openssl" and version is not None and _parse_ver(version) >= (3, 5):
        return (
            Classification.PQC_READY,
            "OpenSSL >= 3.5 ships the hybrid X25519MLKEM768 group by default",
        )
    return Classification.SEDERHANA, "classical crypto stack, no PQC by default"


# --- low-level byte helpers ----------------------------------------------


def _cstr(buf: bytes, start: int, end: int | None = None) -> str:
    """Read a NUL-terminated ASCII string from buf[start:end]."""
    if start < 0 or start >= len(buf):
        return ""
    stop = len(buf) if end is None else min(end, len(buf))
    nul = buf.find(b"\x00", start, stop)
    raw = buf[start:(nul if nul != -1 else stop)]
    return raw.decode("ascii", "ignore")


# --- ELF ------------------------------------------------------------------

_SHT_DYNAMIC = 6
_DT_NEEDED = 1


def _elf_needed(data: bytes) -> list[str]:
    """DT_NEEDED shared-library names from an ELF's .dynamic section."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        return []
    endian = ">" if ei_data == 2 else "<"
    is64 = ei_class == 2
    try:
        if is64:
            (_type, _mach, _ver, _entry, _phoff, e_shoff, _flags, _ehsize,
             _phentsize, _phnum, e_shentsize, e_shnum, _shstrndx) = struct.unpack(
                endian + "HHIQQQIHHHHHH", data[16:64])
        else:
            (_type, _mach, _ver, _entry, _phoff, e_shoff, _flags, _ehsize,
             _phentsize, _phnum, e_shentsize, e_shnum, _shstrndx) = struct.unpack(
                endian + "HHIIIIIHHHHHH", data[16:52])
    except struct.error:
        return []

    sh_entry = 64 if is64 else 40
    sections: list[tuple[int, int, int, int]] = []  # (type, offset, size, link)
    dyn_idx: int | None = None
    for i in range(min(e_shnum, 4096)):
        base = e_shoff + i * e_shentsize
        chunk = data[base:base + sh_entry]
        if len(chunk) < sh_entry:
            break
        try:
            if is64:
                (_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link,
                 _info, _align, _entsize) = struct.unpack(endian + "IIQQQQIIQQ", chunk)
            else:
                (_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link,
                 _info, _align, _entsize) = struct.unpack(endian + "IIIIIIIIII", chunk)
        except struct.error:
            continue
        sections.append((sh_type, sh_offset, sh_size, sh_link))
        if sh_type == _SHT_DYNAMIC and dyn_idx is None:
            dyn_idx = len(sections) - 1

    if dyn_idx is None:
        return []
    # The .dynamic section's sh_link is the index of its associated string
    # table section (.dynstr); DT_NEEDED values are offsets into it.
    _t, dyn_off, dyn_size, dyn_link = sections[dyn_idx]
    if not (0 <= dyn_link < len(sections)):
        return []
    _t2, str_off, str_size, _l2 = sections[dyn_link]
    ent = 16 if is64 else 8
    needed: list[str] = []
    count = min(dyn_size // ent, 8192)
    for i in range(count):
        base = dyn_off + i * ent
        chunk = data[base:base + ent]
        if len(chunk) < ent:
            break
        try:
            d_tag, d_val = struct.unpack(endian + ("qQ" if is64 else "iI"), chunk)
        except struct.error:
            break
        if d_tag == 0:  # DT_NULL — end of dynamic array
            break
        if d_tag == _DT_NEEDED:
            name = _cstr(data, str_off + d_val, str_off + str_size)
            if name:
                needed.append(name)
    return needed


# --- PE -------------------------------------------------------------------


def _pe_imports(data: bytes) -> list[str]:
    """Imported DLL names from a PE image's import directory."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    try:
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    except struct.error:
        return []
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return []
    coff = e_lfanew + 4
    try:
        (_machine, num_sections, _ts, _psym, _nsym, opt_size,
         _chars) = struct.unpack("<HHIIIHH", data[coff:coff + 20])
    except struct.error:
        return []
    opt = coff + 20
    try:
        magic = struct.unpack("<H", data[opt:opt + 2])[0]
    except struct.error:
        return []
    if magic == 0x20B:      # PE32+
        dd_base = opt + 112
    elif magic == 0x10B:    # PE32
        dd_base = opt + 96
    else:
        return []
    try:  # data directory index 1 = import table
        import_rva, _import_size = struct.unpack("<II", data[dd_base + 8:dd_base + 16])
    except struct.error:
        return []
    if import_rva == 0:
        return []

    sec_off = opt + opt_size
    sections: list[tuple[int, int, int, int]] = []  # (vaddr, vsize, rawptr, rawsize)
    for i in range(min(num_sections, 96)):
        chunk = data[sec_off + i * 40:sec_off + i * 40 + 24]
        if len(chunk) < 24:
            break
        try:
            _name, vsize, vaddr, rawsize, rawptr = struct.unpack("<8sIIII", chunk)
        except struct.error:
            break
        sections.append((vaddr, vsize, rawptr, rawsize))

    def rva_to_off(rva: int) -> int | None:
        for vaddr, vsize, rawptr, rawsize in sections:
            span = max(vsize, rawsize)
            if vaddr <= rva < vaddr + span:
                return rawptr + (rva - vaddr)
        return None

    table = rva_to_off(import_rva)
    if table is None:
        return []
    names: list[str] = []
    for i in range(1024):
        base = table + i * 20
        desc = data[base:base + 20]
        if len(desc) < 20:
            break
        try:
            oft, _ts, _fwd, name_rva, first_thunk = struct.unpack("<IIIII", desc)
        except struct.error:
            break
        if oft == 0 and name_rva == 0 and first_thunk == 0:
            break
        noff = rva_to_off(name_rva)
        if noff is not None:
            nm = _cstr(data, noff)
            if nm:
                names.append(nm)
    return names


# --- Mach-O ---------------------------------------------------------------

_MACHO_LE64 = b"\xcf\xfa\xed\xfe"
_MACHO_LE32 = b"\xce\xfa\xed\xfe"
_MACHO_BE64 = b"\xfe\xed\xfa\xcf"
_MACHO_BE32 = b"\xfe\xed\xfa\xce"
_MACHO_FAT = b"\xca\xfe\xba\xbe"
_MACHO_THIN_MAGICS = frozenset({_MACHO_LE64, _MACHO_LE32, _MACHO_BE64, _MACHO_BE32})
_LC_DYLIB_CMDS = frozenset({0x0C, 0x1F, 0x80000018, 0x80000023})  # LOAD/REEXPORT/WEAK/UPWARD


def _macho_dylibs(data: bytes) -> list[str]:
    if data[:4] == _MACHO_FAT:
        try:
            nfat = struct.unpack(">I", data[4:8])[0]
        except struct.error:
            return []
        if nfat == 0:
            return []
        try:  # first fat_arch: cputype, cpusubtype, offset, size, align
            _cpu, _sub, offset, size, _align = struct.unpack(">IIIII", data[8:28])
        except struct.error:
            return []
        if offset == 0 or offset >= len(data):
            return []
        return _macho_thin(data[offset:offset + size])
    return _macho_thin(data)


def _macho_thin(data: bytes) -> list[str]:
    if len(data) < 28:
        return []
    magic = data[:4]
    if magic not in _MACHO_THIN_MAGICS:
        return []
    endian = "<" if magic in (_MACHO_LE64, _MACHO_LE32) else ">"
    is64 = magic in (_MACHO_LE64, _MACHO_BE64)
    hdr_size = 32 if is64 else 28
    try:
        # after magic: cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
        fields = struct.unpack(endian + "IIIIII", data[4:28])
    except struct.error:
        return []
    ncmds = fields[3]
    off = hdr_size
    names: list[str] = []
    for _ in range(min(ncmds, 10000)):
        if off + 8 > len(data):
            break
        try:
            cmd, cmdsize = struct.unpack(endian + "II", data[off:off + 8])
        except struct.error:
            break
        if cmdsize < 8:
            break
        if cmd in _LC_DYLIB_CMDS and off + 12 <= len(data):
            try:
                name_off = struct.unpack(endian + "I", data[off + 8:off + 12])[0]
            except struct.error:
                name_off = 0
            if 0 < name_off < cmdsize:
                nm = _cstr(data, off + name_off, off + cmdsize)
                if nm:
                    names.append(nm)
        off += cmdsize
    return names


# --- format detection + string scan ---------------------------------------


def _detect_format(data: bytes) -> str | None:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == _MACHO_FAT or data[:4] in _MACHO_THIN_MAGICS:
        return "macho"
    return None


def _scan_banners(data: bytes) -> list[tuple[str, str | None]]:
    """Find embedded crypto version banners in the first window of the file."""
    text = data[:_STRING_SCAN_BYTES].decode("latin-1", "ignore")
    out: list[tuple[str, str | None]] = []
    for lib_id, rx in _BANNER_PATTERNS:
        m = rx.search(text)
        if m is None:
            continue
        version = m.group(1) if rx.groups else None
        out.append((lib_id, version))
    return out


# --- probe ----------------------------------------------------------------


class FsBinaryCrypto(Probe):
    """Scan compiled binaries (no source) for the crypto libraries they link/ship."""

    id = "fs.binary.crypto"
    family = ProbeFamily.SBOM
    framework_tags = ("nist-ir-8547:sbom", "mykripto:sbom")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots

    async def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.scan_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        roots = self.roots if self.roots is not None else ctx.scan_paths
        emitted = 0
        capped = False
        for path in _iter_files(roots):
            if capped:
                break
            try:
                hits = self._scan_file(path)
            except Exception:  # pragma: no cover — defensive backstop, never raise
                continue
            for hit in hits:
                if emitted >= _MAX_FINDINGS:
                    capped = True
                    break
                emit(_finding(self.id, path, hit))
                emitted += 1
        if capped:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=sev_for(Classification.INFO),
                title=f"finding cap ({_MAX_FINDINGS}) reached — binary crypto output truncated",
                evidence={"cap": _MAX_FINDINGS},
            ))

    def _scan_file(self, path: Path) -> list[_Hit]:
        data = _read(path)
        if data is None:
            return []
        fmt = _detect_format(data)
        if fmt is None:  # not a binary we recognise — skip (no banner scan)
            return []

        try:
            if fmt == "elf":
                linked = _elf_needed(data)
            elif fmt == "pe":
                linked = _pe_imports(data)
            else:
                linked = _macho_dylibs(data)
        except Exception:  # pragma: no cover — parsers are already guarded
            linked = []

        hits: dict[str, _Hit] = {}
        for raw in linked:
            lib_id = _match_lib(raw)
            if lib_id is not None and lib_id not in hits:
                hits[lib_id] = _Hit(library=lib_id, fmt=fmt, origin="linked",
                                    confidence="high", detail=raw)
        try:
            banners = _scan_banners(data)
        except Exception:  # pragma: no cover
            banners = []
        for lib_id, version in banners:
            existing = hits.get(lib_id)
            if existing is not None:
                if existing.version is None and version is not None:
                    existing.version = version  # upgrade a linked hit with a real version
                continue
            hits[lib_id] = _Hit(library=lib_id, fmt=fmt, origin="embedded",
                                confidence="medium", version=version)
        return list(hits.values())


def _finding(probe_id: str, path: Path, hit: _Hit) -> Finding:
    cls, note = _classify_lib(hit.library, hit.version)
    algorithm = f"pkg:generic/{hit.library}@{hit.version}" if hit.version is not None else hit.library
    purl = (f"pkg:generic/{hit.library}@{hit.version}"
            if hit.version is not None else f"pkg:generic/{hit.library}")
    linked = "linked" if hit.origin == "linked" else "embedded"
    evidence: dict[str, object] = {
        "path": str(path),
        "format": hit.fmt,
        "linked": linked,
        "library": hit.library,
        "version": hit.version,
        "note": note,
    }
    if hit.detail is not None:
        evidence["matched"] = hit.detail
    if hit.origin == "embedded":
        evidence["confidence"] = "medium"
    return Finding(
        probe_id=probe_id,
        algorithm=algorithm,
        classification=cls,
        severity=sev_for(cls),
        title=f"{path.name}: {hit.library} crypto library ({linked}) — {note}",
        component_purl=purl,
        evidence=evidence,
        confidence=hit.confidence,
    )


def _read(path: Path) -> bytes | None:
    try:
        with path.open("rb") as fh:
            return fh.read(_MAX_FILE_BYTES)
    except OSError:
        return None


def _iter_files(roots: list[Path]) -> Iterator[Path]:
    for root in roots:
        try:
            if root.is_file():
                yield root
                continue
            if not root.is_dir():
                continue
            for p in root.rglob("*"):
                try:
                    if any(part in _EXCLUDE_DIRS for part in p.parts):
                        continue
                    if p.is_symlink() or not p.is_file():
                        continue
                except OSError:
                    continue
                yield p
        except OSError:
            continue

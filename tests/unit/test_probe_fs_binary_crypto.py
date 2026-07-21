"""Tests for fs.binary.crypto — crypto-library scanner for compiled binaries.

Every fixture is hand-built with `struct` (no external binaries and no
dependency on the probe's own parsers), so the test proves the probe reads the
same bytes a real linker/toolchain would emit: a minimal ELF64 whose `.dynamic`
carries a DT_NEEDED for `libcrypto.so.3`, a minimal PE importing `bcrypt.dll`, a
minimal Mach-O with an LC_LOAD_DYLIB, and tiny binaries carrying embedded
OpenSSL version banners.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_binary_crypto import FsBinaryCrypto

# --- harness --------------------------------------------------------------


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(),
                       scan_paths=[tmp_path])


async def _run(tmp_path: Path) -> list:
    found: list = []
    await FsBinaryCrypto().run(_ctx(tmp_path), emit=found.append)
    return found


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# --- ELF64 fixture builder ------------------------------------------------
#
# Layout (all little-endian):
#   [0x00 .. 0x40)  ELF header
#   dynstr section  b"\x00" + b"libcrypto.so.3\x00"   (string at offset 1)
#   dynamic section two Elf64_Dyn entries: DT_NEEDED(val=1), DT_NULL
#   section header table: [SHT_NULL, .dynstr(STRTAB), .dynamic(DYNAMIC)]
# The .dynamic section header's sh_link points at the .dynstr section index.


def _elf64_with_needed(soname: bytes = b"libcrypto.so.3") -> bytes:
    dynstr = b"\x00" + soname + b"\x00"          # NEEDED name starts at offset 1
    dynamic = struct.pack("<qQ", 1, 1)           # DT_NEEDED, val = strtab offset 1
    dynamic += struct.pack("<qQ", 0, 0)          # DT_NULL

    ehdr_size = 64
    off_dynstr = ehdr_size
    off_dynamic = off_dynstr + len(dynstr)
    off_sh = off_dynamic + len(dynamic)
    sh_entry = 64
    e_shnum = 3
    dynstr_idx = 1

    def shdr(sh_type: int, sh_offset: int, sh_size: int, sh_link: int, sh_entsize: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            0,          # sh_name
            sh_type,
            0,          # sh_flags
            0,          # sh_addr
            sh_offset,
            sh_size,
            sh_link,
            0,          # sh_info
            0,          # sh_addralign
            sh_entsize,
        )

    shtab = b"".join((
        shdr(0, 0, 0, 0, 0),                                  # 0: SHT_NULL
        shdr(3, off_dynstr, len(dynstr), 0, 0),               # 1: .dynstr (STRTAB)
        shdr(6, off_dynamic, len(dynamic), dynstr_idx, 16),   # 2: .dynamic (DYNAMIC)
    ))

    e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9     # ELFCLASS64, ELFDATA2LSB
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        0x3E,       # e_machine = x86-64
        1,          # e_version
        0,          # e_entry
        0,          # e_phoff
        off_sh,     # e_shoff
        0,          # e_flags
        ehdr_size,  # e_ehsize
        0,          # e_phentsize
        0,          # e_phnum
        sh_entry,   # e_shentsize
        e_shnum,    # e_shnum
        0,          # e_shstrndx
    )
    assert len(ehdr) == ehdr_size
    return ehdr + dynstr + dynamic + shtab


# --- ELF64 fixture builder with a .dynsym symbol table --------------------
#
# Extends the DT_NEEDED fixture with a .dynsym (SHT_DYNSYM) section and its
# linked symbol string table, so the probe's reachability check has real
# imported (SHN_UNDEF) symbols to intersect against.
#
# Sections: [NULL, .dynstr, .dynamic->.dynstr, .dynsym->symstr, symstr]


def _elf64_with_symbols(
    soname: bytes = b"libssl.so.3",
    symbols: tuple[bytes, ...] = (b"EVP_EncryptInit_ex",),
) -> bytes:
    dynstr = b"\x00" + soname + b"\x00"           # DT_NEEDED name at offset 1
    dynamic = struct.pack("<qQ", 1, 1)            # DT_NEEDED, val = strtab offset 1
    dynamic += struct.pack("<qQ", 0, 0)           # DT_NULL

    # Symbol string table + one UNDEF symbol per requested name (st_shndx = 0).
    symstr = b"\x00"
    sym_offsets: list[int] = []
    for s in symbols:
        sym_offsets.append(len(symstr))
        symstr += s + b"\x00"
    # Elf64_Sym: st_name u32, st_info u8, st_other u8, st_shndx u16,
    #            st_value u64, st_size u64  ("<IBBHQQ", 24 bytes).
    symtab = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)   # index 0: null symbol
    for off in sym_offsets:
        symtab += struct.pack("<IBBHQQ", off, 0, 0, 0, 0, 0)  # SHN_UNDEF import

    ehdr_size = 64
    off_dynstr = ehdr_size
    off_dynamic = off_dynstr + len(dynstr)
    off_symstr = off_dynamic + len(dynamic)
    off_symtab = off_symstr + len(symstr)
    off_sh = off_symtab + len(symtab)
    sh_entry = 64
    e_shnum = 5
    dynstr_idx = 1
    symstr_idx = 4

    def shdr(sh_type: int, sh_offset: int, sh_size: int, sh_link: int, sh_entsize: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            0, sh_type, 0, 0, sh_offset, sh_size, sh_link, 0, 0, sh_entsize,
        )

    shtab = b"".join((
        shdr(0, 0, 0, 0, 0),                                        # 0: SHT_NULL
        shdr(3, off_dynstr, len(dynstr), 0, 0),                     # 1: .dynstr
        shdr(6, off_dynamic, len(dynamic), dynstr_idx, 16),         # 2: .dynamic
        shdr(11, off_symtab, len(symtab), symstr_idx, 24),          # 3: .dynsym
        shdr(3, off_symstr, len(symstr), 0, 0),                     # 4: symstr
    ))

    e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9           # ELFCLASS64 LSB
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0, 0, off_sh, 0, ehdr_size, 0, 0, sh_entry, e_shnum, 0,
    )
    assert len(ehdr) == ehdr_size
    return ehdr + dynstr + dynamic + symstr + symtab + shtab


# --- PE fixture builder ---------------------------------------------------
#
# Minimal PE32+ with a single ".idata" section carrying one import descriptor
# (for bcrypt.dll) plus the DLL name string. The import data directory points
# at the descriptor array; the descriptor's Name RVA points at the string.


def _pe_import(dll: bytes = b"bcrypt.dll") -> bytes:
    sect_va = 0x1000
    # Section raw contents: [descriptors...][name string]
    name_rva = sect_va + 40                       # after 2 * 20-byte descriptors
    descriptors = struct.pack("<IIIII", 0, 0, 0, name_rva, 0)  # bcrypt import
    descriptors += struct.pack("<IIIII", 0, 0, 0, 0, 0)        # null terminator
    sect_raw = descriptors + dll + b"\x00"
    sect_raw += b"\x00" * ((-len(sect_raw)) % 0x200)           # pad to file align

    num_sections = 1
    opt_size = 240                                # PE32+ optional header size we emit
    dos = b"MZ" + b"\x00" * 0x3A                  # up to 0x3C
    e_lfanew = 0x40
    dos += struct.pack("<I", e_lfanew)           # 0x3C: e_lfanew -> 0x40
    assert len(dos) == 0x40

    coff = struct.pack("<HHIIIHH", 0x8664, num_sections, 0, 0, 0, opt_size, 0x2022)

    # Optional header (PE32+). We only need a valid magic + data directories.
    opt = struct.pack("<H", 0x20B)               # magic PE32+
    opt += b"\x00" * (112 - len(opt))            # pad to start of data directories
    # 16 data directories; index 1 = import table. Compute import RVA below.
    sec_off = e_lfanew + 4 + 20 + opt_size
    raw_ptr = sec_off + 40                        # section raw data right after headers
    import_rva = sect_va                          # descriptors sit at start of section
    data_dirs = struct.pack("<II", 0, 0)          # [0] export
    data_dirs += struct.pack("<II", import_rva, len(descriptors))  # [1] import
    data_dirs += struct.pack("<II", 0, 0) * 14    # [2..15]
    opt += data_dirs
    assert len(opt) == opt_size, (len(opt), opt_size)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\x00\x00",
        len(sect_raw),   # VirtualSize
        sect_va,         # VirtualAddress
        len(sect_raw),   # SizeOfRawData
        raw_ptr,         # PointerToRawData
        0, 0, 0, 0, 0,   # relocs/linenums/chars
    )
    assert len(section) == 40, len(section)

    headers = dos + b"PE\x00\x00" + coff + opt + section
    pad = raw_ptr - len(headers)
    return headers + b"\x00" * pad + sect_raw


# --- Mach-O fixture builder -----------------------------------------------


def _macho64_with_dylib(name: bytes = b"/usr/lib/libcrypto.dylib") -> bytes:
    name_field = name + b"\x00"
    name_field += b"\x00" * ((-len(name_field)) % 8)
    cmdsize = 24 + len(name_field)                # dylib_command fixed part + name
    lc = struct.pack("<IIIIII", 0x0C, cmdsize, 24, 0, 0, 0) + name_field  # LC_LOAD_DYLIB
    # mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds,
    # flags, reserved  (8 x u32 = 32 bytes)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 0, 6, 1, len(lc), 0, 0)
    return header + lc


# --- tests: ELF -----------------------------------------------------------


@pytest.mark.asyncio
async def test_elf_dt_needed_openssl(tmp_path: Path):
    _write(tmp_path, "app.elf", _elf64_with_needed(b"libcrypto.so.3"))
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert openssl, "expected an openssl finding from DT_NEEDED libcrypto.so.3"
    hit = openssl[0]
    assert hit.classification is Classification.SEDERHANA
    assert hit.severity is Severity.MED
    assert hit.evidence["format"] == "elf"
    assert hit.evidence["linked"] == "linked"
    assert hit.confidence == "high"
    assert hit.algorithm == "openssl"
    assert hit.evidence["matched"] == "libcrypto.so.3"


@pytest.mark.asyncio
async def test_elf_libssl_maps_to_openssl(tmp_path: Path):
    _write(tmp_path, "app2.so", _elf64_with_needed(b"libssl.so.1.1"))
    found = await _run(tmp_path)
    assert any(f.evidence.get("library") == "openssl" for f in found)


# --- tests: ELF .dynsym reachability --------------------------------------


@pytest.mark.asyncio
async def test_elf_invoked_crypto_symbol(tmp_path: Path):
    # libssl DT_NEEDED + an imported EVP_ symbol → the library is INVOKED.
    _write(tmp_path, "invoked.elf",
           _elf64_with_symbols(b"libssl.so.3", (b"EVP_EncryptInit_ex", b"printf")))
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert openssl, "expected an openssl finding"
    hit = openssl[0]
    assert hit.evidence["reachability"] == "invoked"
    assert "EVP_EncryptInit_ex" in hit.evidence["imported_crypto_symbols"]
    assert "printf" not in hit.evidence["imported_crypto_symbols"]
    assert hit.confidence == "high"          # invoked keeps linked confidence


@pytest.mark.asyncio
async def test_elf_linked_only_no_crypto_symbol(tmp_path: Path):
    # libssl DT_NEEDED but .dynsym imports only printf → LINKED-ONLY, the
    # classic transitive-dependency false positive → forced low confidence.
    _write(tmp_path, "linkedonly.elf",
           _elf64_with_symbols(b"libssl.so.3", (b"printf", b"malloc")))
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert openssl, "expected an openssl finding"
    hit = openssl[0]
    assert hit.evidence["reachability"] == "linked-only"
    assert hit.evidence["confidence"] == "low"
    assert hit.confidence == "low"
    assert "imported_crypto_symbols" not in hit.evidence


@pytest.mark.asyncio
async def test_elf_no_dynsym_reachability_unknown(tmp_path: Path):
    # The DT_NEEDED-only fixture has no .dynsym section → reachability unknown
    # and confidence unchanged (high), i.e. behaviour identical to before.
    _write(tmp_path, "nodynsym.elf", _elf64_with_needed(b"libcrypto.so.3"))
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert openssl
    hit = openssl[0]
    assert hit.evidence["reachability"] == "unknown"
    assert hit.confidence == "high"
    assert "imported_crypto_symbols" not in hit.evidence


def test_elf_dynsym_imports_direct():
    # Unit-level check of the parser: only SHN_UNDEF names are returned.
    from pqcscan.probes.fs_binary_crypto import _elf_dynsym_imports
    data = _elf64_with_symbols(b"libssl.so.3", (b"EVP_DigestInit", b"gnutls_init"))
    imports = _elf_dynsym_imports(data)
    assert {"EVP_DigestInit", "gnutls_init"} <= imports
    # Non-ELF / garbage never raises and yields an empty set.
    assert _elf_dynsym_imports(b"not an elf") == set()
    assert _elf_dynsym_imports(b"\x7fELF" + b"\x00" * 60) == set()


# --- tests: PE ------------------------------------------------------------


@pytest.mark.asyncio
async def test_pe_import_bcrypt(tmp_path: Path):
    _write(tmp_path, "app.exe", _pe_import(b"bcrypt.dll"))
    found = await _run(tmp_path)
    bcrypt = [f for f in found if f.evidence.get("library") == "bcrypt"]
    assert bcrypt, "expected a bcrypt finding from PE import of bcrypt.dll"
    hit = bcrypt[0]
    assert hit.evidence["format"] == "pe"
    assert hit.evidence["linked"] == "linked"
    assert hit.classification is Classification.SEDERHANA
    assert hit.confidence == "high"


# --- tests: Mach-O --------------------------------------------------------


@pytest.mark.asyncio
async def test_macho_load_dylib_openssl(tmp_path: Path):
    _write(tmp_path, "app.macho", _macho64_with_dylib(b"/usr/lib/libcrypto.dylib"))
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert openssl, "expected an openssl finding from LC_LOAD_DYLIB"
    assert openssl[0].evidence["format"] == "macho"
    assert openssl[0].evidence["linked"] == "linked"


# --- tests: embedded string banners ---------------------------------------


def _elf_stub_with_banner(banner: bytes) -> bytes:
    # A file that is detected as an ELF (magic) but whose structural parse
    # yields nothing; the embedded banner drives the finding.
    return b"\x7fELF" + b"\x00" * 60 + b"\x00" + banner + b"\x00"


@pytest.mark.asyncio
async def test_embedded_openssl_35_is_pqc_ready(tmp_path: Path):
    _write(tmp_path, "static35", _elf_stub_with_banner(b"OpenSSL 3.5.0"))
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert openssl, "expected an embedded openssl banner finding"
    hit = openssl[0]
    assert hit.classification is Classification.PQC_READY
    assert hit.severity is Severity.INFO
    assert hit.evidence["linked"] == "embedded"
    assert hit.evidence["confidence"] == "medium"
    assert hit.confidence == "medium"
    assert hit.evidence["version"] == "3.5.0"
    assert hit.algorithm == "pkg:generic/openssl@3.5.0"


@pytest.mark.asyncio
async def test_embedded_openssl_111_is_sederhana(tmp_path: Path):
    _write(tmp_path, "static111", _elf_stub_with_banner(b"OpenSSL 1.1.1w  11 Sep 2023"))
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert openssl
    hit = openssl[0]
    assert hit.classification is Classification.SEDERHANA
    assert hit.evidence["linked"] == "embedded"
    assert hit.evidence["version"] == "1.1.1w"


@pytest.mark.asyncio
async def test_linked_wins_over_embedded_but_gains_version(tmp_path: Path):
    # An ELF with DT_NEEDED libcrypto.so.3 AND an embedded "OpenSSL 3.5.0" banner
    # should be a single high-confidence linked finding that adopts the version
    # and is therefore classified PQC_READY.
    body = _elf64_with_needed(b"libcrypto.so.3") + b"OpenSSL 3.5.0\x00"
    _write(tmp_path, "both.elf", body)
    found = await _run(tmp_path)
    openssl = [f for f in found if f.evidence.get("library") == "openssl"]
    assert len(openssl) == 1
    hit = openssl[0]
    assert hit.evidence["linked"] == "linked"
    assert hit.confidence == "high"
    assert hit.evidence["version"] == "3.5.0"
    assert hit.classification is Classification.PQC_READY


# --- tests: negatives + gating --------------------------------------------


@pytest.mark.asyncio
async def test_plain_text_no_findings(tmp_path: Path):
    _write(tmp_path, "notes.txt", b"hello world, this mentions OpenSSL but is not a binary")
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_binary_without_crypto_no_findings(tmp_path: Path):
    _write(tmp_path, "nocrypto.elf", _elf64_with_needed(b"libc.so.6"))
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_garbage_binary_no_crash(tmp_path: Path):
    _write(tmp_path, "junk.exe", b"MZ" + b"\xde\xad\xbe\xef" * 32)
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_applies_true_with_scan_paths(tmp_path: Path):
    assert await FsBinaryCrypto().applies(_ctx(tmp_path)) is True


@pytest.mark.asyncio
async def test_applies_falls_back_to_default_system_roots(monkeypatch, tmp_path: Path):
    # With no --path, the probe scans the standard system executable dirs so
    # binary-crypto + reachability surface on a plain host scan.
    import pqcscan.probes.fs_binary_crypto as m
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    monkeypatch.setattr(m, "_DEFAULT_BINARY_ROOTS", [tmp_path])          # exists
    assert await FsBinaryCrypto().applies(ctx) is True
    monkeypatch.setattr(m, "_DEFAULT_BINARY_ROOTS", [tmp_path / "nope"])  # absent
    assert await FsBinaryCrypto().applies(ctx) is False


@pytest.mark.asyncio
async def test_applies_false_with_explicit_empty_roots():
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await FsBinaryCrypto(roots=[]).applies(ctx) is False


@pytest.mark.asyncio
async def test_default_sweep_is_bounded_by_file_budget(monkeypatch, tmp_path: Path):
    # The implicit default sweep must stop after _MAX_DEFAULT_FILES files (so a
    # huge /opt tool cache can't hang a plain scan) and say so honestly.
    import pqcscan.probes.fs_binary_crypto as m
    for i in range(5):
        (tmp_path / f"f{i}.bin").write_bytes(b"not-a-binary")
    monkeypatch.setattr(m, "_DEFAULT_BINARY_ROOTS", [tmp_path])
    monkeypatch.setattr(m, "_MAX_DEFAULT_FILES", 3)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await FsBinaryCrypto().run(ctx, emit=found.append)
    notes = [f for f in found if "file budget" in f.title]
    assert len(notes) == 1
    assert notes[0].evidence["file_budget"] == 3


@pytest.mark.asyncio
async def test_explicit_path_scan_is_not_budget_limited(monkeypatch, tmp_path: Path):
    # An explicit --path scans everything asked for — no default file budget.
    import pqcscan.probes.fs_binary_crypto as m
    for i in range(5):
        (tmp_path / f"f{i}.bin").write_bytes(b"not-a-binary")
    monkeypatch.setattr(m, "_MAX_DEFAULT_FILES", 3)
    found = await _run(tmp_path)  # _ctx() sets scan_paths=[tmp_path]
    assert not [f for f in found if "file budget" in f.title]


# --- tests: embedded crypto-constant signatures (static/stripped binaries) --

from pqcscan.probes._crypto_constants import (  # noqa: E402
    _AES_SBOX,
    _MD5_T,
    _SHA1_K,
    _le,
)


def _elf_with_constants(*blobs: bytes) -> bytes:
    """A valid-magic ELF that carries no DT_NEEDED crypto lib, only the given
    constant blobs — so the library scan finds nothing and the constant
    fallback fires."""
    return b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 200 + b"".join(blobs)


@pytest.mark.asyncio
async def test_constant_detection_finds_static_crypto(tmp_path: Path):
    # No library linkage, but embedded AES S-box + MD5 T-table constants.
    _write(tmp_path, "static.bin",
           _elf_with_constants(_AES_SBOX, b"\xff" * 40, _le(_MD5_T, 4)))
    found = await _run(tmp_path)
    by_alg = {f.algorithm: f for f in found}
    assert "AES" in by_alg and "MD5" in by_alg
    md5 = by_alg["MD5"]
    assert md5.evidence["detection"] == "constant-signature"
    assert md5.evidence["signature"].startswith("MD5 T-table")
    assert md5.confidence == "medium"
    # MD5 is quantum-irrelevant but classically broken — must be top severity.
    assert md5.classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_constant_detection_flags_embedded_sha1(tmp_path: Path):
    _write(tmp_path, "s1.bin", _elf_with_constants(_le(_SHA1_K, 4)))
    found = await _run(tmp_path)
    sha1 = [f for f in found if f.algorithm == "SHA-1"]
    assert sha1 and sha1[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_constant_scan_suppressed_when_library_linked(tmp_path: Path):
    # A dynamically-linked binary (DT_NEEDED libcrypto) that ALSO embeds an AES
    # S-box must NOT emit a redundant constant finding — the constant fallback
    # is gated on "no library detected".
    blob = _elf64_with_needed(b"libcrypto.so.3") + _AES_SBOX
    _write(tmp_path, "linked.so", blob)
    found = await _run(tmp_path)
    assert any(f.evidence.get("library") == "openssl" for f in found)
    assert not [f for f in found
                if f.evidence.get("detection") == "constant-signature"]


@pytest.mark.asyncio
async def test_constant_scan_no_false_positive_on_plain_binary(tmp_path: Path):
    _write(tmp_path, "plain.bin",
           _elf_with_constants(b"just some strings and \x00 bytes, no crypto"))
    found = await _run(tmp_path)
    assert not [f for f in found
                if f.evidence.get("detection") == "constant-signature"]

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
async def test_applies_false_without_scan_paths():
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await FsBinaryCrypto().applies(ctx) is False

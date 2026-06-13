from __future__ import annotations

from pathlib import Path

from .entropy import shannon_entropy
from .models import SectionInfo


def collect_metadata(path: Path, file_type: str) -> tuple[str | None, list[str], list[SectionInfo]]:
    if file_type == "PE":
        return _pe_metadata(path)
    if file_type == "ELF":
        return _elf_metadata(path)
    if file_type == "Mach-O":
        return _macho_metadata(path)
    return None, [], []


def _pe_metadata(path: Path) -> tuple[str | None, list[str], list[SectionInfo]]:
    try:
        import pefile
    except ImportError:
        return None, [], []

    pe = pefile.PE(str(path), fast_load=False)
    machine = pe.FILE_HEADER.Machine
    architecture = {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C0: "ARM",
        0xAA64: "ARM64",
    }.get(machine, hex(machine))

    hints: list[str] = []
    if hasattr(pe, "VS_VERSIONINFO"):
        hints.append("version_info")
    if getattr(pe, "DIRECTORY_ENTRY_DEBUG", None):
        hints.append("debug_directory")

    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode(errors="replace") or "<unnamed>"
        data = section.get_data()
        flags = []
        if section.IMAGE_SCN_MEM_EXECUTE:
            flags.append("execute")
        if section.IMAGE_SCN_MEM_WRITE:
            flags.append("write")
        if section.IMAGE_SCN_MEM_READ:
            flags.append("read")
        sections.append(
            SectionInfo(
                name=name,
                size=len(data),
                entropy=round(shannon_entropy(data), 3),
                virtual_address=hex(section.VirtualAddress),
                flags=flags,
            )
        )
    return architecture, hints, sections


def _elf_metadata(path: Path) -> tuple[str | None, list[str], list[SectionInfo]]:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return None, [], []

    with path.open("rb") as handle:
        elf = ELFFile(handle)
        architecture = elf.get_machine_arch()
        hints = [elf.header["e_type"]]
        sections = [
            SectionInfo(
                name=section.name or "<unnamed>",
                size=section.data_size,
                entropy=round(shannon_entropy(section.data()), 3),
                virtual_address=hex(section["sh_addr"]),
                flags=_elf_flags(section["sh_flags"]),
            )
            for section in elf.iter_sections()
            if section.data_size
        ]
    return architecture, hints, sections


def _elf_flags(flags: int) -> list[str]:
    names = []
    if flags & 0x1:
        names.append("write")
    if flags & 0x2:
        names.append("alloc")
    if flags & 0x4:
        names.append("execute")
    return names


def _macho_metadata(path: Path) -> tuple[str | None, list[str], list[SectionInfo]]:
    try:
        from macholib.MachO import MachO
    except ImportError:
        return None, [], []

    macho = MachO(str(path))
    headers = [header.header for header in macho.headers]
    architecture = ", ".join(str(getattr(header, "cputype", "unknown")) for header in headers)
    return architecture or None, ["mach-o"], []

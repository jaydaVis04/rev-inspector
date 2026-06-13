from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .entropy import shannon_entropy
from .models import SectionInfo


def collect_metadata(path: Path, file_type: str) -> tuple[str | None, dict[str, Any], list[str], list[SectionInfo]]:
    if file_type == "PE":
        return _pe_metadata(path)
    if file_type == "ELF":
        return _elf_metadata(path)
    if file_type == "Mach-O":
        return _macho_metadata(path)
    return None, {}, [], []


def _pe_metadata(path: Path) -> tuple[str | None, dict[str, Any], list[str], list[SectionInfo]]:
    try:
        import pefile
    except ImportError:
        return _pe_metadata_basic(path)

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception:
        return _pe_metadata_basic(path)

    _, details, _, _ = _pe_metadata_basic(path)
    machine = pe.FILE_HEADER.Machine
    architecture = {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C0: "ARM",
        0xAA64: "ARM64",
    }.get(machine, hex(machine))

    hints: list[str] = []
    details.update(
        {
            "sections_count": pe.FILE_HEADER.NumberOfSections,
            "timestamp": _format_timestamp(pe.FILE_HEADER.TimeDateStamp),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": _pe_subsystem_name(pe.OPTIONAL_HEADER.Subsystem),
            "characteristics": _pe_file_characteristics(pe.FILE_HEADER.Characteristics),
        }
    )
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
    return architecture, details, hints, sections


def _pe_metadata_basic(path: Path) -> tuple[str | None, dict[str, Any], list[str], list[SectionInfo]]:
    data = path.read_bytes()
    if len(data) < 0x40:
        return None, {}, [], []

    e_lfanew = _unpack_from("<I", data, 0x3C)
    if e_lfanew is None or e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None, {}, [], []

    file_header_offset = e_lfanew + 4
    file_header = _unpack_from("<HHIIIHH", data, file_header_offset)
    if file_header is None:
        return None, {}, [], []

    machine, section_count, timestamp, _, _, optional_size, characteristics = file_header
    optional_offset = file_header_offset + 20
    optional_magic = _unpack_from("<H", data, optional_offset)
    entry_point = _unpack_from("<I", data, optional_offset + 16)
    image_base_offset = optional_offset + (24 if optional_magic == 0x20B else 28)
    image_base_format = "<Q" if optional_magic == 0x20B else "<I"
    image_base = _unpack_from(image_base_format, data, image_base_offset)
    subsystem = _unpack_from("<H", data, optional_offset + 68)

    details = {
        "pe_format": {0x10B: "PE32", 0x20B: "PE32+"}.get(optional_magic, hex(optional_magic or 0)),
        "sections_count": section_count,
        "timestamp": _format_timestamp(timestamp),
        "entry_point": hex(entry_point or 0),
        "image_base": hex(image_base or 0),
        "subsystem": _pe_subsystem_name(subsystem or 0),
        "characteristics": _pe_file_characteristics(characteristics),
    }

    section_table = optional_offset + optional_size
    sections: list[SectionInfo] = []
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset : offset + 8].rstrip(b"\x00").decode(errors="replace") or "<unnamed>"
        values = _unpack_from("<IIIIIIHHI", data, offset + 8)
        if values is None:
            continue
        virtual_size, virtual_address, raw_size, raw_pointer, _, _, _, _, section_characteristics = values
        raw_data = data[raw_pointer : raw_pointer + raw_size] if raw_pointer < len(data) else b""
        sections.append(
            SectionInfo(
                name=name,
                size=raw_size,
                entropy=round(shannon_entropy(raw_data), 3),
                virtual_address=hex(virtual_address),
                flags=_pe_section_characteristics(section_characteristics),
            )
        )
        if virtual_size and raw_size and raw_size > virtual_size * 4:
            details.setdefault("section_notes", []).append(f"{name}: raw size is much larger than virtual size")

    return _pe_machine_name(machine), details, [], sections


def _elf_metadata(path: Path) -> tuple[str | None, dict[str, Any], list[str], list[SectionInfo]]:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return None, {}, [], []

    with path.open("rb") as handle:
        elf = ELFFile(handle)
        architecture = elf.get_machine_arch()
        details = {
            "elf_type": elf.header["e_type"],
            "entry_point": hex(elf.header["e_entry"]),
            "endianness": "little" if elf.little_endian else "big",
        }
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
    return architecture, details, hints, sections


def _elf_flags(flags: int) -> list[str]:
    names = []
    if flags & 0x1:
        names.append("write")
    if flags & 0x2:
        names.append("alloc")
    if flags & 0x4:
        names.append("execute")
    return names


def _macho_metadata(path: Path) -> tuple[str | None, dict[str, Any], list[str], list[SectionInfo]]:
    try:
        from macholib.MachO import MachO
    except ImportError:
        return None, {}, [], []

    macho = MachO(str(path))
    headers = [header.header for header in macho.headers]
    architecture = ", ".join(str(getattr(header, "cputype", "unknown")) for header in headers)
    details = {"headers": len(headers)}
    return architecture or None, details, ["mach-o"], []


def _unpack_from(fmt: str, data: bytes, offset: int) -> Any:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        return None
    values = struct.unpack_from(fmt, data, offset)
    return values[0] if len(values) == 1 else values


def _format_timestamp(value: int) -> str:
    if not value:
        return "0"
    return datetime.fromtimestamp(value, UTC).isoformat()


def _pe_machine_name(machine: int) -> str:
    return {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C0: "ARM",
        0x01C4: "ARMv7",
        0xAA64: "ARM64",
    }.get(machine, hex(machine))


def _pe_subsystem_name(subsystem: int) -> str:
    return {
        1: "native",
        2: "windows_gui",
        3: "windows_console",
        5: "os2_console",
        7: "posix_console",
        9: "windows_ce_gui",
        10: "efi_application",
        11: "efi_boot_service_driver",
        12: "efi_runtime_driver",
        14: "xbox",
        16: "windows_boot_application",
    }.get(subsystem, hex(subsystem))


def _pe_file_characteristics(value: int) -> list[str]:
    flags = {
        0x0001: "relocations_stripped",
        0x0002: "executable_image",
        0x0004: "line_numbers_stripped",
        0x0008: "local_symbols_stripped",
        0x0020: "large_address_aware",
        0x0100: "32bit_machine",
        0x0200: "debug_stripped",
        0x2000: "dll",
    }
    return [name for bit, name in flags.items() if value & bit]


def _pe_section_characteristics(value: int) -> list[str]:
    flags = []
    if value & 0x00000020:
        flags.append("code")
    if value & 0x00000040:
        flags.append("initialized_data")
    if value & 0x00000080:
        flags.append("uninitialized_data")
    if value & 0x20000000:
        flags.append("execute")
    if value & 0x40000000:
        flags.append("read")
    if value & 0x80000000:
        flags.append("write")
    return flags

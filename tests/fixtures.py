from __future__ import annotations

import struct


def minimal_pe32() -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"

    file_header_offset = 0x84
    struct.pack_into(
        "<HHIIIHH",
        data,
        file_header_offset,
        0x014C,
        1,
        1_704_067_200,
        0,
        0,
        0xE0,
        0x0102,
    )

    optional_offset = file_header_offset + 20
    struct.pack_into("<H", data, optional_offset, 0x10B)
    struct.pack_into("<I", data, optional_offset + 16, 0x1000)
    struct.pack_into("<I", data, optional_offset + 28, 0x400000)
    struct.pack_into("<I", data, optional_offset + 56, 0x2000)
    struct.pack_into("<I", data, optional_offset + 60, 0x200)
    struct.pack_into("<H", data, optional_offset + 68, 3)

    section_offset = optional_offset + 0xE0
    data[section_offset : section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section_offset + 8,
        0x100,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[0x200:0x400] = bytes((index % 251 for index in range(0x200)))
    return bytes(data)
